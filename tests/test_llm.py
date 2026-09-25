"""The Token Factory client: which failures are retried, how output is validated, and
what each step records. The OpenAI client is replaced by a scripted fake."""

from types import SimpleNamespace

import httpx
import openai
import pytest
from pydantic import BaseModel

import backend.llm as llm_mod
from backend.config import Settings
from backend.llm import LLM, LLMError, reasoning_body

REQ = httpx.Request("POST", "https://api.tokenfactory.nebius.com/v1/chat/completions")


class Item(BaseModel):
    name: str
    score: int


def reply(content: str, finish: str = "stop", tokens=(100, 20)):
    return SimpleNamespace(
        choices=[SimpleNamespace(finish_reason=finish, message=SimpleNamespace(content=content))],
        usage=SimpleNamespace(
            prompt_tokens=tokens[0], completion_tokens=tokens[1], completion_tokens_details=None
        ),
    )


def status_error(cls, code: int):
    return cls("boom", response=httpx.Response(code, request=REQ), body=None)


class FakeCompletions:
    def __init__(self, script):
        self.script, self.calls = list(script), []

    async def create(self, **kw):
        self.calls.append(kw)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture
def make_llm(monkeypatch):
    sleeps: list[float] = []

    async def no_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(llm_mod.asyncio, "sleep", no_sleep)

    def build(script, **settings):
        llm = LLM(Settings(nebius_api_key="k", llm_max_retries=2, **settings))
        fake = FakeCompletions(script)
        llm.client = SimpleNamespace(chat=SimpleNamespace(completions=fake))
        return llm, fake, sleeps

    return build


GOOD = '{"name": "x", "score": 3}'


async def test_bad_request_is_not_retried_and_falls_through_to_json_object(make_llm):
    llm, fake, sleeps = make_llm(
        [
            status_error(openai.BadRequestError, 400),
            status_error(openai.BadRequestError, 400),
            reply(GOOD),
        ]
    )
    out = await llm.structured(Item, "s", "u", stage="context", model="nvidia/nemotron-nano")
    assert out.score == 3
    assert fake.calls[-1]["response_format"] == {"type": "json_object"}
    assert sleeps == []  # a 400 is never slept on


async def test_transient_errors_are_retried_with_backoff(make_llm):
    llm, fake, sleeps = make_llm([status_error(openai.InternalServerError, 503), reply(GOOD)])
    out = await llm.structured(Item, "s", "u", stage="verdict")
    assert out.name == "x" and len(fake.calls) == 2 and sleeps == [1.0]


async def test_retries_are_bounded(make_llm):
    errors = [status_error(openai.InternalServerError, 503) for _ in range(6)]
    llm, fake, _ = make_llm(errors)
    with pytest.raises(LLMError):
        await llm.structured(Item, "s", "u", stage="verdict")
    assert len(fake.calls) == 6  # 3 attempts for json_schema, 3 for json_object


async def test_truncated_reply_is_never_parsed(make_llm):
    llm, fake, _ = make_llm([reply('{"name": "x", "sco', finish="length"), reply(GOOD)])
    out = await llm.structured(Item, "s", "u", stage="verdict")
    assert out.score == 3 and fake.calls[1]["response_format"] == {"type": "json_object"}


async def test_leaked_reasoning_is_stripped_before_parsing(make_llm):
    llm, _, _ = make_llm([reply('<think>maybe {"name": "y"}</think>' + GOOD)])
    assert (await llm.structured(Item, "s", "u", stage="verdict")).name == "x"


async def test_invalid_output_gets_one_repair(make_llm):
    llm, fake, _ = make_llm([reply('{"name": "x"}'), reply(GOOD)])
    trace = []
    out = await llm.structured(Item, "s", "u", stage="classify", trace=trace)
    assert out.score == 3 and fake.calls[1]["messages"][-1]["role"] == "user"
    assert trace[0].note == "repaired" and trace[0].calls == 2


async def test_usage_and_mode_are_recorded(make_llm):
    llm, fake, _ = make_llm([reply(GOOD, tokens=(400, 60))])
    trace = []
    await llm.structured(
        Item,
        "s",
        "u",
        stage="verdict",
        model="nvidia/nemotron-3-super",
        thinking="low",
        trace=trace,
    )
    entry = trace[0]
    assert (entry.stage, entry.tokens_in, entry.tokens_out, entry.ok) == ("verdict", 400, 60, True)
    assert entry.detail == "reasoning low"
    assert fake.calls[0]["extra_body"] == {
        "chat_template_kwargs": {"enable_thinking": True, "low_effort": True}
    }


def test_reasoning_mode_only_goes_to_nemotron():
    assert reasoning_body("nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B", "off") == {
        "chat_template_kwargs": {"enable_thinking": False}
    }
    assert reasoning_body("openbmb/MiniCPM-V-4_5", "off") is None
    assert reasoning_body("nvidia/nemotron-3-super", None) is None


async def test_endpoint_that_rejects_template_kwargs_is_remembered(make_llm):
    llm, fake, _ = make_llm([status_error(openai.BadRequestError, 400), reply(GOOD), reply(GOOD)])
    await llm.structured(Item, "s", "u", stage="context", model="nvidia/nemotron-nano")
    await llm.structured(Item, "s", "u", stage="context", model="nvidia/nemotron-nano")
    assert fake.calls[1]["extra_body"] is None and fake.calls[2]["extra_body"] is None
    trace = []
    llm2, _, _ = make_llm([status_error(openai.BadRequestError, 400), reply(GOOD)])
    await llm2.structured(
        Item, "s", "u", stage="context", model="nvidia/nemotron-nano", trace=trace
    )
    assert trace[0].detail == "reasoning mode not accepted, model default"


async def test_missing_key_fails_fast():
    with pytest.raises(LLMError):
        await LLM(Settings(nebius_api_key="")).structured(Item, "s", "u", stage="context")
