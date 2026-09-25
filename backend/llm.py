"""Token Factory client: schema-constrained output, bounded retries, per-call usage."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any, Literal, TypeVar

import openai
from openai import AsyncOpenAI
from pydantic import BaseModel, ValidationError

from backend.config import Settings, get_settings
from backend.schemas import TraceEntry

log = logging.getLogger("telltale.llm")

T = TypeVar("T", bound=BaseModel)
Thinking = Literal["off", "low", "on"]

# Worth another attempt. Anything else (a 400 for an unsupported response_format, a bad key,
# an unknown model id) fails at once so the next output strategy or the fallback can run.
_RETRYABLE = (
    openai.APITimeoutError,
    openai.APIConnectionError,
    openai.RateLimitError,
    openai.InternalServerError,
)
_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.S)


class LLMError(RuntimeError):
    pass


class TruncatedReply(LLMError):
    """The reply stopped at max_tokens, so the content is a fragment and isn't parsed."""


def _strictify(schema: dict) -> dict:
    """Reduce a Pydantic JSON schema to the subset strict decoding accepts."""

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            node.pop("default", None)
            node.pop("title", None)
            if node.get("type") == "object" and "properties" in node:
                node["additionalProperties"] = False
                node["required"] = list(node["properties"])
            return {key: walk(value) for key, value in node.items()}
        if isinstance(node, list):
            return [walk(value) for value in node]
        return node

    return walk(json.loads(json.dumps(schema)))


def _extract_json(text: str) -> str:
    """The JSON object in a reply, ignoring a leaked <think> block or code fences."""
    text = _THINK_BLOCK.sub("", text).strip()
    start, end = text.find("{"), text.rfind("}")
    return text[start : end + 1] if start != -1 and end > start else text


def reasoning_body(model: str, thinking: Thinking | None) -> dict | None:
    """extra_body that sets Nemotron 3's reasoning mode. Other models get nothing extra."""
    if thinking is None or "nemotron" not in model.lower():
        return None
    kwargs: dict[str, bool] = {"enable_thinking": thinking != "off"}
    if thinking == "low":
        kwargs["low_effort"] = True
    return {"chat_template_kwargs": kwargs}


def _backoff(exc: Exception, attempt: int) -> float:
    retry_after = getattr(getattr(exc, "response", None), "headers", {}).get("retry-after")
    try:
        return min(float(retry_after), 8.0) if retry_after else float(2**attempt)
    except ValueError:
        return float(2**attempt)


class LLM:
    def __init__(self, settings: Settings | None = None):
        self.s = settings or get_settings()
        self._no_template_kwargs: set[str] = set()
        self.client = (
            AsyncOpenAI(
                base_url=self.s.nebius_base_url,
                api_key=self.s.nebius_api_key,
                timeout=self.s.llm_timeout,
                max_retries=0,
            )
            if self.s.has_llm
            else None
        )

    def _mode_label(self, model: str, thinking: Thinking | None) -> str:
        """The reasoning mode actually sent, for the run trace."""
        if not thinking or reasoning_body(model, thinking) is None:
            return ""
        if model in self._no_template_kwargs:
            return "reasoning mode not accepted, model default"
        return f"reasoning {thinking}"

    async def _chat(
        self,
        *,
        model: str,
        messages: list[dict],
        response_format: dict,
        max_tokens: int,
        temperature: float,
        thinking: Thinking | None,
        usage: dict[str, int],
    ) -> str:
        extra = None if model in self._no_template_kwargs else reasoning_body(model, thinking)
        dropped_extra = False
        attempt = 0
        while True:
            try:
                resp = await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    response_format=response_format,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    extra_body=extra,
                )
            except openai.BadRequestError as exc:
                if extra is not None:
                    # Try once without chat_template_kwargs in case this endpoint rejects it.
                    extra, dropped_extra = None, True
                    continue
                raise LLMError(f"{model} rejected the request: {exc.message}") from exc
            except _RETRYABLE as exc:
                if attempt >= self.s.llm_max_retries:
                    raise LLMError(
                        f"{model}: {type(exc).__name__} after {attempt + 1} attempts"
                    ) from exc
                await asyncio.sleep(_backoff(exc, attempt))
                attempt += 1
                continue
            except openai.APIStatusError as exc:
                raise LLMError(f"{model} returned HTTP {exc.status_code}") from exc

            if dropped_extra:
                log.warning("%s rejected chat_template_kwargs; reasoning mode not set", model)
                self._no_template_kwargs.add(model)
            usage["calls"] += 1
            if resp.usage:
                usage["tokens_in"] += resp.usage.prompt_tokens or 0
                usage["tokens_out"] += resp.usage.completion_tokens or 0
                details = getattr(resp.usage, "completion_tokens_details", None)
                usage["reasoning_tokens"] += getattr(details, "reasoning_tokens", 0) or 0
            choice = resp.choices[0]
            if choice.finish_reason == "length":
                raise TruncatedReply(f"{model} stopped at max_tokens={max_tokens}")
            return choice.message.content or ""

    async def structured(
        self,
        schema: type[T],
        system: str,
        user: str,
        *,
        stage: str,
        model: str | None = None,
        images: list[str] | None = None,
        thinking: Thinking | None = "off",
        max_tokens: int = 1500,
        temperature: float | None = None,
        trace: list[TraceEntry] | None = None,
    ) -> T:
        """One pipeline step: ask for `schema`, validate, and record what it cost."""
        if self.client is None:
            raise LLMError("NEBIUS_API_KEY is not set, so Token Factory can't be reached.")
        model = model or (self.s.vision_model if images else self.s.reasoning_model)
        usage = {"calls": 0, "tokens_in": 0, "tokens_out": 0, "reasoning_tokens": 0}
        started = time.perf_counter()
        ok, note = False, ""
        try:
            async with asyncio.timeout(self.s.llm_stage_budget):
                result, note = await self._structured(
                    schema,
                    system,
                    user,
                    model=model,
                    images=images,
                    thinking=thinking,
                    max_tokens=max_tokens,
                    temperature=self.s.llm_temperature if temperature is None else temperature,
                    usage=usage,
                )
            ok = True
            return result
        except TimeoutError as exc:
            note = f"step budget of {self.s.llm_stage_budget:.0f}s exceeded"
            raise LLMError(note) from exc
        except LLMError as exc:
            note = str(exc)
            raise
        finally:
            if trace is not None:
                trace.append(
                    TraceEntry(
                        kind="model",
                        stage=stage,
                        name=model,
                        detail=self._mode_label(model, thinking),
                        ms=int((time.perf_counter() - started) * 1000),
                        ok=ok,
                        note=note,
                        **usage,
                    )
                )

    async def _structured(
        self,
        schema: type[T],
        system: str,
        user: str,
        *,
        model: str,
        images: list[str] | None,
        thinking: Thinking | None,
        max_tokens: int,
        temperature: float,
        usage: dict[str, int],
    ) -> tuple[T, str]:
        json_schema = _strictify(schema.model_json_schema())
        # The schema also goes in the prompt for endpoints that ignore response_format.
        prompt = (
            f"{user}\n\nReturn one JSON object matching this schema, with no prose or "
            f"markdown.\n{json.dumps(json_schema)}"
        )
        content: Any = prompt
        if images:
            content = [{"type": "text", "text": prompt}] + [
                {"type": "image_url", "image_url": {"url": u}} for u in images
            ]
        messages = [{"role": "system", "content": system}, {"role": "user", "content": content}]
        formats = [
            (
                "",
                {
                    "type": "json_schema",
                    "json_schema": {"name": schema.__name__, "schema": json_schema, "strict": True},
                },
            ),
            ("json_object fallback", {"type": "json_object"}),
        ]
        call = dict(max_tokens=max_tokens, temperature=temperature, thinking=thinking, usage=usage)
        errors: list[str] = []
        for label, fmt in formats:
            try:
                raw = await self._chat(model=model, messages=messages, response_format=fmt, **call)
            except LLMError as exc:
                errors.append(str(exc))
                continue
            try:
                return schema.model_validate_json(_extract_json(raw)), label
            except (ValidationError, json.JSONDecodeError) as exc:
                errors.append(
                    f"invalid {schema.__name__}: {exc.errors()[0]['msg'] if isinstance(exc, ValidationError) else exc}"
                )
                repair = messages + [
                    {"role": "assistant", "content": raw},
                    {
                        "role": "user",
                        "content": f"That did not validate ({errors[-1]}). Return corrected JSON only.",
                    },
                ]
                try:
                    raw = await self._chat(
                        model=model, messages=repair, response_format=fmt, **call
                    )
                    return schema.model_validate_json(_extract_json(raw)), "repaired"
                except (LLMError, ValidationError, json.JSONDecodeError) as repair_exc:
                    errors.append(str(repair_exc)[:200])
        raise LLMError(
            f"no valid {schema.__name__} from {model}: {errors[-1] if errors else 'unknown'}"
        )


_llm: LLM | None = None


def get_llm() -> LLM:
    global _llm
    if _llm is None:
        _llm = LLM()
    return _llm
