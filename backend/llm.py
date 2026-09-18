"""Thin async wrapper around Nemotron on Nebius Token Factory.

Two things matter here:

  1. Structured output. Every reasoning step returns JSON that validates against a
     Pydantic schema. We ask for `response_format=json_schema` (guided decoding),
     and if the endpoint or model doesn't honour it we fall back to `json_object`
     plus the schema in the prompt, then validate ourselves with one repair pass.
     Either way the caller gets a typed object or a clean error — never half-parsed
     text.

  2. Vision. Screenshots go to a vision-language model (MiniCPM-V by default, set
     via TELLTALE_VISION_MODEL) as base64 data URLs in the OpenAI content-array
     format. All *reasoning* stays on Nemotron; only screenshot transcription uses
     the vision model, because Token Factory has no Nemotron vision model.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, TypeVar

from openai import AsyncOpenAI
from pydantic import BaseModel, ValidationError

from backend.config import Settings, get_settings

T = TypeVar("T", bound=BaseModel)


class LLMError(RuntimeError):
    pass


def _strictify(schema: dict) -> dict:
    """Make a Pydantic JSON schema acceptable to strict guided decoding:
    every object gets additionalProperties=false and all its properties marked
    required, and we drop keys the strict validators choke on."""
    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            node.pop("default", None)
            node.pop("title", None)
            if node.get("type") == "object" and "properties" in node:
                node["additionalProperties"] = False
                node["required"] = list(node["properties"].keys())
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v) for v in node]
        return node

    return walk(json.loads(json.dumps(schema)))


def _extract_json(text: str) -> str:
    """Best-effort recovery if a model wraps JSON in prose or a code fence."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start:end + 1]
    return text


class LLM:
    def __init__(self, settings: Settings | None = None):
        self.s = settings or get_settings()
        if not self.s.has_llm:
            # Constructed lazily is fine, but calling without a key is not.
            self.client = None
        else:
            self.client = AsyncOpenAI(
                base_url=self.s.nebius_base_url,
                api_key=self.s.nebius_api_key,
                timeout=self.s.llm_timeout,
                max_retries=0,     # we handle retries so we can switch strategies
            )

    def _require_client(self):
        if self.client is None:
            raise LLMError("NEBIUS_API_KEY is not set — cannot reach Token Factory.")

    async def _chat(self, model: str, messages: list[dict], response_format: dict | None,
                    temperature: float) -> str:
        last_err: Exception | None = None
        for attempt in range(self.s.llm_max_retries + 1):
            try:
                resp = await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    response_format=response_format,
                    temperature=temperature,
                )
                return resp.choices[0].message.content or ""
            except Exception as e:  # network, rate-limit, bad-request — retry a little
                last_err = e
                if attempt < self.s.llm_max_retries:
                    await asyncio.sleep(1.5 * (attempt + 1))
        raise LLMError(f"Token Factory call failed: {last_err}")

    async def structured(
        self,
        schema: type[T],
        system: str,
        user: str,
        *,
        model: str | None = None,
        images: list[str] | None = None,
        temperature: float = 0.2,
    ) -> T:
        """Return an instance of `schema`, populated by the model."""
        self._require_client()
        model = model or (self.s.vision_model if images else self.s.reasoning_model)

        json_schema = _strictify(schema.model_json_schema())
        # Belt and braces: the docs recommend sending the schema in the prompt too.
        user_with_schema = (
            f"{user}\n\n"
            f"Respond with a single JSON object matching this schema exactly. "
            f"No prose, no markdown:\n{json.dumps(json_schema)}"
        )

        content: Any
        if images:
            content = [{"type": "text", "text": user_with_schema}]
            for data_url in images:
                content.append({"type": "image_url", "image_url": {"url": data_url}})
        else:
            content = user_with_schema

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": content},
        ]

        # Strategy 1: guided decoding against the schema.
        rf_schema = {
            "type": "json_schema",
            "json_schema": {"name": schema.__name__, "schema": json_schema, "strict": True},
        }
        strategies = [rf_schema, {"type": "json_object"}]

        errors = []
        for rf in strategies:
            try:
                raw = await self._chat(model, messages, rf, temperature)
                return schema.model_validate_json(_extract_json(raw))
            except (ValidationError, json.JSONDecodeError) as e:
                errors.append(str(e))
                # One repair attempt: hand the model its own broken output + the error.
                try:
                    repair = messages + [
                        {"role": "assistant", "content": raw},
                        {"role": "user", "content":
                            f"That did not validate ({e}). Return corrected JSON only."},
                    ]
                    raw = await self._chat(model, repair, rf, temperature)
                    return schema.model_validate_json(_extract_json(raw))
                except Exception as e2:
                    errors.append(str(e2))
                    continue
            except LLMError as e:
                # If json_schema isn't supported, fall through to json_object.
                errors.append(str(e))
                continue

        raise LLMError(f"Could not get valid {schema.__name__} from the model: {errors[-1]}")


_llm: LLM | None = None


def get_llm() -> LLM:
    global _llm
    if _llm is None:
        _llm = LLM()
    return _llm
