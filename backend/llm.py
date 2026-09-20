"""Async client wrapper for the reasoning and vision models."""

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
    """Convert a Pydantic schema to the subset accepted by strict decoding."""

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

    # Work on a copy so the Pydantic-generated schema isn't modified.
    return walk(json.loads(json.dumps(schema)))


def _extract_json(text: str) -> str:
    """Extract a JSON object from a model response."""

    text = text.strip()

    if text.startswith("```"):
        text = text.strip("`")
        start = text.find("{")
        if start != -1:
            text = text[start:]

    start = text.find("{")
    end = text.rfind("}")

    if start != -1 and end > start:
        return text[start : end + 1]

    return text


class LLM:
    def __init__(self, settings: Settings | None = None):
        self.s = settings or get_settings()

        if not self.s.has_llm:
            # Allow the application to start in detector-only mode.
            self.client = None
            return

        self.client = AsyncOpenAI(
            base_url=self.s.nebius_base_url,
            api_key=self.s.nebius_api_key,
            timeout=self.s.llm_timeout,
            max_retries=0,
        )

    def _require_client(self) -> None:
        if self.client is None:
            raise LLMError(
                "NEBIUS_API_KEY is not set — cannot reach Token Factory."
            )

    async def _chat(
        self,
        model: str,
        messages: list[dict],
        response_format: dict | None,
        temperature: float,
    ) -> str:
        last_error: Exception | None = None

        for attempt in range(self.s.llm_max_retries + 1):
            try:
                response = await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    response_format=response_format,
                    temperature=temperature,
                )

                return response.choices[0].message.content or ""

            except Exception as exc:
                last_error = exc

                if attempt < self.s.llm_max_retries:
                    await asyncio.sleep(1.5 * (attempt + 1))

        raise LLMError(f"Token Factory call failed: {last_error}")

    async def structured(
        self,
        schema: type[T],
        system: str,
        user: str,
        *,
        model: str | None = None,
        images: list[str] | None = None,
        temperature: float = 0.0,
    ) -> T:
        """Run a model call and validate the response against a Pydantic model."""

        self._require_client()

        model = model or (
            self.s.vision_model if images else self.s.reasoning_model
        )

        json_schema = _strictify(schema.model_json_schema())

        # Include the schema in the prompt for models that do not fully honor
        # response_format.
        user_with_schema = (
            f"{user}\n\n"
            "Return a single JSON object matching this schema. "
            "Do not include prose or markdown.\n"
            f"{json.dumps(json_schema)}"
        )

        if images:
            content: Any = [
                {"type": "text", "text": user_with_schema}
            ]

            for data_url in images:
                content.append(
                    {
                        "type": "image_url",
                        "image_url": {"url": data_url},
                    }
                )
        else:
            content = user_with_schema

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": content},
        ]

        structured_format = {
            "type": "json_schema",
            "json_schema": {
                "name": schema.__name__,
                "schema": json_schema,
                "strict": True,
            },
        }

        response_formats = [
            structured_format,
            {"type": "json_object"},
        ]

        errors: list[str] = []

        for response_format in response_formats:
            raw = ""

            try:
                raw = await self._chat(
                    model,
                    messages,
                    response_format,
                    temperature,
                )

                return schema.model_validate_json(_extract_json(raw))

            except (ValidationError, json.JSONDecodeError) as exc:
                errors.append(str(exc))

                # Give the model one chance to repair an invalid response.
                try:
                    repair_messages = messages + [
                        {"role": "assistant", "content": raw},
                        {
                            "role": "user",
                            "content": (
                                f"The response did not validate: {exc}. "
                                "Return corrected JSON only."
                            ),
                        },
                    ]

                    raw = await self._chat(
                        model,
                        repair_messages,
                        response_format,
                        temperature,
                    )

                    return schema.model_validate_json(_extract_json(raw))

                except Exception as repair_error:
                    errors.append(str(repair_error))

            except LLMError as exc:
                errors.append(str(exc))

        detail = errors[-1] if errors else "unknown error"
        raise LLMError(
            f"Could not get valid {schema.__name__} from the model: {detail}"
        )


_llm: LLM | None = None


def get_llm() -> LLM:
    global _llm

    if _llm is None:
        _llm = LLM()

    return _llm
