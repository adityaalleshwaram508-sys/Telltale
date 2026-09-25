"""Runtime configuration, read once from the environment.

Everything that might differ between a laptop, CI, and a deployed container lives
here so the rest of the code never touches os.environ directly.

Note the two vendor keys use their own names (NEBIUS_API_KEY, TAVILY_API_KEY) via
validation_alias, while our own knobs use the TELLTALE_ prefix. That way a .env
with the vendors' usual names works whether it's parsed by
pydantic-settings, exported by scripts/run-dev.sh, or passed with docker --env-file.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TELLTALE_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- Nebius Token Factory ---
    nebius_api_key: str = Field("", validation_alias=AliasChoices("NEBIUS_API_KEY"))
    nebius_base_url: str = "https://api.tokenfactory.nebius.com/v1/"

    reasoning_model: str = "nvidia/nemotron-3-super-120b-a12b"
    fast_model: str = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
    # Screenshots need a vision-language model. Token Factory has no Nemotron VL
    # model, so we use MiniCPM-V (a strong OCR/vision model); swap for
    # google/gemma-3-27b-it if you prefer. All *reasoning* stays on Nemotron.
    vision_model: str = "openbmb/MiniCPM-V-4_5"

    # Nemotron 3 reasons before it answers unless told not to. Reasoning is spent on the
    # verdict; context, classification and the action plan are extraction and writing.
    thinking_context: Literal["off", "low", "on"] = "off"
    thinking_classify: Literal["off", "low", "on"] = "off"
    thinking_verdict: Literal["off", "low", "on"] = "low"
    thinking_action: Literal["off", "low", "on"] = "off"

    # Optional second opinion for ambiguous verdicts, e.g. Nemotron 3 Ultra. Copy the exact
    # id from the Token Factory catalog; empty turns it off.
    escalation_model: str = ""
    thinking_escalation: Literal["off", "low", "on"] = "on"

    llm_timeout: float = 45.0  # one HTTP call
    llm_max_retries: int = 2  # transient errors only (timeouts, 429, 5xx)
    llm_stage_budget: float = 75.0  # one pipeline step, retries and repair included
    llm_temperature: float = 0.0

    # --- Tavily ---
    tavily_api_key: str = Field("", validation_alias=AliasChoices("TAVILY_API_KEY"))
    tavily_timeout: float = 15.0
    tavily_depth: Literal["basic", "advanced"] = "advanced"

    # --- Server ---
    cors_origins: str = "*"
    cache_ttl_s: int = 900
    max_input_chars: int = 6000
    max_images: int = 2
    max_image_bytes: int = 4_000_000
    # The public demo pays for every model call, so both limits exist to protect the credits.
    rate_limit_per_ip: int = 20  # analyses per window per client
    rate_limit_window_s: int = 600
    daily_model_budget: int = 800  # full model runs per UTC day, then detectors only

    @property
    def has_llm(self) -> bool:
        return bool(self.nebius_api_key)

    @property
    def has_tavily(self) -> bool:
        return bool(self.tavily_api_key)

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
