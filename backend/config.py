"""Runtime configuration, read once from the environment.

Everything that might differ between a laptop, CI, and a deployed container lives
here so the rest of the code never touches os.environ directly.

Note the two vendor keys use their own names (NEBIUS_API_KEY, TAVILY_API_KEY) via
validation_alias, while our own knobs use the TELLTALE_ prefix. That way a .env
with the vendors' conventional names Just Works, whether it's parsed by
pydantic-settings, exported by scripts/run-dev.sh, or passed with docker --env-file.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TELLTALE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
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

    llm_timeout: float = 60.0
    llm_max_retries: int = 2

    # --- Tavily ---
    tavily_api_key: str = Field("", validation_alias=AliasChoices("TAVILY_API_KEY"))
    tavily_timeout: float = 15.0

    # --- Server ---
    cors_origins: str = "*"

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
