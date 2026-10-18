"""Environment-backed application configuration."""

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables or a .env file."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "AI-Powered Ethical Hacking Chatbot"
    environment: str = "development"
    database_url: str = (
        "sqlite:////tmp/ethical_hacking.db"
        if os.getenv("VERCEL")
        else "sqlite:///./data/ethical_hacking.db"
    )
    max_upload_size_bytes: int = Field(default=10 * 1024 * 1024, ge=1)
    allowed_upload_extensions: tuple[str, ...] = (
        "txt",
        "log",
        "csv",
        "json",
        "md",
        "pdf",
        "py",
        "js",
        "java",
        "php",
        "c",
        "cpp",
        "sql",
    )
    log_level: str = "INFO"
    llm_provider: str = "disabled"
    llm_api_base: str | None = None
    llm_api_key: str | None = None
    llm_model: str | None = None

    @field_validator("allowed_upload_extensions", mode="before")
    @classmethod
    def parse_extensions(cls, value: str | tuple[str, ...]) -> tuple[str, ...]:
        if isinstance(value, str):
            return tuple(
                extension.strip().lower().lstrip(".")
                for extension in value.split(",")
                if extension.strip()
            )
        return tuple(extension.lower().lstrip(".") for extension in value)

    @property
    def data_directory(self) -> Path:
        return Path("data")


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide, immutable settings instance."""
    return Settings()
