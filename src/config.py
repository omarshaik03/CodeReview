from __future__ import annotations

from pathlib import Path
from typing import Literal, Optional

from pydantic import Field  # type: ignore[import]
from pydantic_settings import BaseSettings, SettingsConfigDict  # type: ignore[import]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    repo_path: Path = Field(default_factory=Path.cwd, description="Path to the Git repository to review")
    start_ref: Optional[str] = Field(default=None, description="Oldest commit (exclusive) for the review range")
    end_ref: str = Field(default="HEAD", description="Newest commit (inclusive) for the review range")
    max_commits: Optional[int] = Field(default=None, description="Limit the number of commits to review")

    llm_provider: Literal["openai", "azure-openai"] = Field(default="openai", alias="LLM_PROVIDER")
    openai_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o-mini", alias="OPENAI_MODEL")
    openai_temperature: float = Field(default=0.1)
    max_output_tokens: int = Field(default=1200, alias="MAX_OUTPUT_TOKENS")

    azure_openai_api_key: Optional[str] = Field(default=None, alias="AZURE_OPENAI_API_KEY")
    azure_openai_endpoint: Optional[str] = Field(default=None, alias="AZURE_OPENAI_ENDPOINT")
    azure_openai_deployment: Optional[str] = Field(default=None, alias="AZURE_OPENAI_DEPLOYMENT")
    azure_openai_api_version: str = Field(default="2024-06-01", alias="AZURE_OPENAI_API_VERSION")

    console_width: Optional[int] = Field(default=None, description="Override console width for Rich output")


settings = Settings()
