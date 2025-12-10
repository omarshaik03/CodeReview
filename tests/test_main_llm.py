from __future__ import annotations

from typing import Any, Dict

import pytest  # type: ignore[import]

from src import main
from src.config import Settings


@pytest.fixture()
def base_settings() -> Settings:
    return Settings()


def test_build_llm_openai(monkeypatch, base_settings: Settings) -> None:
    captured: Dict[str, Any] = {}

    class DummyLLM:  # noqa: D401 - simple stub
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(main, "ChatOpenAI", DummyLLM)

    cfg = base_settings.model_copy(
        update={
            "llm_provider": "openai",
            "openai_model": "test-model",
            "openai_temperature": 0.2,
            "max_output_tokens": 256,
        }
    )

    llm = main._build_llm(cfg)

    assert isinstance(llm, DummyLLM)
    assert captured["model"] == "test-model"
    assert captured["temperature"] == 0.2
    assert captured["max_tokens"] == 256


def test_build_llm_azure_requires_fields(monkeypatch, base_settings: Settings) -> None:
    cfg = base_settings.model_copy(
        update={
            "llm_provider": "azure-openai",
            "azure_openai_api_key": None,
            "azure_openai_endpoint": None,
            "azure_openai_deployment": None,
        }
    )

    with pytest.raises(ValueError):
        main._build_llm(cfg)


def test_build_llm_azure(monkeypatch, base_settings: Settings) -> None:
    captured: Dict[str, Any] = {}

    class DummyAzureLLM:  # noqa: D401 - simple stub
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(main, "AzureChatOpenAI", DummyAzureLLM)

    cfg = base_settings.model_copy(
        update={
            "llm_provider": "azure-openai",
            "max_output_tokens": 256,
            "azure_openai_api_key": "test-key",
            "azure_openai_endpoint": "https://example.openai.azure.com/",
            "azure_openai_deployment": "gpt4o",
            "azure_openai_api_version": "2024-06-01",
        }
    )

    llm = main._build_llm(cfg)

    assert isinstance(llm, DummyAzureLLM)
    assert captured["azure_deployment"] == "gpt4o"
    assert captured["azure_endpoint"] == "https://example.openai.azure.com/"
    assert captured["api_version"] == "2024-06-01"
    assert captured["api_key"] == "test-key"
    assert captured["max_tokens"] == 256