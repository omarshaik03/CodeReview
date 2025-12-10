from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import List, Literal, Optional

from langchain_core.output_parsers import PydanticOutputParser  # type: ignore[import]
from langchain_core.prompts import ChatPromptTemplate  # type: ignore[import]
from langchain_openai import ChatOpenAI  # type: ignore[import]
from pydantic import BaseModel, Field  # type: ignore[import]

from src.models import RepoChange, ReviewReport, ReviewSuggestion


logger = logging.getLogger(__name__)


class BaseReviewAgent(ABC):
    """Interface for review agents."""

    @abstractmethod
    def review(self, change: RepoChange, custom_guidelines: Optional[str] = None) -> ReviewReport:
        raise NotImplementedError


class _ReviewSuggestionModel(BaseModel):
    file_path: str = Field(..., description="File path relative to repo root")
    message: str = Field(..., description="Concise review feedback")
    severity: Literal["info", "nit", "warn", "critical"] = "info"


class _ReviewModel(BaseModel):
    summary: str = Field(..., description="High-level summary of the commit's intent and risk")
    suggestions: List[_ReviewSuggestionModel] = Field(default_factory=list)


class LangChainReviewAgent(BaseReviewAgent):
    """LangChain-based agent that prompts an OpenAI-compatible chat model."""

    def __init__(
        self,
        *,
        model: str = "gpt-4o-mini",
        temperature: float = 0.1,
        max_output_tokens: int = 1200,
        llm: Optional[ChatOpenAI] = None,
        enable_json_mode: bool = False,
    ) -> None:
        self._parser = PydanticOutputParser(pydantic_object=_ReviewModel)
        
        # Base prompt template (will be modified with custom guidelines if provided)
        self._base_system_prompt = (
            "You are a senior software engineer performing code review."
            " Provide concise, actionable feedback without being overly verbose."
            " Focus on correctness, security, performance, testing, and readability."
            " Respond using the JSON schema provided in the instructions."
        )
        
        self._prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "{system_prompt}",
                ),
                (
                    "user",
                    "Commit metadata:\n"
                    "SHA: {sha}\n"
                    "Summary: {summary}\n"
                    "Description:\n{description}\n\n"
                    "Changes:\n{diffs}\n\n"
                    "{format_instructions}",
                ),
            ]
        )

        llm_kwargs = {"model": model, "temperature": temperature}
        if max_output_tokens:
            llm_kwargs["max_tokens"] = max_output_tokens

        base_llm = llm or ChatOpenAI(**llm_kwargs)

        self._json_chain = None
        if enable_json_mode:
            try:
                structured_llm = base_llm.with_structured_output(
                    _ReviewModel, method="json_mode"
                )
                self._json_chain = self._prompt | structured_llm
                logger.debug("Structured JSON mode enabled for review agent.")
            except Exception as exc:  # pragma: no cover - optional feature
                logger.warning(
                    "Failed to enable JSON mode for LangChain review agent. Falling back to parser pipeline.",
                    exc_info=exc,
                )

        self._llm = base_llm
        self._fallback_chain = self._prompt | self._llm | self._parser

    def review(self, change: RepoChange, custom_guidelines: Optional[str] = None) -> ReviewReport:
        # Build system prompt with optional custom guidelines
        system_prompt = self._base_system_prompt
        if custom_guidelines:
            system_prompt += f"\n\nADDITIONAL REVIEW GUIDELINES:\n{custom_guidelines}\n\nPlease apply these guidelines when reviewing the code."
        
        payload = {
            "system_prompt": system_prompt,
            "sha": change.sha,
            "summary": change.summary,
            "description": change.description,
            "diffs": self._render_diffs(change.file_changes),
            "format_instructions": self._parser.get_format_instructions(),
        }

        parsed: _ReviewModel
        if self._json_chain is not None:
            try:
                parsed = self._json_chain.invoke(payload)
            except Exception as exc:  # pragma: no cover - runtime fallback
                logger.warning(
                    "Structured chain invocation failed. Falling back to parser pipeline.",
                    exc_info=exc,
                )
                parsed = self._fallback_chain.invoke(payload)
        else:
            parsed = self._fallback_chain.invoke(payload)

        return ReviewReport(
            commit=change,
            summary=parsed.summary,
            suggestions=[
                ReviewSuggestion(
                    file_path=item.file_path,
                    message=item.message,
                    severity=item.severity,
                )
                for item in parsed.suggestions
            ],
        )

    def _render_diffs(self, file_changes) -> str:
        sections = []
        for change in file_changes:
            header = f"File: {change.path} (status={change.status})"
            sections.append(f"{header}\n{change.diff}")
        return "\n\n".join(sections)