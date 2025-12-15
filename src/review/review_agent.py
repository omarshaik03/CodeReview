from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Literal, Optional

from langchain_core.output_parsers import PydanticOutputParser  # type: ignore[import]
from langchain_core.prompts import ChatPromptTemplate  # type: ignore[import]
from langchain_openai import ChatOpenAI  # type: ignore[import]
from pydantic import BaseModel, Field  # type: ignore[import]

from src.models import RepoChange, ReviewReport, ReviewSuggestion
from src.security import SecurityScanner


logger = logging.getLogger(__name__)


class BaseReviewAgent(ABC):
    """Interface for review agents."""

    @abstractmethod
    def review(self, change: RepoChange, custom_guidelines: Optional[str] = None, repo_path: Optional[Path] = None) -> ReviewReport:
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
        enable_security_scan: bool = True,
    ) -> None:
        self._parser = PydanticOutputParser(pydantic_object=_ReviewModel)
        self._enable_security_scan = enable_security_scan
        
        # Base prompt template (will be modified with custom guidelines and security findings if provided)
        self._base_system_prompt = (
            "You are a senior software engineer performing code review."
            " Provide concise, actionable feedback without being overly verbose."
            " Focus on correctness, security, performance, testing, and readability."
            " Respond using the JSON schema provided in the instructions."
        )

        self._security_findings_template = (
            "\n\nSECURITY SCAN RESULTS:\n"
            "Automated security scanners have identified the following issues in the files changed by this commit:\n"
            "{security_findings}\n\n"
            "Please review these security findings and:"
            "\n1. Confirm if they are true positives or false positives (many password regex matches in test files are false positives)"
            "\n2. For true positives: explain the security impact concisely"
            "\n3. For true positives: provide actionable remediation steps"
            "\n4. Identify any additional security concerns in the changed code not caught by the scanners"
            "\n\nIMPORTANT: The severity levels are already assigned by the scanners. Use those exact severity levels in your findings."
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

    def review(self, change: RepoChange, custom_guidelines: Optional[str] = None, repo_path: Optional[Path] = None) -> ReviewReport:
        # Run security scan if enabled and repo_path is provided
        security_report = None
        if self._enable_security_scan and repo_path:
            try:
                scanner = SecurityScanner(repo_path)
                # Extract changed file paths from the commit
                changed_files = [fc.path for fc in change.file_changes]
                security_report = scanner.scan(commit_sha=change.sha, changed_files=changed_files)
                logger.info(f"Security scan found {len(security_report.findings)} findings in {len(changed_files)} changed files for commit {change.sha[:8]}")
            except Exception as exc:
                logger.warning(f"Security scan failed for commit {change.sha[:8]}: {exc}")

        # Build system prompt with optional custom guidelines and security findings
        system_prompt = self._base_system_prompt

        if custom_guidelines:
            system_prompt += f"\n\nADDITIONAL REVIEW GUIDELINES:\n{custom_guidelines}\n\nPlease apply these guidelines when reviewing the code."

        if security_report and security_report.findings:
            security_findings_text = self._format_security_findings(security_report)
            system_prompt += self._security_findings_template.format(security_findings=security_findings_text)

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
            security_report=security_report,
        )

    def _render_diffs(self, file_changes) -> str:
        sections = []
        for change in file_changes:
            header = f"File: {change.path} (status={change.status})"
            sections.append(f"{header}\n{change.diff}")
        return "\n\n".join(sections)

    def _format_security_findings(self, security_report) -> str:
        """Format security findings for LLM consumption."""
        if not security_report.findings:
            return "No security issues detected by automated scanners."

        lines = [
            f"Risk Level: {security_report.risk_level.upper()}",
            f"Total Findings: {len(security_report.findings)}",
            f"  - Critical: {security_report.critical_count}",
            f"  - High: {security_report.high_count}",
            f"  - Medium: {security_report.medium_count}",
            f"  - Low: {security_report.low_count}",
            "",
            "Detailed Findings:",
        ]

        for idx, finding in enumerate(security_report.findings, 1):
            lines.append(f"\n{idx}. [{finding.severity.value.upper()}] {finding.title}")
            lines.append(f"   Type: {finding.finding_type.value}")
            lines.append(f"   File: {finding.file_path}" + (f":{finding.line_number}" if finding.line_number else ""))
            if finding.description:
                lines.append(f"   Description: {finding.description}")
            if finding.cve_id:
                lines.append(f"   CVE: {finding.cve_id}")
            if finding.recommendation:
                lines.append(f"   Recommendation: {finding.recommendation}")

        return "\n".join(lines)