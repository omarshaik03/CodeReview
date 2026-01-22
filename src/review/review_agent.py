from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Literal, Optional

from langchain_core.output_parsers import PydanticOutputParser  # type: ignore[import]
from langchain_core.prompts import ChatPromptTemplate  # type: ignore[import]
from langchain_openai import ChatOpenAI  # type: ignore[import]
from openai import RateLimitError  # type: ignore[import]
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
    solution: Optional[str] = Field(None, description="Suggested code solution or fix for the issue")
    original_code: Optional[str] = Field(None, description="Original problematic code snippet")


class _ReviewModel(BaseModel):
    summary: str = Field(..., description="High-level summary of the commit's intent and risk")
    suggestions: List[_ReviewSuggestionModel] = Field(default_factory=list)


class LangChainReviewAgent(BaseReviewAgent):
    """LangChain-based agent that prompts an OpenAI-compatible chat model."""

    # Token usage optimization settings
    MAX_DIFF_CHARS_PER_FILE = 4000  # Truncate individual file diffs beyond this
    MAX_TOTAL_DIFF_CHARS = 12000    # Truncate total diff content beyond this
    MAX_FILES_TO_REVIEW = 10        # Skip files beyond this count (review most important)

    def __init__(
        self,
        *,
        model: str = "gpt-4o-mini",
        temperature: float = 0.1,
        max_output_tokens: int = 1200,
        llm: Optional[ChatOpenAI] = None,
        enable_json_mode: bool = False,
        enable_security_scan: bool = True,
        max_retries: int = 5,
        initial_retry_delay: float = 5.0,
        max_retry_delay: float = 60.0,
    ) -> None:
        self._parser = PydanticOutputParser(pydantic_object=_ReviewModel)
        self._enable_security_scan = enable_security_scan
        self._max_retries = max_retries
        self._initial_retry_delay = initial_retry_delay
        self._max_retry_delay = max_retry_delay
        
        # Base prompt template (will be modified with custom guidelines and security findings if provided)
        self._base_system_prompt = (
            "You are a senior software engineer performing code review."
            " Provide concise, actionable feedback without being overly verbose."
            " Focus on correctness, security, performance, testing, and readability."
            " For each finding, provide both 'original_code' and 'solution' fields:"
            " - 'original_code': The exact problematic code snippet (1-3 lines)"
            " - 'solution': The corrected/improved version of that code"
            " This allows users to see a before/after comparison."
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

        # Invoke LLM with exponential backoff for rate limit errors
        parsed: _ReviewModel = self._invoke_with_retry(payload)

        return ReviewReport(
            commit=change,
            summary=parsed.summary,
            suggestions=[
                ReviewSuggestion(
                    file_path=item.file_path,
                    message=item.message,
                    severity=item.severity,
                    solution=item.solution,
                    original_code=item.original_code,
                )
                for item in parsed.suggestions
            ],
            security_report=security_report,
        )

    def _invoke_with_retry(self, payload: dict) -> _ReviewModel:
        """Invoke LLM with exponential backoff retry logic for rate limit errors."""
        retry_delay = self._initial_retry_delay
        last_exception = None

        for attempt in range(self._max_retries):
            try:
                if self._json_chain is not None:
                    try:
                        return self._json_chain.invoke(payload)
                    except Exception as exc:
                        # If structured mode fails for non-rate-limit reasons, fall back to parser
                        if not isinstance(exc, RateLimitError):
                            logger.warning(
                                "Structured chain invocation failed. Falling back to parser pipeline.",
                                exc_info=exc,
                            )
                            return self._fallback_chain.invoke(payload)
                        raise  # Re-raise rate limit errors to retry
                else:
                    return self._fallback_chain.invoke(payload)

            except RateLimitError as exc:
                last_exception = exc
                if attempt < self._max_retries - 1:
                    logger.warning(
                        f"Rate limit error on attempt {attempt + 1}/{self._max_retries}. "
                        f"Retrying in {retry_delay:.1f} seconds..."
                    )
                    time.sleep(retry_delay)
                    # Exponential backoff with cap
                    retry_delay = min(retry_delay * 2, self._max_retry_delay)
                else:
                    logger.error(f"Rate limit error after {self._max_retries} attempts. Giving up.")
                    raise
            except Exception as exc:
                # For non-rate-limit errors, don't retry
                logger.error(f"LLM invocation failed with non-retriable error: {exc}")
                raise

        # Should never reach here, but just in case
        if last_exception:
            raise last_exception
        raise RuntimeError("Unexpected retry loop exit")

    def _render_diffs(self, file_changes) -> str:
        """Render file diffs with truncation to reduce token usage."""
        sections = []
        total_chars = 0

        # Prioritize important files (non-test, non-config files first)
        def file_priority(fc):
            path_lower = fc.path.lower()
            # Deprioritize test files, configs, and generated files
            if 'test' in path_lower or '_test' in path_lower or 'spec' in path_lower:
                return 2
            if any(name in path_lower for name in ['package-lock', 'yarn.lock', '.lock', '.min.', 'generated']):
                return 3
            if any(ext in path_lower for ext in ['.json', '.yaml', '.yml', '.toml', '.ini', '.cfg']):
                return 1
            return 0  # Source code files get highest priority

        sorted_changes = sorted(file_changes, key=file_priority)

        for idx, change in enumerate(sorted_changes):
            # Skip files beyond the limit
            if idx >= self.MAX_FILES_TO_REVIEW:
                skipped_count = len(file_changes) - self.MAX_FILES_TO_REVIEW
                sections.append(f"\n[... {skipped_count} additional file(s) not shown to reduce token usage ...]")
                break

            header = f"File: {change.path} (status={change.status})"
            diff_content = change.diff or ""

            # Truncate individual file diff if too large
            if len(diff_content) > self.MAX_DIFF_CHARS_PER_FILE:
                diff_content = diff_content[:self.MAX_DIFF_CHARS_PER_FILE]
                diff_content += f"\n\n[... diff truncated ({len(change.diff)} chars total) ...]"

            section = f"{header}\n{diff_content}"

            # Check total size limit
            if total_chars + len(section) > self.MAX_TOTAL_DIFF_CHARS:
                remaining = self.MAX_TOTAL_DIFF_CHARS - total_chars
                if remaining > 500:  # Only include if there's meaningful space
                    section = section[:remaining] + "\n\n[... remaining content truncated to reduce token usage ...]"
                    sections.append(section)
                else:
                    sections.append(f"\n[... {len(file_changes) - idx} file(s) not shown to reduce token usage ...]")
                break

            sections.append(section)
            total_chars += len(section)

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