from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class FindingType(str, Enum):
    """Type of security finding."""
    SECRET = "secret"
    DEPENDENCY_CVE = "dependency_cve"
    CODE_PATTERN = "code_pattern"
    INSECURE_CRYPTO = "insecure_crypto"
    INJECTION = "injection"
    AUTH_ISSUE = "auth_issue"
    OTHER = "other"


class FindingSeverity(str, Enum):
    """Severity level for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(slots=True)
class SecurityFinding:
    """Represents a single security finding."""

    finding_type: FindingType
    severity: FindingSeverity
    file_path: str
    line_number: Optional[int] = None
    title: str = ""
    description: str = ""
    cve_id: Optional[str] = None
    recommendation: str = ""
    raw_data: Optional[dict] = None


@dataclass(slots=True)
class SecurityReport:
    """Aggregates all security findings for a commit or repository."""

    commit_sha: Optional[str] = None
    findings: List[SecurityFinding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.LOW)

    @property
    def has_critical_issues(self) -> bool:
        return self.critical_count > 0

    @property
    def risk_level(self) -> str:
        """Overall risk assessment."""
        if self.critical_count > 0:
            return "critical"
        elif self.high_count > 0:
            return "high"
        elif self.medium_count > 0:
            return "medium"
        elif self.low_count > 0:
            return "low"
        else:
            return "none"
