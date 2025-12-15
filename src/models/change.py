from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from src.security.models import SecurityReport


@dataclass(slots=True)
class FileChange:
    """Represents a single file delta in a commit."""

    path: str
    status: str
    diff: str


@dataclass(slots=True)
class RepoChange:
    """Aggregates metadata and file-level diffs for a commit."""

    sha: str
    summary: str
    description: str
    author_name: str
    author_email: str
    authored_date: datetime
    file_changes: List[FileChange] = field(default_factory=list)


@dataclass(slots=True)
class ReviewSuggestion:
    """Structured review feedback targeted at a single file."""

    file_path: str
    message: str
    severity: str = "info"


@dataclass(slots=True)
class ReviewReport:
    """LLM-generated review output for a commit."""

    commit: RepoChange
    summary: str
    suggestions: List[ReviewSuggestion] = field(default_factory=list)
    security_report: Optional[SecurityReport] = None
