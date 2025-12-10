from __future__ import annotations

from datetime import datetime
from typing import List

import pytest  # type: ignore[import]

from src.models import FileChange, RepoChange, ReviewReport, ReviewSuggestion
from src.review import BaseReviewAgent
from src.services.review_service import ReviewService


class DummyRepository:
    def __init__(self, changes: List[RepoChange]) -> None:
        self._changes = changes

    def get_commits(self, query) -> List[RepoChange]:  # noqa: D401 - simple stub
        return self._changes


class DummyAgent(BaseReviewAgent):
    def review(self, change: RepoChange) -> ReviewReport:  # noqa: D401 - simple stub
        return ReviewReport(
            commit=change,
            summary=f"Reviewed {change.sha}",
            suggestions=[
                ReviewSuggestion(
                    file_path=fc.path,
                    message="Looks good",
                    severity="info",
                )
                for fc in change.file_changes
            ],
        )


@pytest.fixture()
def sample_change() -> RepoChange:
    return RepoChange(
        sha="abc123",
        summary="Add feature X",
        description="Longer description",
        author_name="Jane Doe",
        author_email="jane@example.com",
        authored_date=datetime.utcnow(),
        file_changes=[
            FileChange(path="app.py", status="M", diff="+1 -1"),
        ],
    )


def test_review_service_returns_suggestions(sample_change: RepoChange) -> None:
    repo = DummyRepository([sample_change])
    agent = DummyAgent()
    service = ReviewService(repo, agent)  # type: ignore[arg-type]

    reports = service.review(start_ref=None, end_ref="HEAD", max_commits=None)

    assert len(reports) == 1
    assert reports[0].summary == "Reviewed abc123"
    assert reports[0].suggestions[0].file_path == "app.py"
