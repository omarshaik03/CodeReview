from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from rich.console import Console  # type: ignore[import]
from rich.table import Table  # type: ignore[import]

from src.commit_ingest import CommitQuery, GitRepository
from src.models import RepoChange, ReviewReport
from src.review import BaseReviewAgent


@dataclass(slots=True)
class ReviewServiceConfig:
    repo_path: Path
    start_ref: Optional[str] = None
    end_ref: str = "HEAD"
    max_commits: Optional[int] = None
    verbose: bool = False
    custom_guidelines: Optional[str] = None


class ReviewService:
    """Coordinates fetching commits and sending them through the review agent."""

    def __init__(self, repository: GitRepository, agent: BaseReviewAgent) -> None:
        self._repository = repository
        self._agent = agent

    def review(
        self,
        *,
        start_ref: Optional[str],
        end_ref: str,
        max_commits: Optional[int],
        custom_guidelines: Optional[str] = None,
    ) -> List[ReviewReport]:
        """
        Review commits in the repository.

        Args:
            start_ref: Starting reference (exclusive). If None, walks back from end_ref.
            end_ref: Ending reference (inclusive).
            max_commits: Maximum number of commits to review.
            custom_guidelines: Optional custom review guidelines to apply.

        Returns:
            List of ReviewReport objects.
        """
        query = CommitQuery(start_ref=start_ref, end_ref=end_ref, max_count=max_commits)
        changes = self._repository.get_commits(query)
        repo_path = self._repository.repo_path if hasattr(self._repository, 'repo_path') else None
        return [self._agent.review(change, custom_guidelines=custom_guidelines, repo_path=repo_path) for change in changes]

    def review_from_config(self, config: ReviewServiceConfig) -> List[ReviewReport]:
        return self.review(
            start_ref=config.start_ref,
            end_ref=config.end_ref,
            max_commits=config.max_commits,
            custom_guidelines=config.custom_guidelines,
        )

    def iter_review(
        self,
        *,
        start_ref: Optional[str],
        end_ref: str,
        max_commits: Optional[int],
        custom_guidelines: Optional[str] = None,
    ) -> Iterable[ReviewReport]:
        """
        Iterate through reviews of commits in the repository.

        Args:
            start_ref: Starting reference (exclusive). If None, walks back from end_ref.
            end_ref: Ending reference (inclusive).
            max_commits: Maximum number of commits to review.
            custom_guidelines: Optional custom review guidelines to apply.

        Yields:
            ReviewReport objects.
        """
        query = CommitQuery(start_ref=start_ref, end_ref=end_ref, max_count=max_commits)
        repo_path = self._repository.repo_path if hasattr(self._repository, 'repo_path') else None
        for change in self._repository.iter_commits(query):
            yield self._agent.review(change, custom_guidelines=custom_guidelines, repo_path=repo_path)

    @staticmethod
    def render_console_summary(reports: Iterable[ReviewReport], *, console: Optional[Console] = None) -> None:
        console = console or Console()
        for report in reports:
            ReviewService._render_report(console, report)

    @staticmethod
    def _render_report(console: Console, report: ReviewReport) -> None:
        title = f"[bold cyan]Commit {report.commit.sha[:8]}[/bold cyan] — {report.commit.summary}"
        console.rule(title)
        console.print(report.summary)

        if not report.suggestions:
            console.print("[green]No actionable suggestions.[/green]")
            return

        table = Table("Severity", "File", "Message", show_header=True, header_style="bold magenta")
        for suggestion in report.suggestions:
            table.add_row(suggestion.severity, suggestion.file_path, suggestion.message)
        console.print(table)