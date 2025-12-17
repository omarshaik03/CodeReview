from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, List, Optional

from git import Commit, NULL_TREE, Repo  # type: ignore[import]

from src.models import FileChange, RepoChange


class GitRepositoryError(RuntimeError):
    """Raised when the repository cannot be accessed or read."""


@dataclass(slots=True)
class CommitQuery:
    start_ref: Optional[str] = None
    end_ref: str = "HEAD"
    max_count: Optional[int] = None
    since: Optional[datetime] = None  # Start date (inclusive)
    until: Optional[datetime] = None  # End date (inclusive)


class GitRepository:
    """Thin wrapper around GitPython for extracting commit metadata and patches."""

    def __init__(self, repo_path: str | Path) -> None:
        self.repo_path = Path(repo_path)
        if not self.repo_path.exists():
            raise GitRepositoryError(f"Repository path does not exist: {self.repo_path}")

        try:
            self._repo = Repo(self.repo_path)
        except Exception as exc:  # pragma: no cover - GitPython error types vary
            raise GitRepositoryError(f"Failed to open repository: {exc}") from exc

        if self._repo.bare:
            raise GitRepositoryError("Bare repositories are not supported")

    def get_commits(self, query: CommitQuery) -> List[RepoChange]:
        """
        Resolve commits between two refs or date ranges and return
        structured change objects ordered from oldest to newest.

        Supports either:
        - Ref-based filtering (start_ref, end_ref) - both inclusive
        - Date-based filtering (since, until) - both inclusive
        But not both simultaneously.
        """
        # Build arguments for iter_commits
        iter_kwargs = {}

        if query.since or query.until:
            # Date-based filtering
            rev = query.end_ref if query.end_ref != "HEAD" else "HEAD"
            if query.since:
                iter_kwargs['since'] = query.since
            if query.until:
                # Make until date inclusive by extending to end of day if no time specified
                until_date = query.until
                # Check if time is midnight (00:00:00), indicating date-only input
                if until_date.hour == 0 and until_date.minute == 0 and until_date.second == 0:
                    # Extend to end of day to include all commits from that date
                    until_date = until_date.replace(hour=23, minute=59, second=59, microsecond=999999)
                iter_kwargs['until'] = until_date
            if query.max_count:
                iter_kwargs['max_count'] = query.max_count

            commits = list(self._repo.iter_commits(rev, **iter_kwargs))
        else:
            # Ref-based filtering - get all commits up to end_ref, then filter by start_ref
            if query.max_count:
                iter_kwargs['max_count'] = query.max_count

            commits = list(self._repo.iter_commits(query.end_ref, **iter_kwargs))

            # If start_ref is provided, filter to only include commits from start_ref to end_ref (inclusive)
            if query.start_ref:
                start_commit_sha = self._repo.commit(query.start_ref).hexsha

                # iter_commits returns newest-to-oldest, so we collect commits until we find start_ref
                filtered_commits = []
                for commit in commits:
                    filtered_commits.append(commit)
                    if commit.hexsha == start_commit_sha:
                        # Found the start commit, stop here
                        break

                commits = filtered_commits

        commits.reverse()  # oldest first for conversational flow
        return [self._map_commit(commit) for commit in commits]

    def latest_commit(self) -> RepoChange:
        return self._map_commit(self._repo.commit("HEAD"))

    def _build_rev_range(self, query: CommitQuery) -> str:
        if query.start_ref:
            return f"{query.start_ref}..{query.end_ref}"
        return query.end_ref

    def _map_commit(self, commit: Commit) -> RepoChange:
        parents = commit.parents
        base_tree = parents[0] if parents else NULL_TREE
        diff_index = commit.diff(base_tree, create_patch=True)

        file_changes: List[FileChange] = []
        for diff in diff_index:
            file_changes.append(
                FileChange(
                    path=diff.b_path or diff.a_path or "",
                    status=self._derive_status(diff),
                    diff=self._decode_patch(diff.diff),
                )
            )

        return RepoChange(
            sha=commit.hexsha,
            summary=commit.summary,
            description=commit.message.strip(),
            author_name=commit.author.name,
            author_email=commit.author.email,
            authored_date=commit.authored_datetime,
            file_changes=file_changes,
        )

    def _derive_status(self, diff) -> str:  # type: ignore[no-untyped-def]
        if diff.new_file:
            return "A"
        if diff.deleted_file:
            return "D"
        if diff.renamed:
            return "R"
        return "M"

    def _decode_patch(self, data: bytes | None) -> str:
        if not data:
            return ""
        return data.decode("utf-8", errors="replace")

    def iter_commits(self, query: CommitQuery) -> Iterator[RepoChange]:
        for change in self.get_commits(query):
            yield change
