from __future__ import annotations

from dataclasses import dataclass
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
        Resolve commits between two refs (inclusive of the end ref) and return
        structured change objects ordered from oldest to newest.
        """

        rev_range = self._build_rev_range(query)
        commits = list(
            self._repo.iter_commits(
                rev_range,
                max_count=query.max_count,
            )
        )
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
