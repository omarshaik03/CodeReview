# Date Range Filtering

The Code Review API now supports filtering commits by date range in addition to commit references.

## Overview

You can review commits using **either**:
1. **Commit references** (SHA hashes or refs like `HEAD~5`) - the original method
2. **Date ranges** (ISO 8601 timestamps) - **NEW**

These two methods are **mutually exclusive** - you cannot use both simultaneously.

## Usage

### Method 1: Commit Reference Filtering (Original)

Filter commits between two commit references:

```bash
curl -X POST "http://localhost:8004/review" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/repo",
    "from_ref": "HEAD~10",
    "to_ref": "HEAD",
    "max_commits": 5
  }'
```

**How it works:**
- `from_ref`: Oldest commit (inclusive) - reviews start *from* this commit
- `to_ref`: Newest commit (inclusive) - reviews up to and including this commit
- Reviews commits in the range `[from_ref, to_ref]` (both inclusive)

### Method 2: Date Range Filtering (NEW)

Filter commits by date range:

```bash
curl -X POST "http://localhost:8004/review" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/repo",
    "since": "2024-01-01T00:00:00",
    "until": "2024-12-31T23:59:59",
    "max_commits": 100
  }'
```

**How it works:**
- `since`: Start date (inclusive) - includes commits on or after this date
- `until`: End date (inclusive) - includes commits on or before this date
  - When using date-only format (YYYY-MM-DD), the date is automatically extended to 23:59:59.999999 to include all commits from that entire day
- Reviews all commits in the range `[since, until]`

## Date Formats

The API accepts ISO 8601 datetime formats:

**Date only (recommended for full-day ranges):**
```json
{
  "since": "2024-01-01",
  "until": "2024-12-31"
}
```
Note: When using date-only format, `until` is automatically extended to 23:59:59.999999 of that day to include all commits from the entire date.

**Date with time:**
```json
{
  "since": "2024-01-01T00:00:00",
  "until": "2024-12-31T23:59:59"
}
```

**With timezone:**
```json
{
  "since": "2024-01-01T00:00:00Z",
  "until": "2024-12-31T23:59:59Z"
}
```

## Validation Rules

### Mutual Exclusivity

The API enforces that you can **only use one filtering method at a time**:

✅ **Valid:**
```json
{
  "repo_path": "/path/to/repo",
  "from_ref": "HEAD~5",
  "to_ref": "HEAD"
}
```

✅ **Valid:**
```json
{
  "repo_path": "/path/to/repo",
  "since": "2024-01-01",
  "until": "2024-12-31"
}
```

❌ **Invalid:**
```json
{
  "repo_path": "/path/to/repo",
  "from_ref": "HEAD~5",
  "since": "2024-01-01"
}
```
Error: `Cannot use both commit references (from_ref/to_ref) and date filters (since/until)`

### Default Behavior

- If neither method is specified, defaults to reviewing from the repository's history up to `HEAD`
- The `to_ref` parameter defaults to `"HEAD"`
- Date parameters default to `None`

## Examples

### Example 1: Review Last Month's Commits

```bash
curl -X POST "http://localhost:8004/review" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/repo",
    "since": "2024-11-01",
    "until": "2024-11-30"
  }'
```

### Example 2: Review All Commits Since a Specific Date

```bash
curl -X POST "http://localhost:8004/review" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/repo",
    "since": "2024-06-01"
  }'
```

Note: `until` is optional. If omitted, it reviews up to the latest commit.

### Example 3: Review Commits Up To a Specific Date

```bash
curl -X POST "http://localhost:8004/review" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/repo",
    "until": "2024-10-31"
  }'
```

Note: `since` is optional. If omitted, it reviews from the beginning of the repository.

### Example 4: Review Specific Date with Commit Limit

```bash
curl -X POST "http://localhost:8004/review" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/repo",
    "since": "2024-12-01T09:00:00",
    "until": "2024-12-01T17:00:00",
    "max_commits": 50
  }'
```

This reviews commits made on December 1, 2024 between 9 AM and 5 PM, limited to 50 commits.

## API Endpoints

All endpoints support date range filtering:

### POST /review
```bash
curl -X POST "http://localhost:8004/review" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/repo",
    "since": "2024-01-01",
    "until": "2024-12-31"
  }'
```

### GET /review
```bash
curl -X GET "http://localhost:8004/review?repo_path=/path/to/repo&since=2024-01-01&until=2024-12-31"
```

### POST /review/upload
```bash
curl -X POST "http://localhost:8004/review/upload" \
  -F "file=@repository.zip" \
  -F "since=2024-01-01" \
  -F "until=2024-12-31"
```

### POST /review/url
```bash
curl -X POST "http://localhost:8004/review/url" \
  -F "repo_url=https://github.com/user/repo.git" \
  -F "since=2024-01-01" \
  -F "until=2024-12-31"
```

## Swagger UI

The Swagger UI (http://localhost:8004/docs) now shows two separate example requests for each endpoint:

1. **"Review using commit references"** - Traditional method
2. **"Review using date range"** - New date-based method

The descriptions on each field clearly indicate that commit refs and date ranges cannot be mixed.

## Use Cases

### When to Use Commit References

- Reviewing a specific feature branch
- Reviewing changes between two releases
- Code review during pull request
- Reviewing recent commits (e.g., `HEAD~10..HEAD`)

### When to Use Date Ranges

- Monthly/quarterly code audits
- Reviewing all changes made during a sprint
- Compliance reviews for a specific time period
- Historical analysis of code changes
- Reviewing commits from a specific date when you don't know the commit hashes

## Technical Details

### Implementation

Date filtering is implemented at the Git level using GitPython's `iter_commits()` with `since` and `until` parameters:

```python
# Internal implementation
commits = repo.iter_commits(
    rev="HEAD",
    since=datetime(2024, 1, 1),
    until=datetime(2024, 12, 31)
)
```

### Commit Ordering

Commits are returned in **chronological order** (oldest first), regardless of whether you use commit references or date ranges.

### Performance

Date range filtering is efficient because it's handled natively by Git. For large repositories:
- Date ranges: Git efficiently filters by commit date
- Commit refs: Git walks the graph between two refs

Both methods scale well to large repositories.

## Troubleshooting

### Issue: No commits found with date range

**Problem:** Query returns 0 commits even though you expect results.

**Possible causes:**
1. Date range doesn't include any commits
2. Timezone mismatch (commits were authored in a different timezone)
3. Using committer date vs author date (Git uses author date by default)

**Solution:**
- Verify commit dates: `git log --since="2024-01-01" --until="2024-12-31"`
- Use wider date range for testing
- Check repository's actual commit history dates

### Issue: Validation error when mixing filters

**Error:**
```
Cannot use both commit references (from_ref/to_ref) and date filters (since/until)
```

**Solution:** Remove either the commit reference parameters OR the date parameters:

❌ Don't do this:
```json
{
  "from_ref": "HEAD~5",
  "since": "2024-01-01"
}
```

✅ Do this (refs only):
```json
{
  "from_ref": "HEAD~5",
  "to_ref": "HEAD"
}
```

✅ Or this (dates only):
```json
{
  "since": "2024-01-01",
  "until": "2024-12-31"
}
```

## Migration Guide

If you have existing scripts using commit references, they will continue to work without any changes. Date filtering is an additional option, not a replacement.

**Existing code (still works):**
```python
response = requests.post("http://localhost:8004/review", json={
    "repo_path": "/path/to/repo",
    "from_ref": "HEAD~10",
    "to_ref": "HEAD"
})
```

**New option (using dates):**
```python
response = requests.post("http://localhost:8004/review", json={
    "repo_path": "/path/to/repo",
    "since": "2024-01-01",
    "until": "2024-12-31"
})
```

## Summary

- **Two filtering methods:** Commit references OR date ranges
- **Mutually exclusive:** Cannot mix both methods
- **Flexible formats:** Supports various ISO 8601 datetime formats
- **All endpoints:** Available on all review endpoints
- **Backward compatible:** Existing code continues to work
- **Swagger documented:** Clear examples in the API documentation
