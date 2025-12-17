# Inclusive Range Fix

## Problem

The `from_ref` parameter was documented as "exclusive", which caused confusion and unexpected behavior:

1. **Extra commit included**: When specifying `from_ref`, the commit **before** that ref was also included in results
2. **Inconsistent with expectations**: Users expected `from_ref` to be the starting point, not the commit after it
3. **Git range syntax issue**: Git's `A..B` syntax means "commits reachable from B but not from A", which excludes A

### Example of the Problem

```bash
# Repository history:
# Commit A (oldest)
# Commit B
# Commit C
# Commit D (HEAD)

# Request:
{
  "from_ref": "B",  # User expects: B, C, D
  "to_ref": "HEAD"
}

# Old behavior: Returns A, B, C, D ❌
# (includes commit before B!)
```

## Solution

Changed `from_ref` to be **inclusive** (matching user expectations):

### Implementation Changes

**Before (using Git's `..` syntax):**
```python
rev_range = f"{start_ref}..{end_ref}"
commits = list(repo.iter_commits(rev_range))
```

**After (manual filtering for inclusive behavior):**
```python
# Get all commits up to end_ref (returns newest-to-oldest)
commits = list(repo.iter_commits(end_ref))

# Filter to include only commits from start_ref to end_ref (inclusive)
if start_ref:
    start_commit_sha = repo.commit(start_ref).hexsha
    filtered_commits = []
    # Iterate through commits (newest to oldest)
    for commit in commits:
        filtered_commits.append(commit)  # Include this commit
        if commit.hexsha == start_commit_sha:
            # Found the start (oldest) commit, stop here
            break
    commits = filtered_commits

# Reverse to get oldest-first order
commits.reverse()
```

## New Behavior

Both `from_ref` and `to_ref` are now **inclusive**:

```bash
# Repository history:
# Commit A (oldest)
# Commit B
# Commit C
# Commit D (HEAD)

# Request:
{
  "from_ref": "B",
  "to_ref": "D"
}

# New behavior: Returns B, C, D ✅
# (exactly what the user expects!)
```

### Range Notation

- **Old:** `(from_ref, to_ref]` - from_ref exclusive, to_ref inclusive
- **New:** `[from_ref, to_ref]` - **both inclusive**

## Documentation Updates

All documentation has been updated to reflect the inclusive behavior:

### API Documentation
- [src/main.py](src/main.py): Field descriptions changed from "exclusive" to "inclusive"
- All endpoints (POST, GET, upload, URL) updated

### Code Documentation
- [git_repository.py](src/commit_ingest/git_repository.py): Docstrings updated
- [review_service.py](src/services/review_service.py): Docstrings updated

### User Documentation
- [DATE_FILTERING.md](DATE_FILTERING.md): Updated examples and explanations

## Examples

### Example 1: Review Last 5 Commits (Inclusive)

```bash
# Get the 5th-to-last commit SHA
OLDEST_SHA=$(git rev-parse HEAD~4)

curl -X POST "http://localhost:8004/review" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/repo",
    "from_ref": "'$OLDEST_SHA'",
    "to_ref": "HEAD"
  }'

# Returns exactly 5 commits: HEAD~4, HEAD~3, HEAD~2, HEAD~1, HEAD
```

### Example 2: Review Specific Commit Range

```bash
curl -X POST "http://localhost:8004/review" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/repo",
    "from_ref": "abc123",
    "to_ref": "def456"
  }'

# Returns all commits from abc123 to def456 (inclusive)
# Including abc123 itself
```

### Example 3: Using HEAD~ Syntax

```bash
curl -X POST "http://localhost:8004/review" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/repo",
    "from_ref": "HEAD~9",
    "to_ref": "HEAD"
  }'

# Returns exactly 10 commits: HEAD~9 through HEAD (inclusive)
```

## Migration Notes

**Breaking Change:** This is a **breaking change** if you were relying on the old exclusive behavior.

### If You Were Using Exclusive Ranges

**Old code (expecting exclusive):**
```json
{
  "from_ref": "HEAD~10",  // Wanted to skip HEAD~10
  "to_ref": "HEAD"
}
```

**New code (to achieve same result):**
```json
{
  "from_ref": "HEAD~9",   // Now start one commit later
  "to_ref": "HEAD"
}
```

### Why This Change?

1. **More intuitive**: Users naturally expect ranges to be inclusive on both ends
2. **Consistency**: Matches the behavior of date ranges (which are also inclusive)
3. **No extra commits**: Eliminates the confusing "extra commit before from_ref" issue
4. **Standard behavior**: Most tools treat ranges as inclusive

## Testing

To verify the fix works correctly:

```bash
# Create a test repo with known commits
mkdir test-repo && cd test-repo
git init
echo "A" > file.txt && git add . && git commit -m "Commit A"
echo "B" > file.txt && git add . && git commit -m "Commit B"
echo "C" > file.txt && git add . && git commit -m "Commit C"
echo "D" > file.txt && git add . && git commit -m "Commit D"

# Get commit SHA for B
COMMIT_B=$(git rev-parse HEAD~2)

# Review from B to HEAD
curl -X POST "http://localhost:8004/review" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "'$(pwd)'",
    "from_ref": "'$COMMIT_B'",
    "to_ref": "HEAD"
  }' | jq '.commit_count'

# Expected output: 3
# (commits B, C, D)

# Verify the commits
curl -X POST "http://localhost:8004/review" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "'$(pwd)'",
    "from_ref": "'$COMMIT_B'",
    "to_ref": "HEAD"
  }' | jq '.reviews[].commit_message'

# Expected output:
# "Commit B"
# "Commit C"
# "Commit D"
```

## Date Range Inclusive Fix

Similar to the commit reference fix, date ranges also needed adjustment to ensure both ends are inclusive.

### Date Range Problem

When using date-only format (YYYY-MM-DD), the `until` parameter was exclusive:

```bash
# Request:
{
  "since": "2024-01-01",
  "until": "2024-01-31"
}

# Problem: Commits made on 2024-01-31 at 10:00 AM were excluded
# Git interprets "2024-01-31" as "2024-01-31 00:00:00"
```

### Date Range Solution

Automatically extend date-only `until` values to end of day:

```python
if query.until:
    until_date = query.until
    # Check if time is midnight (00:00:00), indicating date-only input
    if until_date.hour == 0 and until_date.minute == 0 and until_date.second == 0:
        # Extend to end of day to include all commits from that date
        until_date = until_date.replace(hour=23, minute=59, second=59, microsecond=999999)
    iter_kwargs['until'] = until_date
```

### Date Range Behavior

```bash
# Request (date-only format):
{
  "since": "2024-01-01",
  "until": "2024-01-31"
}

# New behavior:
# - since: "2024-01-01 00:00:00" (start of day)
# - until: "2024-01-31 23:59:59.999999" (end of day)
# Result: Includes ALL commits from both January 1 and January 31 ✅

# Request (with explicit time):
{
  "since": "2024-01-01T09:00:00",
  "until": "2024-01-31T17:00:00"
}

# Behavior: Uses exact times specified (no auto-extension)
# Result: Commits from 9 AM Jan 1 to 5 PM Jan 31
```

## Summary

- ✅ `from_ref` is now **inclusive** (was exclusive)
- ✅ `to_ref` remains **inclusive**
- ✅ `since` date is **inclusive** (start of day)
- ✅ `until` date is now **inclusive** (end of day when using date-only format)
- ✅ No extra commits included
- ✅ All documentation updated
- ✅ Behavior matches user expectations
- ⚠️ **Breaking change** - adjust existing code if relying on exclusive behavior
