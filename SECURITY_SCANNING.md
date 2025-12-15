# Security Scanning Features

This document describes the security vulnerability detection capabilities added to the Code Review Assistant.

## Overview

The Code Review Assistant now includes **hybrid security scanning** that combines:
1. **Deterministic security scanners** - Find concrete, verifiable issues
2. **LLM analysis** - Explain, prioritize, and contextualize findings

This approach provides both **accuracy** (from automated tools) and **trust** (from AI-enhanced explanation).

## Architecture

### Three-Phase Scanning Pipeline

#### Phase 1: Secrets Detection
**Purpose:** Find exposed credentials, API keys, and sensitive data

**Tools used (in priority order):**
1. **gitleaks** (recommended) - Most comprehensive secrets scanner
2. **detect-secrets** (fallback) - Alternative secrets detection
3. **Regex patterns** (fallback) - Built-in pattern matching

**What it catches:**
- AWS access keys and secret keys
- GitHub tokens (classic and fine-grained)
- OpenAI API keys
- Generic API keys and secrets
- Private keys (RSA, EC, DSA, etc.)
- Hardcoded passwords

#### Phase 2: Dependency Vulnerabilities
**Purpose:** Identify known CVEs in project dependencies

**Tools used:**

**Python projects:**
- **pip-audit** (recommended) - Official Python dependency auditor
- **safety** (fallback) - Alternative vulnerability database

**JavaScript/Node.js projects:**
- **npm audit** - Built-in npm vulnerability scanner

**What it catches:**
- Known CVEs in dependencies
- Outdated packages with security patches
- Vulnerable package versions

#### Phase 3: Code Security Patterns (SAST)
**Purpose:** Find insecure coding patterns

**Tools used:**
- **semgrep** - Multi-language static analysis (auto-detects language)
- **bandit** - Python-specific security linter

**What it catches:**
- SQL injection patterns
- Command injection vulnerabilities
- Insecure cryptography (weak hashing, hardcoded keys)
- Authentication issues
- Unsafe deserialization
- Use of eval() and similar dangerous functions

## Installation

### Basic Installation
The core application works without security scanners but provides limited functionality:

```bash
pip install -e .
```

### Recommended: Install with Security Tools

#### Option 1: Install Python security scanners only
```bash
pip install -e ".[security]"
```

This installs:
- `bandit` - Python SAST
- `pip-audit` - Python dependency scanner
- `safety` - Alternative Python dependency scanner

#### Option 2: Install external tools for full coverage

**Linux/macOS:**
```bash
# Install gitleaks (secrets scanning)
brew install gitleaks  # macOS
# OR on Linux:
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/

# Install semgrep (multi-language SAST)
pip install semgrep

# Install detect-secrets (alternative secrets scanner)
pip install detect-secrets
```

**Windows:**
```powershell
# Install gitleaks
scoop install gitleaks
# OR download from https://github.com/gitleaks/gitleaks/releases

# Install semgrep
pip install semgrep

# Install detect-secrets
pip install detect-secrets
```

#### Option 3: Docker-based deployment
```bash
# Use the provided Dockerfile which includes all security tools
docker build -t code-review-security .
```

## Usage

### Two Modes of Security Scanning

The system provides two distinct modes:

#### 1. Per-Commit Security Scanning (Default)

When reviewing commits, security scans are **scoped to the files changed in each commit**. This prevents noise and false attribution:

- **Secrets & SAST**: Only scans files modified in the commit
- **Dependencies**: Only scans if dependency files (requirements.txt, package.json, etc.) were changed
- **Result**: Security findings are directly related to the commit's changes

This is the recommended mode for code review workflows.

#### 2. Repository-Wide Security Scanning

For a complete security audit of the entire repository, use the dedicated endpoint:

```bash
# Full repository security scan
curl -X POST "http://localhost:8004/security/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/repo"
  }'
```

This scans the **entire repository** for:
- All secrets in all files
- All dependency vulnerabilities
- All code security patterns

**Example per-commit review** (security scoped to changed files):

```bash
curl -X POST "http://localhost:8004/review" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_path": "/path/to/repo",
    "to_ref": "HEAD",
    "format": "json"
  }'
```

### Response Format

#### Per-Commit Review Response

The response will include a `security_summary` section for each commit, containing only findings in files changed by that commit:

```json
{
  "success": true,
  "commit_count": 1,
  "reviews": [
    {
      "commit_hash": "abc123...",
      "commit_message": "Add authentication module",
      "summary": "This commit introduces user authentication...",
      "findings": [...],
      "security_summary": {
        "risk_level": "high",
        "total_findings": 3,
        "critical_count": 1,
        "high_count": 2,
        "medium_count": 0,
        "low_count": 0,
        "findings": [
          {
            "finding_type": "secret",
            "severity": "critical",
            "file_path": "src/config.py",
            "line_number": 42,
            "title": "Secret detected: OpenAI API Key",
            "description": "Potential secret or credential found",
            "cve_id": null,
            "recommendation": "Remove the secret and rotate credentials immediately. Use environment variables or secret management systems."
          }
        ]
      }
    }
  ]
}
```

#### Repository-Wide Security Scan Response

```json
{
  "risk_level": "high",
  "total_findings": 5,
  "critical_count": 0,
  "high_count": 3,
  "medium_count": 2,
  "low_count": 0,
  "findings": [
    {
      "finding_type": "secret",
      "severity": "high",
      "file_path": "tests/test_utils.py",
      "line_number": 230,
      "title": "Potential Password detected",
      "description": "Line contains pattern matching Password",
      "cve_id": null,
      "recommendation": "Verify if this is a real secret. If so, remove and rotate immediately."
    }
  ]
}
```

### Disabling Security Scanning

If you want to disable security scanning (not recommended for production):

```python
# In your code
from src.review import LangChainReviewAgent

agent = LangChainReviewAgent(
    model="gpt-4o-mini",
    enable_security_scan=False  # Disable security scanning
)
```

## How It Works

### 1. Commit Analysis Flow (Scoped Scanning)

```
Repository → Extract Commits → For Each Commit:
                                 ├─ Get changed files list
                                 ├─ Run Security Scanners (SCOPED):
                                 │  ├─ Secrets: only in changed files
                                 │  ├─ SAST: only on changed files
                                 │  └─ Dependencies: only if deps changed
                                 ├─ Aggregate Findings
                                 └─ Send to LLM with:
                                    ├─ Code diffs
                                    ├─ Security findings (scoped)
                                    └─ Custom guidelines
                                        ↓
                                    LLM Output:
                                    ├─ Validates findings (filters false positives)
                                    ├─ Explains risks concisely
                                    ├─ Suggests fixes
                                    └─ Identifies missed issues in changes
```

**Key Principle**: Security findings are only reported if they appear in files the commit actually modified. This prevents:
- Blaming documentation commits for test file passwords
- Reporting the same repo-wide CVEs on every commit
- Noise from unrelated security issues

### 2. LLM Enhancement & Severity Handling

**Important**: Severity levels are assigned by the security scanners, not the LLM. The LLM's role is to validate and explain, not to re-score.

The LLM receives structured security findings and is prompted to:
1. **Confirm** if findings are true positives or false positives (e.g., "password" in test files is usually a false positive)
2. **Explain** the security impact concisely for true positives
3. **Provide** actionable remediation steps
4. **Identify** additional security concerns not caught by scanners

The LLM uses the scanner's severity in its response to maintain consistency.

Example LLM-enhanced output:
```
Finding: Hardcoded API key in config.py:42 [HIGH severity]

LLM Analysis:
- ✓ True positive - this is a valid OpenAI API key
- Impact: If this code is pushed to a public repository, the API key will be exposed,
  allowing unauthorized access to your OpenAI account and potential billing fraud
- Fix:
  1. Immediately rotate the API key at https://platform.openai.com/api-keys
  2. Move to environment variable: os.getenv('OPENAI_API_KEY')
  3. Add .env to .gitignore
  4. Use git filter-branch to remove from history if already committed
```

Example false positive detection:
```
Finding: Potential Password in tests/test_auth.py:42 [HIGH severity]

LLM Analysis:
- ✗ False positive - this is a test fixture with a fake password: "password123"
- This is safe test code and not a real credential
- No action needed
```

## Security Finding Types

### Finding Severity Levels

| Severity | Description | Example |
|----------|-------------|---------|
| **CRITICAL** | Immediate security risk requiring urgent action | Exposed AWS credentials, SQL injection |
| **HIGH** | Significant security issue that should be fixed soon | Known CVE with exploit available, weak crypto |
| **MEDIUM** | Security issue that should be addressed | Outdated dependencies, missing input validation |
| **LOW** | Minor security concern or best practice | Weak random number generation, TODO security notes |
| **INFO** | Informational finding, no immediate risk | Security-related code comments |

### Finding Types

| Type | Description | Tools |
|------|-------------|-------|
| `secret` | Exposed credentials, API keys, tokens | gitleaks, detect-secrets, regex |
| `dependency_cve` | Known vulnerabilities in dependencies | pip-audit, safety, npm audit |
| `code_pattern` | Insecure coding patterns | bandit, semgrep |
| `insecure_crypto` | Weak cryptography usage | bandit, semgrep |
| `injection` | SQL/Command injection risks | semgrep, bandit |
| `auth_issue` | Authentication/authorization problems | semgrep |
| `other` | Other security concerns | LLM analysis |

## Best Practices

### 1. Install Security Tools
For the best results, install all recommended security tools:
```bash
# Python tools
pip install -e ".[security]"
pip install semgrep detect-secrets

# System tools (choose based on your OS)
brew install gitleaks  # macOS
scoop install gitleaks  # Windows
```

### 2. Use Custom Guidelines
Enhance security scanning with custom review guidelines:

```python
POST /review
{
  "repo_path": "/path/to/repo",
  "review_guidelines": "Focus on OWASP Top 10 vulnerabilities. Pay special attention to authentication and session management."
}
```

### 3. Integrate into CI/CD
Add security scanning to your CI pipeline:

```yaml
# .github/workflows/code-review.yml
name: Security Code Review
on: [push, pull_request]
jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Code Review
        run: |
          pip install -e ".[security]"
          python -m uvicorn src.main:app &
          curl -X POST http://localhost:8004/review \
            -H "Content-Type: application/json" \
            -d '{"repo_path": ".", "to_ref": "HEAD"}'
```

### 4. Regular Scans
Run security scans regularly, not just on new commits:
- **On every commit** - Catch issues early
- **Weekly** - Full repository scan
- **Before releases** - Comprehensive security audit

## Limitations and Caveats

### Tool Availability
- Security scanners are **optional dependencies**
- If tools are not installed, that scanner is skipped
- Regex-based fallbacks provide basic coverage

### False Positives
- Automated tools may flag legitimate code as vulnerable
- LLM helps identify false positives
- Review findings manually for critical changes

### Language Support
- **Full support:** Python, JavaScript/TypeScript
- **Partial support:** Go, Java, Ruby (via semgrep)
- **Limited:** Other languages (regex-based only)

### Performance
- Security scanning adds overhead to code review
- Typical overhead: 5-30 seconds per commit
- Large repositories may take longer

## Troubleshooting

### "No security findings" but expecting some
1. Verify security tools are installed: `which gitleaks bandit pip-audit`
2. Check logs for scanner errors
3. Ensure repository contains the files being scanned

### High false positive rate
1. Use LLM analysis to filter false positives
2. Add custom guidelines to refine scanning
3. Configure tool-specific ignore files (`.bandit`, `.semgrepignore`)

### Scanner timeouts
1. Increase timeout values in [scanner.py](src/security/scanner.py)
2. Exclude large files or vendor directories
3. Run scanners separately for large repos

## Example Output

### Complete Security Report Example

```json
{
  "commit_hash": "a1b2c3d4",
  "commit_message": "Add payment processing",
  "summary": "Introduces Stripe integration for payment processing",
  "findings": [
    {
      "severity": "warn",
      "file": "src/payment.py",
      "message": "Consider adding retry logic for payment failures"
    }
  ],
  "security_summary": {
    "risk_level": "high",
    "total_findings": 4,
    "critical_count": 1,
    "high_count": 2,
    "medium_count": 1,
    "low_count": 0,
    "findings": [
      {
        "finding_type": "secret",
        "severity": "critical",
        "file_path": "src/config.py",
        "line_number": 15,
        "title": "Secret detected: Stripe API Key",
        "description": "sk_live_... pattern detected",
        "recommendation": "Use environment variables for API keys"
      },
      {
        "finding_type": "dependency_cve",
        "severity": "high",
        "file_path": "requirements.txt",
        "title": "Vulnerable dependency: requests 2.25.0",
        "description": "CVE-2023-xxxxx: SSL certificate validation bypass",
        "cve_id": "CVE-2023-xxxxx",
        "recommendation": "Upgrade requests to version 2.31.0 or later"
      },
      {
        "finding_type": "insecure_crypto",
        "severity": "high",
        "file_path": "src/auth.py",
        "line_number": 42,
        "title": "Use of MD5 hash function",
        "description": "MD5 is cryptographically broken and should not be used",
        "recommendation": "Use SHA-256 or bcrypt for password hashing"
      },
      {
        "finding_type": "code_pattern",
        "severity": "medium",
        "file_path": "src/payment.py",
        "line_number": 78,
        "title": "SQL query uses string formatting",
        "description": "Potential SQL injection vulnerability",
        "recommendation": "Use parameterized queries or ORM"
      }
    ]
  }
}
```

## Advanced Configuration

### Custom Security Patterns

Add custom regex patterns for organization-specific secrets:

```python
# In src/security/scanner.py
def _build_secrets_patterns(self) -> dict[str, re.Pattern]:
    patterns = {
        # ... existing patterns ...
        "Company API Key": re.compile(r"COMPANY-[A-Z0-9]{32}", re.IGNORECASE),
        "Internal Token": re.compile(r"INT-TOKEN-[0-9a-f]{40}", re.IGNORECASE),
    }
    return patterns
```

### Scanner Priorities

Modify scanner execution order in [scanner.py:59-68](src/security/scanner.py#L59-L68):

```python
def scan(self, commit_sha: Optional[str] = None) -> SecurityReport:
    report = SecurityReport(commit_sha=commit_sha)

    # Customize order and enabled scanners
    report.findings.extend(self._scan_secrets())
    report.findings.extend(self._scan_dependencies())
    report.findings.extend(self._scan_code_patterns())

    return report
```

## Contributing

To add support for new security tools:

1. Add scanner method to [SecurityScanner](src/security/scanner.py)
2. Parse tool output to `SecurityFinding` objects
3. Update this documentation
4. Add tests for the new scanner

Example:
```python
def _run_new_scanner(self) -> List[SecurityFinding]:
    """Run new security scanner."""
    try:
        result = subprocess.run(
            ["new-scanner", "scan", str(self.repo_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return self._parse_new_scanner_output(result.stdout)
    except Exception as exc:
        logger.warning(f"New scanner failed: {exc}")
        return []
```

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [gitleaks Documentation](https://github.com/gitleaks/gitleaks)
- [semgrep Rules](https://semgrep.dev/r)
- [bandit Documentation](https://bandit.readthedocs.io/)
- [CVE Database](https://cve.mitre.org/)

## Support

For issues related to security scanning:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review scanner logs for errors
3. Verify tool installation and versions
4. Open an issue with scanner output and error messages
