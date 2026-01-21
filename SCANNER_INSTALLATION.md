# Security Scanner Installation Guide

This guide covers how to install all the security scanners used by the CodeReview application.

## Table of Contents
1. [Secret Scanners](#secret-scanners)
2. [Dependency Scanners](#dependency-scanners)
3. [Code Pattern Scanners (SAST)](#code-pattern-scanners-sast)
4. [Quick Install Script](#quick-install-script)

---

## Secret Scanners

### 1. Gitleaks (Primary Secret Scanner)
**Purpose**: Detect hardcoded secrets, API keys, tokens, credentials

**Installation**:

**Windows (Chocolatey)**:
```powershell
choco install gitleaks
```

**Windows (Manual)**:
```powershell
# Download from GitHub releases
# https://github.com/gitleaks/gitleaks/releases
# Extract and add to PATH
```

**Verify**:
```powershell
gitleaks version
```

### 2. detect-secrets (Fallback)
**Purpose**: Backup secret detection if gitleaks unavailable

**Installation**:
```powershell
pip install detect-secrets
```

**Verify**:
```powershell
detect-secrets --version
```

---

## Dependency Scanners

### 3. pip-audit (Python Dependencies)
**Purpose**: Scan Python dependencies for known CVEs

**Installation**:
```powershell
pip install pip-audit
```

**Verify**:
```powershell
pip-audit --version
```

### 4. Safety (Python Dependencies - Alternative)
**Purpose**: Backup Python dependency scanner

**Installation**:
```powershell
pip install safety
```

**Verify**:
```powershell
safety --version
```

### 5. npm audit (JavaScript/Node.js Dependencies)
**Purpose**: Scan npm packages for vulnerabilities

**Installation**:
npm audit comes built-in with npm. Just ensure you have Node.js installed:

```powershell
# Download and install Node.js from https://nodejs.org/
node --version
npm --version
```

**Verify**:
```powershell
npm audit --help
```

---

## Code Pattern Scanners (SAST)

### 6. Semgrep (Multi-Language SAST)
**Purpose**: Static analysis for security patterns across all languages

**Installation**:
```powershell
pip install semgrep
```

**Verify**:
```powershell
semgrep --version
```

### 7. Bandit (Python SAST)
**Purpose**: Python-specific security issue detection

**Installation**:
```powershell
pip install bandit
```

**Verify**:
```powershell
bandit --version
```

### 8. Pylint with Security Plugin (Python)
**Purpose**: Enhanced Python security linting

**Installation**:
```powershell
pip install pylint pylint-secure-coding-standard
```

**Verify**:
```powershell
pylint --version
```

### 9. ESLint with Security Plugin (JavaScript/Node.js)
**Purpose**: JavaScript security linting

**Installation**:
```powershell
npm install -g eslint eslint-plugin-security
```

**Verify**:
```powershell
eslint --version
```

### 10. NodeJsScan (Node.js SAST)
**Purpose**: Node.js specific security scanning

**Installation**:
```powershell
pip install nodejsscan
```

**Verify**:
```powershell
nodejsscan --version
```

### 11. Gosec (Go SAST)
**Purpose**: Go language security scanner

**Installation**:

**Windows (Using Go)**:
```powershell
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

**Or download binary**:
```powershell
# Download from https://github.com/securego/gosec/releases
# Extract and add to PATH
```

**Verify**:
```powershell
gosec -version
```

### 12. Brakeman (Ruby/Rails SAST)
**Purpose**: Ruby on Rails security scanner

**Installation**:
```powershell
gem install brakeman
```

**Verify**:
```powershell
brakeman --version
```

### 13. SpotBugs (Java SAST)
**Purpose**: Java security and bug detection

**Installation**:

Requires Java JDK installed first.

```powershell
# Download SpotBugs from https://spotbugs.github.io/
# Extract and add to PATH
# Or use Maven/Gradle plugin
```

**Verify**:
```powershell
spotbugs -version
```

### 14. Security Code Scan (C# SAST)
**Purpose**: .NET/C# security scanner

**Installation**:

Security Code Scan is typically used as a NuGet package or Roslyn analyzer in Visual Studio projects.

```powershell
# Install as NuGet package in .NET projects
dotnet add package SecurityCodeScan.VS2019
```

**Alternative - Use Roslyn Security Guard**:
```powershell
dotnet tool install --global security-scan
```

### 15. PHPCS with Security Standard (PHP SAST)
**Purpose**: PHP security scanning

**Installation**:

**Using Composer**:
```powershell
composer global require squizlabs/php_codesniffer
composer global require pheromone/phpcs-security-audit
```

**Add to PATH**:
```powershell
# Add composer global bin to PATH
# Usually: C:\Users\YourUser\AppData\Roaming\Composer\vendor\bin
```

**Verify**:
```powershell
phpcs --version
```

### 16. Snyk Code (Optional - Requires Account)
**Purpose**: Commercial SAST tool with free tier

**Installation**:
```powershell
npm install -g snyk
snyk auth  # Requires Snyk account
```

**Verify**:
```powershell
snyk --version
```

### 17. Trivy (Container & Dependency Scanner)
**Purpose**: Comprehensive vulnerability scanner

**Installation**:

**Windows (Chocolatey)**:
```powershell
choco install trivy
```

**Windows (Manual)**:
```powershell
# Download from https://github.com/aquasecurity/trivy/releases
# Extract and add to PATH
```

**Verify**:
```powershell
trivy --version
```

---

## Quick Install Script

Here's a PowerShell script to install the most essential scanners:

```powershell
# Essential Python-based scanners
pip install semgrep bandit pip-audit safety detect-secrets nodejsscan pylint

# Essential Node.js-based scanners (if Node.js is installed)
npm install -g eslint eslint-plugin-security

# Gitleaks (download manually or use chocolatey)
# choco install gitleaks

# Trivy (download manually or use chocolatey)
# choco install trivy

Write-Host "Core scanners installed!" -ForegroundColor Green
Write-Host "Optional: Install gitleaks, trivy, gosec, brakeman, spotbugs, phpcs manually" -ForegroundColor Yellow
```

---

## Minimum Required Scanners

For basic functionality, at minimum install:

1. **Semgrep** - Multi-language SAST (covers most languages)
2. **Bandit** - Python security
3. **Gitleaks** - Secret detection
4. **pip-audit** - Python dependencies
5. **npm audit** - Node.js dependencies (comes with npm)

```powershell
pip install semgrep bandit pip-audit
choco install gitleaks
```

---

## Scanner Priority

The CodeReview app tries scanners in order and falls back if unavailable:

**Secrets**: Gitleaks → detect-secrets → regex patterns
**Python Dependencies**: pip-audit → Safety
**Code Patterns**: Semgrep + Bandit + language-specific tools

Most scanners are **optional** - the app will skip unavailable scanners gracefully.

---

## Testing Scanner Installation

After installation, test with the TestRepo:

```powershell
cd c:\Users\Omars\Repos\TestRepo

# Test Bandit
bandit -r . -f json

# Test Semgrep
semgrep --config=auto --json .

# Test Gitleaks
gitleaks detect --no-git -v

# Test pip-audit
pip-audit -r requirements.txt

# Test npm audit
npm audit
```

---

## Troubleshooting

### Scanner Not Found
- Ensure the scanner is in your PATH
- Restart your terminal after installation
- Check installation with `scanner-name --version`

### Permission Errors
- Run PowerShell as Administrator for global installations
- Use `pip install --user` if needed

### Python Scanners Conflict
- Use the CodeReview virtual environment:
  ```powershell
  cd c:\Users\Omars\Repos\CodeReview
  .\.venv\Scripts\Activate.ps1
  pip install semgrep bandit pip-audit safety detect-secrets nodejsscan
  ```

### Node.js Scanners
- Ensure Node.js is installed: https://nodejs.org/
- Use `npm install -g` for global installation
- May need to restart terminal after Node.js installation

---

## Notes

- **CodeReview gracefully handles missing scanners** - it will skip unavailable tools
- Not all scanners are required - install based on languages you're scanning
- Some scanners (Snyk, GitHub Advanced Security) require accounts
- Commercial tools may have rate limits or require licenses
- Keep scanners updated: `pip install --upgrade semgrep bandit pip-audit`

---

## Summary: Recommended Installation

For a Windows environment scanning Python, JavaScript, and general code:

```powershell
# Install Python scanners in CodeReview venv
cd c:\Users\Omars\Repos\CodeReview
.\.venv\Scripts\Activate.ps1
pip install semgrep bandit pip-audit safety detect-secrets nodejsscan pylint

# Install Node.js scanners globally
npm install -g eslint eslint-plugin-security

# Install binary tools via Chocolatey (run as Admin)
choco install gitleaks trivy

# Verify installations
semgrep --version
bandit --version
gitleaks version
pip-audit --version
npm audit --help
```

This gives you comprehensive coverage for Python, JavaScript, secrets, and dependencies!
