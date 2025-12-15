from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import List, Optional

from src.security.models import (
    SecurityFinding,
    SecurityReport,
    FindingType,
    FindingSeverity,
)

logger = logging.getLogger(__name__)


class SecurityScanner:
    """
    Hybrid security scanner that combines deterministic tools with structured output.

    Scans for:
    1. Secrets (API keys, tokens, credentials)
    2. Dependency vulnerabilities (CVEs)
    3. Code security patterns (SAST)
    """

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = repo_path
        self._secrets_patterns = self._build_secrets_patterns()

    def scan(self, commit_sha: Optional[str] = None, changed_files: Optional[List[str]] = None) -> SecurityReport:
        """
        Run all security scans on the repository.

        Args:
            commit_sha: Optional commit SHA to associate with findings
            changed_files: Optional list of file paths to scope the scan to.
                          If provided, only scan these files for secrets/SAST.
                          Dependencies are always scanned at repo level.

        Returns:
            SecurityReport with all findings
        """
        report = SecurityReport(commit_sha=commit_sha)

        # Run all scanners (scoped to changed files if provided)
        report.findings.extend(self._scan_secrets(changed_files=changed_files))
        report.findings.extend(self._scan_code_patterns(changed_files=changed_files))

        # Dependencies are scanned at repo level only if dependency files changed
        # or if we're doing a full repo scan (changed_files is None)
        dependency_files = {'requirements.txt', 'pyproject.toml', 'setup.py', 'package.json', 'package-lock.json', 'yarn.lock'}
        should_scan_deps = (
            changed_files is None or  # Full repo scan
            any(Path(f).name in dependency_files for f in changed_files)  # Dependency file changed
        )

        if should_scan_deps:
            report.findings.extend(self._scan_dependencies())

        return report

    def _scan_secrets(self, changed_files: Optional[List[str]] = None) -> List[SecurityFinding]:
        """
        Scan for secrets using multiple approaches.
        Priority: gitleaks > detect-secrets > regex fallback

        Args:
            changed_files: Optional list of file paths to scope the scan to.
                          If None, scan entire repository.
        """
        findings: List[SecurityFinding] = []

        # Try gitleaks first (most comprehensive)
        gitleaks_findings = self._run_gitleaks(changed_files=changed_files)
        if gitleaks_findings:
            return gitleaks_findings

        # Fallback to detect-secrets
        detect_secrets_findings = self._run_detect_secrets(changed_files=changed_files)
        if detect_secrets_findings:
            return detect_secrets_findings

        # Final fallback: regex-based detection
        logger.info("Using regex-based secrets detection as fallback")
        findings.extend(self._scan_secrets_regex(changed_files=changed_files))

        return findings

    def _run_gitleaks(self, changed_files: Optional[List[str]] = None) -> List[SecurityFinding]:
        """Run gitleaks if available."""
        # Gitleaks doesn't support per-file scanning easily, skip if scoped scan requested
        if changed_files is not None:
            logger.debug("Skipping gitleaks for scoped scan (not supported)")
            return []

        try:
            result = subprocess.run(
                ["gitleaks", "detect", "--source", str(self.repo_path), "--report-format", "json", "--no-git"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            # gitleaks returns exit code 1 when it finds secrets
            if result.returncode == 0:
                logger.debug("Gitleaks: no secrets found")
                return []

            if result.returncode == 1 and result.stdout:
                # Parse gitleaks JSON output
                try:
                    gitleaks_data = json.loads(result.stdout)
                    return self._parse_gitleaks_output(gitleaks_data)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse gitleaks JSON output")
                    return []

            logger.debug(f"Gitleaks exited with code {result.returncode}")
            return []

        except FileNotFoundError:
            logger.debug("gitleaks not found, trying alternatives")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("gitleaks timed out")
            return []
        except Exception as exc:
            logger.warning(f"gitleaks scan failed: {exc}")
            return []

    def _parse_gitleaks_output(self, data: List[dict]) -> List[SecurityFinding]:
        """Parse gitleaks JSON output into SecurityFinding objects."""
        findings = []

        for item in data:
            finding = SecurityFinding(
                finding_type=FindingType.SECRET,
                severity=FindingSeverity.CRITICAL,
                file_path=item.get("File", "unknown"),
                line_number=item.get("StartLine"),
                title=f"Secret detected: {item.get('RuleID', 'Unknown')}",
                description=item.get("Description", "Potential secret or credential found"),
                recommendation="Remove the secret and rotate credentials immediately. Use environment variables or secret management systems.",
                raw_data=item,
            )
            findings.append(finding)

        return findings

    def _run_detect_secrets(self, changed_files: Optional[List[str]] = None) -> List[SecurityFinding]:
        """Run detect-secrets if available."""
        # detect-secrets doesn't support per-file scanning easily, skip if scoped scan requested
        if changed_files is not None:
            logger.debug("Skipping detect-secrets for scoped scan (not supported)")
            return []

        try:
            result = subprocess.run(
                ["detect-secrets", "scan", "--all-files", str(self.repo_path)],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(self.repo_path),
            )

            if result.returncode == 0 and result.stdout:
                try:
                    secrets_data = json.loads(result.stdout)
                    return self._parse_detect_secrets_output(secrets_data)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse detect-secrets JSON output")
                    return []

            return []

        except FileNotFoundError:
            logger.debug("detect-secrets not found")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("detect-secrets timed out")
            return []
        except Exception as exc:
            logger.warning(f"detect-secrets scan failed: {exc}")
            return []

    def _parse_detect_secrets_output(self, data: dict) -> List[SecurityFinding]:
        """Parse detect-secrets JSON output into SecurityFinding objects."""
        findings = []

        results = data.get("results", {})
        for file_path, secrets in results.items():
            for secret in secrets:
                finding = SecurityFinding(
                    finding_type=FindingType.SECRET,
                    severity=FindingSeverity.CRITICAL,
                    file_path=file_path,
                    line_number=secret.get("line_number"),
                    title=f"Secret detected: {secret.get('type', 'Unknown')}",
                    description="Potential secret or credential found",
                    recommendation="Remove the secret and rotate credentials immediately.",
                    raw_data=secret,
                )
                findings.append(finding)

        return findings

    def _scan_secrets_regex(self, changed_files: Optional[List[str]] = None) -> List[SecurityFinding]:
        """Fallback: regex-based secret scanning."""
        findings = []

        # Determine which files to scan
        if changed_files is not None:
            # Scan only changed files
            files_to_scan = [self.repo_path / f for f in changed_files if (self.repo_path / f).exists()]
        else:
            # Scan all files
            files_to_scan = list(self.repo_path.rglob("*"))

        for file_path in files_to_scan:
            if not file_path.is_file():
                continue

            # Skip binary files and large files
            if file_path.suffix in [".pyc", ".exe", ".dll", ".so", ".dylib", ".zip", ".tar", ".gz"]:
                continue

            try:
                # Skip files larger than 1MB
                if file_path.stat().st_size > 1_000_000:
                    continue

                content = file_path.read_text(encoding="utf-8", errors="ignore")
                findings.extend(self._scan_file_for_secrets(file_path, content))

            except Exception as exc:
                logger.debug(f"Could not scan {file_path}: {exc}")
                continue

        return findings

    def _scan_file_for_secrets(self, file_path: Path, content: str) -> List[SecurityFinding]:
        """Scan a single file for secrets using regex patterns."""
        findings = []

        for line_num, line in enumerate(content.split("\n"), start=1):
            for pattern_name, pattern in self._secrets_patterns.items():
                if pattern.search(line):
                    finding = SecurityFinding(
                        finding_type=FindingType.SECRET,
                        severity=FindingSeverity.HIGH,
                        file_path=str(file_path.relative_to(self.repo_path)),
                        line_number=line_num,
                        title=f"Potential {pattern_name} detected",
                        description=f"Line contains pattern matching {pattern_name}",
                        recommendation="Verify if this is a real secret. If so, remove and rotate immediately.",
                    )
                    findings.append(finding)

        return findings

    def _build_secrets_patterns(self) -> dict[str, re.Pattern]:
        """Build regex patterns for common secrets."""
        return {
            "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
            "AWS Secret Key": re.compile(r"aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", re.IGNORECASE),
            "GitHub Token": re.compile(r"gh[pousr]_[0-9a-zA-Z]{36,}", re.IGNORECASE),
            "OpenAI API Key": re.compile(r"sk-[a-zA-Z0-9]{48}", re.IGNORECASE),
            "Generic API Key": re.compile(r"api[_-]?key['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z]{32,}['\"]?", re.IGNORECASE),
            "Private Key": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY", re.IGNORECASE),
            "Generic Secret": re.compile(r"secret['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z]{16,}['\"]?", re.IGNORECASE),
            "Password": re.compile(r"password['\"]?\s*[:=]\s*['\"]?.{8,}['\"]?", re.IGNORECASE),
        }

    def _scan_dependencies(self) -> List[SecurityFinding]:
        """
        Scan dependencies for known vulnerabilities.
        Supports Python (pip-audit, safety) and JavaScript (npm audit).
        """
        findings: List[SecurityFinding] = []

        # Python dependencies
        findings.extend(self._scan_python_dependencies())

        # JavaScript dependencies
        findings.extend(self._scan_javascript_dependencies())

        return findings

    def _scan_python_dependencies(self) -> List[SecurityFinding]:
        """Scan Python dependencies using pip-audit or safety."""
        findings = []

        # Check for requirements files
        requirements_files = [
            self.repo_path / "requirements.txt",
            self.repo_path / "pyproject.toml",
            self.repo_path / "setup.py",
        ]

        has_python_deps = any(f.exists() for f in requirements_files)
        if not has_python_deps:
            return findings

        # Try pip-audit first
        pip_audit_findings = self._run_pip_audit()
        if pip_audit_findings:
            return pip_audit_findings

        # Fallback to safety
        safety_findings = self._run_safety()
        if safety_findings:
            return safety_findings

        return findings

    def _run_pip_audit(self) -> List[SecurityFinding]:
        """Run pip-audit for Python dependency vulnerabilities."""
        try:
            result = subprocess.run(
                ["pip-audit", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(self.repo_path),
            )

            if result.stdout:
                try:
                    audit_data = json.loads(result.stdout)
                    return self._parse_pip_audit_output(audit_data)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse pip-audit JSON output")
                    return []

            return []

        except FileNotFoundError:
            logger.debug("pip-audit not found")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("pip-audit timed out")
            return []
        except Exception as exc:
            logger.warning(f"pip-audit scan failed: {exc}")
            return []

    def _parse_pip_audit_output(self, data: dict) -> List[SecurityFinding]:
        """Parse pip-audit JSON output."""
        findings = []

        dependencies = data.get("dependencies", [])
        for dep in dependencies:
            package_name = dep.get("name", "unknown")
            version = dep.get("version", "unknown")

            for vuln in dep.get("vulns", []):
                severity = self._map_cvss_to_severity(vuln.get("fix_versions"))

                finding = SecurityFinding(
                    finding_type=FindingType.DEPENDENCY_CVE,
                    severity=severity,
                    file_path="requirements.txt",
                    title=f"Vulnerable dependency: {package_name} {version}",
                    description=vuln.get("description", "Known vulnerability in dependency"),
                    cve_id=vuln.get("id"),
                    recommendation=f"Upgrade {package_name} to a patched version: {', '.join(vuln.get('fix_versions', []))}",
                    raw_data=vuln,
                )
                findings.append(finding)

        return findings

    def _run_safety(self) -> List[SecurityFinding]:
        """Run safety for Python dependency vulnerabilities."""
        try:
            result = subprocess.run(
                ["safety", "check", "--json"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(self.repo_path),
            )

            if result.stdout:
                try:
                    safety_data = json.loads(result.stdout)
                    return self._parse_safety_output(safety_data)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse safety JSON output")
                    return []

            return []

        except FileNotFoundError:
            logger.debug("safety not found")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("safety timed out")
            return []
        except Exception as exc:
            logger.warning(f"safety scan failed: {exc}")
            return []

    def _parse_safety_output(self, data: list) -> List[SecurityFinding]:
        """Parse safety JSON output."""
        findings = []

        for vuln in data:
            package_name = vuln.get("package", "unknown")

            finding = SecurityFinding(
                finding_type=FindingType.DEPENDENCY_CVE,
                severity=FindingSeverity.HIGH,
                file_path="requirements.txt",
                title=f"Vulnerable dependency: {package_name}",
                description=vuln.get("advisory", "Known vulnerability in dependency"),
                cve_id=vuln.get("cve"),
                recommendation=f"Upgrade {package_name} to version {vuln.get('secure_version', 'latest')}",
                raw_data=vuln,
            )
            findings.append(finding)

        return findings

    def _scan_javascript_dependencies(self) -> List[SecurityFinding]:
        """Scan JavaScript dependencies using npm audit."""
        findings = []

        package_json = self.repo_path / "package.json"
        if not package_json.exists():
            return findings

        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(self.repo_path),
            )

            if result.stdout:
                try:
                    audit_data = json.loads(result.stdout)
                    return self._parse_npm_audit_output(audit_data)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse npm audit JSON output")
                    return []

        except FileNotFoundError:
            logger.debug("npm not found")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("npm audit timed out")
            return []
        except Exception as exc:
            logger.warning(f"npm audit scan failed: {exc}")
            return []

        return findings

    def _parse_npm_audit_output(self, data: dict) -> List[SecurityFinding]:
        """Parse npm audit JSON output."""
        findings = []

        vulnerabilities = data.get("vulnerabilities", {})
        for package_name, vuln_data in vulnerabilities.items():
            severity_str = vuln_data.get("severity", "medium").lower()
            severity = {
                "critical": FindingSeverity.CRITICAL,
                "high": FindingSeverity.HIGH,
                "moderate": FindingSeverity.MEDIUM,
                "low": FindingSeverity.LOW,
            }.get(severity_str, FindingSeverity.MEDIUM)

            finding = SecurityFinding(
                finding_type=FindingType.DEPENDENCY_CVE,
                severity=severity,
                file_path="package.json",
                title=f"Vulnerable dependency: {package_name}",
                description=vuln_data.get("via", [{}])[0].get("title", "Known vulnerability"),
                cve_id=vuln_data.get("via", [{}])[0].get("cve"),
                recommendation=f"Update {package_name} to a secure version",
                raw_data=vuln_data,
            )
            findings.append(finding)

        return findings

    def _scan_code_patterns(self, changed_files: Optional[List[str]] = None) -> List[SecurityFinding]:
        """
        Scan code for security anti-patterns using SAST tools.
        Supports: bandit (Python), semgrep (multi-language)

        Args:
            changed_files: Optional list of file paths to scope the scan to.
        """
        findings: List[SecurityFinding] = []

        # Try semgrep first (multi-language)
        semgrep_findings = self._run_semgrep(changed_files=changed_files)
        if semgrep_findings:
            findings.extend(semgrep_findings)

        # Run bandit for Python
        bandit_findings = self._run_bandit(changed_files=changed_files)
        if bandit_findings:
            findings.extend(bandit_findings)

        return findings

    def _run_semgrep(self, changed_files: Optional[List[str]] = None) -> List[SecurityFinding]:
        """Run semgrep with OWASP rules."""
        # Build command
        cmd = ["semgrep", "scan", "--config=auto", "--json"]

        if changed_files is not None:
            # Scan specific files
            for f in changed_files:
                cmd.append(str(self.repo_path / f))
        else:
            # Scan entire repo
            cmd.append(str(self.repo_path))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
            )

            if result.stdout:
                try:
                    semgrep_data = json.loads(result.stdout)
                    return self._parse_semgrep_output(semgrep_data)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse semgrep JSON output")
                    return []

            return []

        except FileNotFoundError:
            logger.debug("semgrep not found")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("semgrep timed out")
            return []
        except Exception as exc:
            logger.warning(f"semgrep scan failed: {exc}")
            return []

    def _parse_semgrep_output(self, data: dict) -> List[SecurityFinding]:
        """Parse semgrep JSON output."""
        findings = []

        for result in data.get("results", []):
            severity_str = result.get("extra", {}).get("severity", "WARNING").lower()
            severity = {
                "error": FindingSeverity.HIGH,
                "warning": FindingSeverity.MEDIUM,
                "info": FindingSeverity.LOW,
            }.get(severity_str, FindingSeverity.MEDIUM)

            finding_type = self._categorize_semgrep_finding(result)

            finding = SecurityFinding(
                finding_type=finding_type,
                severity=severity,
                file_path=result.get("path", "unknown"),
                line_number=result.get("start", {}).get("line"),
                title=result.get("check_id", "Security issue"),
                description=result.get("extra", {}).get("message", "Potential security issue"),
                recommendation="Review and fix the security issue identified",
                raw_data=result,
            )
            findings.append(finding)

        return findings

    def _run_bandit(self, changed_files: Optional[List[str]] = None) -> List[SecurityFinding]:
        """Run bandit for Python security issues."""
        # Determine which Python files to scan
        if changed_files is not None:
            python_files = [f for f in changed_files if f.endswith('.py')]
            if not python_files:
                return []
        else:
            # Check if there are any Python files
            python_files = list(self.repo_path.rglob("*.py"))
            if not python_files:
                return []

        # Build command
        cmd = ["bandit", "-f", "json"]

        if changed_files is not None and python_files:
            # Scan specific files
            for f in python_files:
                cmd.append(str(self.repo_path / f))
        else:
            # Scan entire repo
            cmd.extend(["-r", str(self.repo_path)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.stdout:
                try:
                    bandit_data = json.loads(result.stdout)
                    return self._parse_bandit_output(bandit_data)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse bandit JSON output")
                    return []

            return []

        except FileNotFoundError:
            logger.debug("bandit not found")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("bandit timed out")
            return []
        except Exception as exc:
            logger.warning(f"bandit scan failed: {exc}")
            return []

    def _parse_bandit_output(self, data: dict) -> List[SecurityFinding]:
        """Parse bandit JSON output."""
        findings = []

        for result in data.get("results", []):
            severity_str = result.get("issue_severity", "MEDIUM").lower()
            severity = {
                "high": FindingSeverity.HIGH,
                "medium": FindingSeverity.MEDIUM,
                "low": FindingSeverity.LOW,
            }.get(severity_str, FindingSeverity.MEDIUM)

            finding_type = self._categorize_bandit_finding(result)

            finding = SecurityFinding(
                finding_type=finding_type,
                severity=severity,
                file_path=result.get("filename", "unknown"),
                line_number=result.get("line_number"),
                title=f"{result.get('test_id', 'Unknown')}: {result.get('test_name', 'Security issue')}",
                description=result.get("issue_text", "Potential security issue"),
                recommendation="Review the code and apply security best practices",
                raw_data=result,
            )
            findings.append(finding)

        return findings

    def _categorize_semgrep_finding(self, result: dict) -> FindingType:
        """Categorize semgrep finding based on rule ID."""
        check_id = result.get("check_id", "").lower()

        if "sql" in check_id or "injection" in check_id:
            return FindingType.INJECTION
        elif "crypto" in check_id or "hash" in check_id:
            return FindingType.INSECURE_CRYPTO
        elif "auth" in check_id or "jwt" in check_id:
            return FindingType.AUTH_ISSUE
        else:
            return FindingType.CODE_PATTERN

    def _categorize_bandit_finding(self, result: dict) -> FindingType:
        """Categorize bandit finding based on test ID."""
        test_id = result.get("test_id", "").lower()

        if "sql" in test_id or "injection" in test_id:
            return FindingType.INJECTION
        elif "crypto" in test_id or "hash" in test_id or "random" in test_id:
            return FindingType.INSECURE_CRYPTO
        else:
            return FindingType.CODE_PATTERN

    def _map_cvss_to_severity(self, fix_versions: Optional[list]) -> FindingSeverity:
        """Map CVSS score or fix availability to severity."""
        # If no fix versions available, it's more critical
        if not fix_versions:
            return FindingSeverity.HIGH
        return FindingSeverity.MEDIUM
