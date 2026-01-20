from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass(slots=True)
class SecurityFinding:
    tool: str
    severity: str  # "info" | "warn" | "critical"
    file: Optional[str]
    message: str
    rule_id: Optional[str] = None
    extra: Optional[dict] = None


@dataclass(slots=True)
class SecuritySection:
    status: str  # "clean" | "found" | "error"
    count: int
    findings: List[SecurityFinding]
    error: Optional[str] = None


@dataclass(slots=True)
class SecurityScanResult:
    overall_risk: str  # "clean" | "low" | "medium" | "high" | "critical"
    summary: str       # deterministic summary (not AI)
    secrets: SecuritySection
    dependencies: SecuritySection
    static_analysis: SecuritySection


# -------------------------
# helpers
# -------------------------
def _run(cmd: list[str], cwd: Path, timeout: int = 180) -> Tuple[int, str, str]:
    p = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr


def _dedupe(findings: List[SecurityFinding]) -> List[SecurityFinding]:
    seen = set()
    out: List[SecurityFinding] = []
    for f in findings:
        key = (f.tool, f.rule_id, f.file, f.message)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _sort(findings: List[SecurityFinding]) -> List[SecurityFinding]:
    rank = {"critical": 0, "warn": 1, "info": 2}
    return sorted(findings, key=lambda x: (rank.get(x.severity, 9), x.tool, x.file or "", x.rule_id or "", x.message))


def _pick_targets(repo_dir: Path) -> list[str]:
    targets: list[str] = []
    for d in ("src", "app", "backend", "server"):
        if (repo_dir / d).exists():
            targets.append(d)
    if not targets:
        targets = ["."]
    return targets


# -------------------------
# gitleaks
# -------------------------
def _scan_gitleaks(repo_dir: Path) -> SecuritySection:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        report_path = Path(f.name)

    rc, _out, err = _run(
        [
            "gitleaks",
            "detect",
            "--no-git",
            "--source",
            ".",
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
        ],
        cwd=repo_dir,
        timeout=180,
    )

    # gitleaks: 0 = no leaks, 1 = leaks found, other = error
    if rc not in (0, 1):
        msg = (err or "").strip() or "gitleaks failed"
        return SecuritySection(status="error", count=0, findings=[], error=msg)

    if not report_path.exists() or report_path.stat().st_size == 0:
        return SecuritySection(status="clean", count=0, findings=[])

    try:
        raw = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return SecuritySection(status="error", count=0, findings=[], error="gitleaks output not parseable")

    if not isinstance(raw, list):
        # gitleaks json is typically a list
        return SecuritySection(status="error", count=0, findings=[], error="gitleaks output format unexpected")

    findings: List[SecurityFinding] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        findings.append(
            SecurityFinding(
                tool="gitleaks",
                severity="critical",
                file=item.get("File") or item.get("file"),
                message=item.get("Description") or item.get("description") or "Potential secret detected",
                rule_id=item.get("RuleID") or item.get("rule_id"),
                extra={
                    "start_line": item.get("StartLine"),
                    "end_line": item.get("EndLine"),
                    "commit": item.get("Commit"),
                },
            )
        )

    findings = _dedupe(findings)
    findings = _sort(findings)

    return SecuritySection(status=("found" if findings else "clean"), count=len(findings), findings=findings)


# -------------------------
# pip-audit
# -------------------------
def _scan_pip_audit(repo_dir: Path) -> SecuritySection:
    # pip-audit looks at installed env / project metadata; it may return non-zero when vulns exist.
    rc, out, err = _run(["python", "-m", "pip_audit", "-f", "json"], cwd=repo_dir, timeout=180)

    if not out.strip() and rc != 0:
        msg = (err or "").strip() or "pip-audit failed"
        return SecuritySection(status="error", count=0, findings=[], error=msg)

    if not out.strip():
        return SecuritySection(status="clean", count=0, findings=[])

    try:
        raw = json.loads(out)
    except Exception:
        return SecuritySection(status="error", count=0, findings=[], error="pip-audit output not parseable")

    if not isinstance(raw, list):
        return SecuritySection(status="error", count=0, findings=[], error="pip-audit output format unexpected")

    findings: List[SecurityFinding] = []
    for dep in raw:
        if not isinstance(dep, dict):
            continue
        name = dep.get("name")
        version = dep.get("version")
        vulns = dep.get("vulns") if isinstance(dep.get("vulns"), list) else []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            vid = v.get("id")
            desc = (v.get("description") or "").strip()
            msg = f"{name} {version} – {vid}"
            if desc:
                msg += f": {desc}"
            findings.append(
                SecurityFinding(
                    tool="pip-audit",
                    severity="critical",
                    file=None,
                    message=msg.strip(),
                    rule_id=vid,
                    extra={"fix_versions": v.get("fix_versions"), "aliases": v.get("aliases")},
                )
            )

    findings = _dedupe(findings)
    findings = _sort(findings)

    return SecuritySection(status=("found" if findings else "clean"), count=len(findings), findings=findings)


# -------------------------
# bandit
# -------------------------
def _scan_bandit(repo_dir: Path) -> SecuritySection:
    targets = _pick_targets(repo_dir)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        report_path = Path(f.name)

    rc, _out, err = _run(
        ["bandit", "-q", "-r", *targets, "-f", "json", "-o", str(report_path)],
        cwd=repo_dir,
        timeout=180,
    )

    if not report_path.exists() or report_path.stat().st_size == 0:
        msg = (err or "").strip() or "bandit produced no output"
        # bandit returns nonzero when it finds issues, so we can't treat rc alone as error.
        return SecuritySection(status="error", count=0, findings=[], error=msg)

    try:
        raw = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return SecuritySection(status="error", count=0, findings=[], error="bandit output not parseable")

    if not isinstance(raw, dict):
        return SecuritySection(status="error", count=0, findings=[], error="bandit output format unexpected")

    results = raw.get("results", [])
    if not isinstance(results, list):
        return SecuritySection(status="error", count=0, findings=[], error="bandit results missing/invalid")

    findings: List[SecurityFinding] = []
    for item in results:
        if not isinstance(item, dict):
            continue

        issue_sev = (item.get("issue_severity") or "LOW").upper()
        test_id = item.get("test_id")

        # Map Bandit severity to your product severity
        # HIGH => critical, MEDIUM/LOW => warn (you can tune later)
        severity = "critical" if issue_sev == "HIGH" else "warn"

        findings.append(
            SecurityFinding(
                tool="bandit",
                severity=severity,
                file=item.get("filename"),
                message=item.get("issue_text") or "Bandit issue",
                rule_id=test_id,
                extra={
                    "line": item.get("line_number"),
                    "confidence": item.get("issue_confidence"),
                    "more_info": item.get("more_info"),
                },
            )
        )

    findings = _dedupe(findings)
    findings = _sort(findings)

    return SecuritySection(status=("found" if findings else "clean"), count=len(findings), findings=findings)


# -------------------------
# overall + public entry
# -------------------------
def _compute_overall_risk(secrets: SecuritySection, deps: SecuritySection, bandit: SecuritySection) -> str:
    # deterministic “final product” verdict
    if secrets.status == "found" and secrets.count > 0:
        return "critical"
    if deps.status == "found" and deps.count > 0:
        return "high"
    if bandit.status == "found":
        # any "critical" bandit => medium, otherwise low
        if any(f.severity == "critical" for f in bandit.findings):
            return "medium"
        if bandit.count > 0:
            return "low"
    if secrets.status == "error" or deps.status == "error" or bandit.status == "error":
        # if scanning fails, don’t lie: treat as medium so users pay attention
        return "medium"
    return "clean"


def _deterministic_summary(secrets: SecuritySection, deps: SecuritySection, bandit: SecuritySection, overall: str) -> str:
    parts = [
        f"Overall risk: {overall}.",
        f"Secrets: {secrets.status} ({secrets.count}).",
        f"Dependencies: {deps.status} ({deps.count}).",
        f"Static analysis: {bandit.status} ({bandit.count}).",
    ]
    if secrets.status == "error":
        parts.append(f"Gitleaks error: {secrets.error}")
    if deps.status == "error":
        parts.append(f"pip-audit error: {deps.error}")
    if bandit.status == "error":
        parts.append(f"Bandit error: {bandit.error}")
    return " ".join([p for p in parts if p])


def scan_repo(repo_dir: Path) -> SecurityScanResult:
    secrets = _scan_gitleaks(repo_dir)
    deps = _scan_pip_audit(repo_dir)
    bandit = _scan_bandit(repo_dir)

    overall = _compute_overall_risk(secrets, deps, bandit)
    summary = _deterministic_summary(secrets, deps, bandit, overall)

    return SecurityScanResult(
        overall_risk=overall,
        summary=summary,
        secrets=secrets,
        dependencies=deps,
        static_analysis=bandit,
    )
