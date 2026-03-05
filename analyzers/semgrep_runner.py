import json
import subprocess
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.models import Finding, FindingSource, Severity

SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def run_semgrep(
    target_dir: str | Path,
    rules_dir: str | Path = "rules/semgrep",
    scope_contracts: list[str] | None = None,
) -> list[Finding]:
    """Run Semgrep with custom Solidity rules."""
    target_dir = Path(target_dir)
    rules_dir = Path(rules_dir)

    if not rules_dir.exists() or not any(rules_dir.glob("*.yaml")):
        return []

    cmd = [
        "semgrep",
        "--config",
        str(rules_dir),
        "--json",
        str(target_dir),
        "--exclude", "node_modules",
        "--exclude", "lib",
        "--exclude", "test",
        "--exclude", "tests",
        "--exclude", "script",
        "--exclude", "scripts",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    if result.returncode not in (0, 1):  # 1 = findings found
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings = parse_semgrep_json(data)

    # Filter to scope if specified
    if scope_contracts:
        scope_lower = {s.lower() for s in scope_contracts}
        findings = [
            f for f in findings
            if any(s in f.file_path.lower() or s in f.contract.lower() for s in scope_lower)
        ]

    return findings


def parse_semgrep_json(data: dict) -> list[Finding]:
    """Parse Semgrep JSON output into Finding objects."""
    findings = []
    results = data.get("results", [])

    for i, res in enumerate(results):
        rule_id = res.get("check_id", "unknown")
        severity_str = res.get("extra", {}).get("severity", "INFO")
        message = res.get("extra", {}).get("message", "")
        metadata = res.get("extra", {}).get("metadata", {})

        path = res.get("path", "")
        start_line = res.get("start", {}).get("line")
        end_line = res.get("end", {}).get("line")

        # Extract code from the matched lines
        code = res.get("extra", {}).get("lines", "")

        category = metadata.get(
            "category", rule_id.split(".")[0] if "." in rule_id else "other"
        )
        confidence_str = metadata.get("confidence", "medium")
        confidence = {"high": 0.9, "medium": 0.6, "low": 0.3}.get(
            confidence_str.lower(), 0.5
        )

        # Try to extract contract name from path
        contract = Path(path).stem if path else ""

        finding = Finding(
            id=f"SGRP-{i:04d}-{rule_id.split('.')[-1] if '.' in rule_id else rule_id}",
            source=FindingSource.SEMGREP,
            detector=rule_id,
            severity=SEMGREP_SEVERITY_MAP.get(severity_str, Severity.LOW),
            confidence=confidence,
            title=f"[{rule_id}] {message[:100]}",
            description=message,
            contract=contract,
            function=None,
            file_path=path,
            line_start=start_line,
            line_end=end_line,
            code_snippet=code,
            category=category,
            raw_output=res,
        )
        findings.append(finding)

    return findings
