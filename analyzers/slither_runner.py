import json
import os
import subprocess
import tempfile
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.models import Finding, FindingSource, Severity


def _get_env_with_foundry() -> dict[str, str]:
    """Return environment with Foundry bin dir in PATH."""
    env = os.environ.copy()
    foundry_bin = Path.home() / ".foundry" / "bin"
    if foundry_bin.exists():
        env["PATH"] = f"{foundry_bin}:{env.get('PATH', '')}"
    return env


SLITHER_SEVERITY_MAP = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Optimization": Severity.INFO,
}

SLITHER_CONFIDENCE_MAP = {
    "High": 0.9,
    "Medium": 0.6,
    "Low": 0.3,
}

DETECTOR_CATEGORY_MAP = {
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",
    "unprotected-upgrade": "access-control",
    "suicidal": "access-control",
    "arbitrary-send-eth": "access-control",
    "arbitrary-send-erc20": "access-control",
    "controlled-delegatecall": "access-control",
    "unchecked-lowlevel": "unchecked-calls",
    "unchecked-send": "unchecked-calls",
    "unchecked-transfer": "unchecked-calls",
    "oracle-price-manipulation": "oracle-manipulation",
    "divide-before-multiply": "integer-overflow",
    "storage-array": "storage-collision",
    "delegatecall-loop": "storage-collision",
    "uninitialized-storage": "storage-collision",
}


def _is_foundry_project(target_dir: Path) -> bool:
    """Check if target uses Foundry (foundry.toml present)."""
    return (target_dir / "foundry.toml").exists()


def _ensure_foundry_deps(target_dir: Path) -> None:
    """Install Foundry dependencies if needed."""
    env = _get_env_with_foundry()
    if not (target_dir / "lib").exists() or not any((target_dir / "lib").iterdir()):
        subprocess.run(
            ["forge", "install", "--no-commit"],
            cwd=target_dir,
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
    # Build to ensure compilation works
    subprocess.run(
        ["forge", "build"],
        cwd=target_dir,
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )


def run_slither(
    target_dir: str | Path,
    filter_paths: list[str] | None = None,
    solc_version: str | None = None,
    scope_contracts: list[str] | None = None,
) -> list[Finding]:
    """Run Slither on a target directory and return findings."""
    target_dir = Path(target_dir).resolve()

    # For Foundry projects, ensure deps are installed
    if _is_foundry_project(target_dir):
        _ensure_foundry_deps(target_dir)

    json_output = tempfile.mktemp(suffix=".json")

    cmd = ["slither", str(target_dir), "--json", json_output]

    if filter_paths:
        for fp in filter_paths:
            cmd.extend(["--filter-paths", fp])

    # Auto-filter common library paths
    for lib_path in ["node_modules", "lib/forge-std", "lib/openzeppelin"]:
        cmd.extend(["--filter-paths", lib_path])

    if solc_version:
        cmd.extend(["--solc-solcs-select", solc_version])

    # Slither returns nonzero when it finds issues - that's expected
    env = _get_env_with_foundry()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)

    # Check if JSON was written
    json_path = Path(json_output)
    if not json_path.exists() or json_path.stat().st_size == 0:
        # Slither crashed before writing JSON — surface the error
        stderr = result.stderr.strip() if result.stderr else "unknown error"
        raise RuntimeError(f"Slither produced no output. stderr: {stderr[:500]}")

    findings = parse_slither_json(json_output)

    # Filter to scope if specified
    if scope_contracts:
        findings = _filter_to_scope(findings, scope_contracts)

    return findings


def _filter_to_scope(findings: list[Finding], scope_contracts: list[str]) -> list[Finding]:
    """Filter findings to only include in-scope contracts."""
    scope_lower = {s.lower() for s in scope_contracts}
    return [
        f for f in findings
        if any(
            s in f.file_path.lower() or s in f.contract.lower()
            for s in scope_lower
        )
    ]


def parse_slither_json(json_path: str | Path) -> list[Finding]:
    """Parse Slither JSON output into Finding objects."""
    json_path = Path(json_path)
    if not json_path.exists():
        return []

    with open(json_path) as f:
        data = json.load(f)

    findings = []
    detectors = data.get("results", {}).get("detectors", [])

    for i, det in enumerate(detectors):
        check = det.get("check", "unknown")
        impact = det.get("impact", "Informational")
        confidence = det.get("confidence", "Low")
        description = det.get("description", "")

        # Extract first element info
        elements = det.get("elements", [])
        contract = ""
        function = None
        file_path = ""
        line_start = None
        code_snippet = ""

        for elem in elements:
            if elem.get("type") == "contract" and not contract:
                contract = elem.get("name", "")
            if elem.get("type") == "function" and not function:
                function = elem.get("name", "")
            source = elem.get("source_mapping", {})
            if source and not file_path:
                file_path = source.get(
                    "filename_relative", source.get("filename_absolute", "")
                )
                lines = source.get("lines", [])
                if lines:
                    line_start = lines[0]
            if not code_snippet:
                code_snippet = elem.get("source_mapping", {}).get("content", "")

        category = DETECTOR_CATEGORY_MAP.get(check, "other")

        finding = Finding(
            id=f"SLITH-{i:04d}-{check}",
            source=FindingSource.SLITHER,
            detector=check,
            severity=SLITHER_SEVERITY_MAP.get(impact, Severity.INFO),
            confidence=SLITHER_CONFIDENCE_MAP.get(confidence, 0.3),
            title=f"[{check}] {description[:100]}",
            description=description,
            contract=contract,
            function=function,
            file_path=file_path,
            line_start=line_start,
            code_snippet=code_snippet,
            category=category,
            raw_output=det,
        )
        findings.append(finding)

    return findings
