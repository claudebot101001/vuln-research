"""Phase 1: Static analysis scan pipeline."""

import json
import subprocess
from collections import Counter
from pathlib import Path

from .models import Finding, ScanConfig, Severity
from .scoring import score_finding

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzers.slither_runner import run_slither
from analyzers.semgrep_runner import run_semgrep


class Scanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.target_dir: Path | None = None
        self.output_dir: Path | None = None

    def run(self) -> list[Finding]:
        """Execute full scan pipeline."""
        # 1. Acquire target (clone or use local)
        self.target_dir = self._acquire_target()
        self.output_dir = Path("output") / self.target_dir.name
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # 2. Detect solc version from pragma
        solc_version = self.config.solc_version or self._detect_solc_version()
        if solc_version:
            self._ensure_solc(solc_version)

        all_findings: list[Finding] = []

        # 3. Run Slither
        try:
            slither_findings = run_slither(
                self.target_dir,
                filter_paths=self.config.exclude_patterns,
                solc_version=solc_version,
                scope_contracts=self.config.scope_contracts or None,
            )
            all_findings.extend(slither_findings)
        except Exception as e:
            print(f"Slither failed: {e}")

        # 4. Run Semgrep
        try:
            rules_dir = Path(__file__).resolve().parent.parent / "rules" / "semgrep"
            semgrep_findings = run_semgrep(
                self.target_dir,
                rules_dir,
                scope_contracts=self.config.scope_contracts or None,
            )
            all_findings.extend(semgrep_findings)
        except Exception as e:
            print(f"Semgrep failed: {e}")

        # 5. Deduplicate
        all_findings = self._deduplicate(all_findings)

        # 6. Score and filter
        scored = [score_finding(f) for f in all_findings]
        filtered = [
            f
            for f in scored
            if _sev_rank(f.severity) <= _sev_rank(self.config.min_severity)
            and f.confidence >= self.config.min_confidence
        ]

        # 7. Sort by severity (critical first), then confidence (high first)
        filtered.sort(key=lambda f: (_sev_rank(f.severity), -f.confidence))

        # 8. Save results
        self._save_findings(filtered)

        return filtered

    def _acquire_target(self) -> Path:
        """Clone repo or return local path."""
        target = self.config.target
        if (
            target.startswith("http://")
            or target.startswith("https://")
            or target.startswith("git@")
        ):
            # Clone to targets/
            repo_name = target.rstrip("/").split("/")[-1].replace(".git", "")
            dest = Path("targets") / repo_name
            if not dest.exists():
                subprocess.run(
                    ["git", "clone", "--depth", "1", target, str(dest)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            return dest
        return Path(target)

    def _detect_solc_version(self) -> str | None:
        """Detect Solidity version from pragma statements."""
        if not self.target_dir:
            return None
        import re

        versions = []
        for sol_file in self.target_dir.rglob("*.sol"):
            try:
                content = sol_file.read_text(errors="ignore")
                matches = re.findall(
                    r"pragma\s+solidity\s+[\^~>=<]*(\d+\.\d+\.\d+)", content
                )
                versions.extend(matches)
            except Exception:
                continue
        if not versions:
            return None
        # Return the most common version
        return Counter(versions).most_common(1)[0][0]

    def _ensure_solc(self, version: str):
        """Install solc version if not available."""
        result = subprocess.run(
            ["solc-select", "versions"], capture_output=True, text=True
        )
        if version not in result.stdout:
            subprocess.run(["solc-select", "install", version], capture_output=True)
        subprocess.run(["solc-select", "use", version], capture_output=True)

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings (same file+line+category from different tools)."""
        seen: set[tuple[str, int | None, str]] = set()
        unique = []
        for f in findings:
            key = (f.file_path, f.line_start, f.category)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _save_findings(self, findings: list[Finding]):
        """Save findings to JSON."""
        if not self.output_dir:
            return
        output_path = self.output_dir / "findings.json"
        data = [f.model_dump(mode="json") for f in findings]
        output_path.write_text(json.dumps(data, indent=2))


def _sev_rank(sev: Severity) -> int:
    """Lower rank = higher severity."""
    return list(Severity).index(sev)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m pipeline.scan <target>")
        sys.exit(1)
    config = ScanConfig(target=sys.argv[1])
    scanner = Scanner(config)
    findings = scanner.run()
    print(f"Found {len(findings)} issues")
    for f in findings[:10]:
        print(f"  [{f.severity.value}] {f.title}")
