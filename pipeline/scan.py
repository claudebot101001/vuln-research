"""Phase 2: Static analysis scan pipeline."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .models import Finding, ScanConfig, sev_rank
from .scoring import score_finding

# Analyzers package lives at repo root level, not inside pipeline/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzers.slither_runner import run_slither  # noqa: E402
from analyzers.semgrep_runner import run_semgrep  # noqa: E402


class Scanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.target_dir: Path | None = None
        self.output_dir: Path | None = None

    def run(self) -> list[Finding]:
        """Execute full scan pipeline.

        Expects target_dir to be set by the orchestrator (via TargetAcquirer).
        Falls back to config.target as a local path if target_dir is not set.
        """
        if not self.target_dir:
            self.target_dir = Path(self.config.target)
        self.output_dir = Path("output") / self.target_dir.name
        self.output_dir.mkdir(parents=True, exist_ok=True)

        all_findings: list[Finding] = []

        # 1. Run Slither
        try:
            slither_findings = run_slither(
                self.target_dir,
                filter_paths=self.config.exclude_patterns,
                solc_version=self.config.solc_version,
                scope_contracts=self.config.scope_contracts or None,
            )
            all_findings.extend(slither_findings)
        except Exception as e:
            print(f"Slither failed: {e}")

        # 2. Run Semgrep
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

        # 3. Deduplicate
        all_findings = self._deduplicate(all_findings)

        # 4. Score and filter
        scored = [score_finding(f) for f in all_findings]
        filtered = [
            f
            for f in scored
            if sev_rank(f.severity) <= sev_rank(self.config.min_severity)
            and f.confidence >= self.config.min_confidence
        ]

        # 5. Sort by severity (critical first), then confidence (high first)
        filtered.sort(key=lambda f: (sev_rank(f.severity), -f.confidence))

        # 6. Save results
        self._save_findings(filtered)

        return filtered

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
