"""Pipeline orchestrator with checkpointing, budget tracking, and freshness gate."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .acquire import TargetAcquirer
from .analyze import Analyzer
from .context import ContextExtractor
from .llm import LLMClient, LLMError
from .models import (
    AcquiredTarget,
    CodeContext,
    Finding,
    FreshnessReport,
    Hypothesis,
    PoCResult,
    ScanConfig,
    Severity,
    VulnReport,
)
from .poc_gen import PoCGenerator
from .report import ReportGenerator
from .scan import Scanner
from .triage import Triager


class PipelineOrchestrator:
    def __init__(self, config: ScanConfig):
        self.config = config
        target_name = self._target_name()
        cache_dir = (
            Path("output") / target_name / "llm_cache" if not config.no_cache else None
        )
        self.llm = LLMClient(
            max_calls=config.max_llm_calls,
            cache_dir=cache_dir,
        )
        self.acquirer = TargetAcquirer()
        self.scanner = Scanner(config)
        self.context_extractor: ContextExtractor | None = None
        self.triager = Triager(self.llm)
        self.analyzer = Analyzer(self.llm)
        self.poc_gen = PoCGenerator(
            self.llm, output_dir=Path("output") / target_name / "poc"
        )
        self.reporter = ReportGenerator(
            self.llm,
            output_dir=Path("output") / target_name / "reports",
            platform=config.platform,
        )
        self.checkpoint_dir = Path("output") / target_name / "checkpoints"

    def run(self) -> list[tuple[VulnReport, Path]]:
        """Execute full pipeline: acquire -> scan -> context -> triage -> analyze -> verify -> report."""
        # 1. Acquire + freshness check (hard gate)
        target = self._load_or_run("acquire", self._phase_acquire)
        self.acquirer.validate_freshness(target.freshness, force=self.config.force)
        print(f"[1/7] Target acquired: {target.path} (solc: {target.solc_version})")

        # 2. Static scan
        self.scanner.target_dir = target.path
        findings = self._load_or_run("scan", self._phase_scan)
        if not findings:
            print("[2/7] No findings. Pipeline complete.")
            return []
        print(f"[2/7] {len(findings)} findings from static analysis")

        # 3. Extract code context
        self.context_extractor = ContextExtractor(target.path)
        contexts = self._load_or_run("context", lambda: self._phase_context(findings))
        print(f"[3/7] Extracted context for {len(contexts)} findings")

        # 4. LLM triage
        triaged = self._load_or_run(
            "triage", lambda: self._phase_triage(findings, contexts)
        )
        print(f"[4/7] {len(triaged)}/{len(findings)} findings survived triage")
        self._print_budget()

        if not triaged:
            print("  All findings triaged as false positives. Pipeline complete.")
            return []

        # 5. LLM deep analysis
        context_map = {c.finding_id: c for c in contexts}
        hypotheses = self._load_or_run(
            "analyze", lambda: self._phase_analyze(triaged, context_map)
        )
        print(f"[5/7] {len(hypotheses)} exploitable hypotheses")
        self._print_budget()

        if not hypotheses:
            print("  No exploitable hypotheses. Pipeline complete.")
            return []

        # 6. PoC generation + verification + validation
        verified = self._load_or_run(
            "verify", lambda: self._phase_verify(hypotheses, context_map)
        )
        print(f"[6/7] {len(verified)} verified + validated PoCs")
        self._print_budget()

        # 7. Report (ONLY for verified findings)
        if not verified:
            print("No verified vulnerabilities found.")
            return []

        reports = self._phase_report(verified)
        print(f"[7/7] {len(reports)} reports generated")
        print(
            f"  Total LLM calls: {self.llm.cost.call_count}, "
            f"est. cost: ${self.llm.cost.estimated_cost_usd:.2f}"
        )

        return reports

    # -- Phase implementations --

    def _phase_acquire(self) -> AcquiredTarget:
        return self.acquirer.acquire(self.config)

    def _phase_scan(self) -> list[Finding]:
        return self.scanner.run()

    def _phase_context(self, findings: list[Finding]) -> list[CodeContext]:
        return [self.context_extractor.extract(f) for f in findings]

    def _phase_triage(
        self, findings: list[Finding], contexts: list[CodeContext]
    ) -> list[Finding]:
        return self.triager.triage(findings, contexts, self.context_extractor)

    def _phase_analyze(
        self, triaged: list[Finding], context_map: dict[str, CodeContext]
    ) -> list[Hypothesis]:
        hypotheses = []
        for finding in triaged:
            ctx = context_map.get(finding.id)
            if not ctx:
                continue
            hyp = self.analyzer.analyze(finding, ctx)
            if hyp:
                hypotheses.append(hyp)
        return hypotheses

    def _phase_verify(
        self,
        hypotheses: list[Hypothesis],
        context_map: dict[str, CodeContext],
    ) -> list[tuple[Hypothesis, PoCResult, str]]:
        """Run PoC generation + verification for each hypothesis.

        Returns list of (hypothesis, poc_result, poc_code) for verified findings.
        """
        verified = []
        for hyp in hypotheses:
            ctx = context_map.get(hyp.finding_ids[0]) if hyp.finding_ids else None
            if not ctx:
                ctx = CodeContext(finding_id=hyp.id)

            try:
                result = self.poc_gen.generate_and_verify(hyp, ctx, self.config)
            except LLMError as e:
                print(f"  PoC generation failed for {hyp.id}: {e}")
                continue

            if result and result.passed and result.validated:
                poc_code = ""
                if result.test_file:
                    test_path = Path(result.test_file)
                    if test_path.exists():
                        poc_code = test_path.read_text()
                verified.append((hyp, result, poc_code))
        return verified

    def _phase_report(
        self, verified: list[tuple[Hypothesis, PoCResult, str]]
    ) -> list[tuple[VulnReport, Path]]:
        reports = []
        for hyp, poc_result, poc_code in verified:
            report, path = self.reporter.generate(
                hypothesis=hyp,
                poc_result=poc_result,
                poc_code=poc_code,
                config=self.config,
            )
            reports.append((report, path))
            print(f"  Report: {path}")
        return reports

    # -- Checkpointing --

    def _load_or_run(self, phase_name: str, phase_fn):
        """Load checkpoint if exists, otherwise run phase and save checkpoint."""
        checkpoint = self.checkpoint_dir / f"{phase_name}.json"
        if checkpoint.exists() and not self.config.no_cache:
            print(f"  (resuming from checkpoint: {phase_name})")
            return self._load_checkpoint(checkpoint, phase_name)
        result = phase_fn()
        self._save_checkpoint(checkpoint, result, phase_name)
        return result

    def _save_checkpoint(self, path: Path, data, phase_name: str) -> None:
        """Serialize phase output to JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        serialized = _serialize(data)
        path.write_text(json.dumps(serialized, indent=2, default=str))

    def _load_checkpoint(self, path: Path, phase_name: str):
        """Deserialize phase output from JSON."""
        raw = json.loads(path.read_text())
        return _deserialize(raw, phase_name)

    # -- Helpers --

    def _target_name(self) -> str:
        return self.config.target.rstrip("/").split("/")[-1].replace(".git", "")

    def _print_budget(self):
        print(
            f"  LLM budget: {self.llm.cost.call_count}/{self.llm.cost.max_calls} calls"
        )


def _serialize(data):
    """Serialize pipeline data for checkpointing."""
    if isinstance(data, list):
        return [_serialize(item) for item in data]
    if isinstance(data, tuple):
        return {"__tuple__": True, "items": [_serialize(item) for item in data]}
    if hasattr(data, "model_dump"):
        return {
            "__model__": type(data).__name__,
            "data": data.model_dump(mode="json"),
        }
    return data


def _deserialize(raw, phase_name: str):
    """Deserialize checkpoint data back to pipeline types."""
    model_map = {
        "AcquiredTarget": AcquiredTarget,
        "Finding": Finding,
        "CodeContext": CodeContext,
        "Hypothesis": Hypothesis,
        "PoCResult": PoCResult,
        "VulnReport": VulnReport,
        "FreshnessReport": FreshnessReport,
    }

    if isinstance(raw, dict):
        if raw.get("__tuple__"):
            return tuple(_deserialize(item, phase_name) for item in raw["items"])
        if "__model__" in raw:
            cls = model_map.get(raw["__model__"])
            if cls:
                return cls.model_validate(raw["data"])
            return raw["data"]
        return raw

    if isinstance(raw, list):
        return [_deserialize(item, phase_name) for item in raw]

    return raw


def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability research pipeline orchestrator"
    )
    parser.add_argument("target", help="Target repository URL or local path")
    parser.add_argument("--scope", nargs="*", default=[], help="Contracts in scope")
    parser.add_argument("--solc", default=None, help="Solidity compiler version")
    parser.add_argument(
        "--min-severity",
        default="low",
        choices=["critical", "high", "medium", "low", "info"],
    )
    parser.add_argument("--min-confidence", type=float, default=0.3)
    parser.add_argument("--fork-url", default=None, help="RPC URL for fork testing")
    parser.add_argument(
        "--fork-block", type=int, default=None, help="Block number for fork"
    )
    parser.add_argument(
        "--immunefi-program", default=None, help="Immunefi program slug"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Override freshness check",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable LLM response caching and checkpoints",
    )
    parser.add_argument(
        "--max-llm-calls",
        type=int,
        default=50,
        help="Maximum LLM calls per pipeline run",
    )
    parser.add_argument(
        "--platform",
        default="cantina",
        choices=["cantina", "immunefi", "generic"],
        help="Report platform format",
    )

    args = parser.parse_args()

    config = ScanConfig(
        target=args.target,
        scope_contracts=args.scope,
        solc_version=args.solc,
        min_severity=Severity(args.min_severity),
        min_confidence=args.min_confidence,
        fork_url=args.fork_url,
        fork_block=args.fork_block,
        immunefi_program=args.immunefi_program,
        force=args.force,
        no_cache=args.no_cache,
        max_llm_calls=args.max_llm_calls,
        platform=args.platform,
    )

    orchestrator = PipelineOrchestrator(config)
    reports = orchestrator.run()

    if not reports:
        sys.exit(0)

    # Print summary
    print("\n--- Summary ---")
    for report, path in reports:
        print(f"  [{report.severity.value.upper()}] {report.title} -> {path}")


if __name__ == "__main__":
    main()
