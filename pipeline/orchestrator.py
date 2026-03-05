"""Phase 6: End-to-end vulnerability research pipeline orchestrator."""

import argparse
import json
import sys
from pathlib import Path

from .models import Finding, Hypothesis, PoCResult, ScanConfig, Severity, VulnReport
from .report import ReportGenerator
from .scan import Scanner
from .verify import Verifier


class PipelineOrchestrator:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.scanner = Scanner(config)
        self.verifier = Verifier()
        self.reporter = ReportGenerator()

        self.findings: list[Finding] = []
        self.hypotheses: list[Hypothesis] = []
        self.results: list[tuple[Hypothesis, PoCResult]] = []
        self.reports: list[tuple[VulnReport, Path]] = []

    def run(self) -> list[tuple[VulnReport, Path]]:
        """Execute full pipeline: scan -> hypothesize -> verify -> report."""
        # Phase 1: Scan
        print("[1/4] Scanning target...")
        self.findings = self.scanner.run()
        print(f"  Found {len(self.findings)} findings")

        if not self.findings:
            print("  No findings. Pipeline complete.")
            return []

        # Phase 2: Hypothesize (lazy import — built in parallel)
        print("[2/4] Generating hypotheses...")
        self.hypotheses = self._generate_hypotheses()
        print(f"  Generated {len(self.hypotheses)} hypotheses")

        if not self.hypotheses:
            print("  No hypotheses. Pipeline complete.")
            return []

        # Phase 3: Verify
        print("[3/4] Verifying hypotheses...")
        for hyp in self.hypotheses:
            params = self._build_verify_params(hyp)
            result = self.verifier.verify(hyp, params)
            self.results.append((hyp, result))
            status = "PASS" if result.passed else "FAIL"
            print(f"  [{status}] {hyp.id}: {hyp.attack_vector}")

        # Phase 4: Report
        print("[4/4] Generating reports...")
        verified = [(h, r) for h, r in self.results if r.passed]
        targets = verified if verified else self.results

        for hyp, poc_result in targets:
            poc_code = ""
            if poc_result.test_file:
                test_path = Path(poc_result.test_file)
                if test_path.exists():
                    poc_code = test_path.read_text()

            report, path = self.reporter.generate(
                hypothesis=hyp,
                poc_result=poc_result,
                config=self.config,
                poc_code=poc_code,
            )
            self.reports.append((report, path))
            print(f"  Report: {path}")

        print(f"\nPipeline complete: {len(self.reports)} reports generated")
        return self.reports

    def _generate_hypotheses(self) -> list[Hypothesis]:
        """Generate hypotheses from findings. Imports HypothesisEngine lazily."""
        try:
            from .hypothesis import HypothesisEngine
            engine = HypothesisEngine()
            return engine.generate(self.findings)
        except ImportError:
            # HypothesisEngine not yet available — fall back to simple mapping
            return self._fallback_hypotheses()

    def _fallback_hypotheses(self) -> list[Hypothesis]:
        """Create basic hypotheses directly from findings when HypothesisEngine is unavailable."""
        hypotheses = []
        for i, finding in enumerate(self.findings):
            hyp = Hypothesis(
                id=f"H-{i+1:03d}",
                finding_ids=[finding.id],
                attack_vector=finding.category,
                preconditions=[],
                impact=finding.description,
                severity=finding.severity,
                exploitability=finding.confidence,
                poc_strategy=f"Verify {finding.category} in {finding.contract}.{finding.function or 'unknown'}",
                target_functions=[f"{finding.contract}.{finding.function}" if finding.function else finding.contract],
                needs_fork=self.config.fork_url is not None,
                fork_block=self.config.fork_block,
            )
            hypotheses.append(hyp)
        return hypotheses

    def _build_verify_params(self, hypothesis: Hypothesis) -> dict:
        """Build template parameters from hypothesis + scan config."""
        params: dict = {}
        if self.config.fork_url:
            params["fork_url"] = self.config.fork_url
        if self.config.fork_block:
            params["fork_block"] = self.config.fork_block
        if self.config.solc_version:
            params["solc_version"] = self.config.solc_version
        return params


def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability research pipeline orchestrator"
    )
    parser.add_argument("target", help="Target repository URL or local path")
    parser.add_argument("--scope", nargs="*", default=[], help="Contracts in scope")
    parser.add_argument("--solc", default=None, help="Solidity compiler version")
    parser.add_argument("--min-severity", default="low", choices=["critical", "high", "medium", "low", "info"])
    parser.add_argument("--min-confidence", type=float, default=0.3)
    parser.add_argument("--fork-url", default=None, help="RPC URL for fork testing")
    parser.add_argument("--fork-block", type=int, default=None, help="Block number for fork")
    parser.add_argument("--immunefi-program", default=None, help="Immunefi program slug")

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
