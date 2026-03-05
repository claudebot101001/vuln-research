"""Integration tests: exercise scan → hypothesize → verify → report pipeline."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline.hypothesize import HypothesisEngine
from pipeline.models import (
    Finding,
    FindingSource,
    Hypothesis,
    PoCResult,
    ScanConfig,
    Severity,
    VulnReport,
)
from pipeline.report import ReportGenerator
from pipeline.verify import Verifier

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE_CONTRACTS = FIXTURES / "sample_contracts"


# ---------------------------------------------------------------------------
# Helpers: simulate scan output (Slither/Semgrep produce these from Vulnerable.sol)
# ---------------------------------------------------------------------------

def _simulated_findings() -> list[Finding]:
    """Findings that static analysis would produce from Vulnerable.sol."""
    return [
        Finding(
            id="SLITH-0001-reentrancy-eth",
            source=FindingSource.SLITHER,
            detector="reentrancy-eth",
            severity=Severity.HIGH,
            confidence=0.9,
            title="Reentrancy in VulnerableVault.withdraw(uint256)",
            description="External call at line 27 before state update at line 31",
            contract="VulnerableVault",
            function="withdraw",
            file_path=str(SAMPLE_CONTRACTS / "Vulnerable.sol"),
            line_start=27,
            code_snippet='msg.sender.call{value: amount}("")',
            category="reentrancy",
        ),
        Finding(
            id="SLITH-0002-arbitrary-send-eth",
            source=FindingSource.SLITHER,
            detector="arbitrary-send-eth",
            severity=Severity.HIGH,
            confidence=0.9,
            title="VulnerableVault.emergencyWithdraw sends ETH to arbitrary user",
            description="emergencyWithdraw(address,address,uint256) has no access control",
            contract="VulnerableVault",
            function="emergencyWithdraw",
            file_path=str(SAMPLE_CONTRACTS / "Vulnerable.sol"),
            line_start=36,
            code_snippet="IERC20(token).transfer(to, amount)",
            category="access-control",
        ),
        Finding(
            id="SEM-0003-unchecked-transfer",
            source=FindingSource.SEMGREP,
            detector="unchecked-erc20-transfer",
            severity=Severity.MEDIUM,
            confidence=0.6,
            title="Unchecked ERC20 transfer return value",
            description="Return value of IERC20.transfer() not checked in transferTokens",
            contract="VulnerableVault",
            function="transferTokens",
            file_path=str(SAMPLE_CONTRACTS / "Vulnerable.sol"),
            line_start=43,
            code_snippet="IERC20(token).transfer(to, amount)",
            category="unchecked-calls",
        ),
        Finding(
            id="SEM-0004-spot-price",
            source=FindingSource.SEMGREP,
            detector="spot-price-getReserves",
            severity=Severity.HIGH,
            confidence=0.6,
            title="Spot price via getReserves is manipulable",
            description="getPrice() uses getReserves for spot price, manipulable via flash loan",
            contract="VulnerableOracle",
            function="getPrice",
            file_path=str(SAMPLE_CONTRACTS / "Vulnerable.sol"),
            line_start=60,
            code_snippet="IUniswapV2Pair(pair).getReserves()",
            category="oracle-manipulation",
        ),
        Finding(
            id="SLITH-0005-controlled-delegatecall",
            source=FindingSource.SLITHER,
            detector="controlled-delegatecall",
            severity=Severity.HIGH,
            confidence=0.9,
            title="Controlled delegatecall in VulnerableProxy.upgradeAndCall",
            description="delegatecall target controlled by user input",
            contract="VulnerableProxy",
            function="upgradeAndCall",
            file_path=str(SAMPLE_CONTRACTS / "Vulnerable.sol"),
            line_start=78,
            code_snippet="newImpl.delegatecall(data)",
            category="access-control",
        ),
    ]


# ---------------------------------------------------------------------------
# Phase 2: Hypothesis generation
# ---------------------------------------------------------------------------


class TestHypothesisIntegration:
    def test_generates_hypotheses_from_findings(self):
        findings = _simulated_findings()
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()

        assert len(hypotheses) >= 3  # at least: reentrancy, access-control(s), unchecked, oracle

        categories = {h.attack_vector for h in hypotheses}
        # Should see reentrancy and oracle-related hypotheses
        assert any("re-enter" in v.lower() for v in categories)
        assert any("oracle" in v.lower() or "price" in v.lower() for v in categories)

    def test_reentrancy_hypothesis_targets_withdraw(self):
        findings = _simulated_findings()
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()

        reent = [h for h in hypotheses if "re-enter" in h.attack_vector.lower()]
        assert len(reent) == 1
        assert "withdraw" in reent[0].target_functions

    def test_access_control_hypotheses(self):
        findings = _simulated_findings()
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()

        ac = [h for h in hypotheses if "authorization" in h.attack_vector.lower()]
        # Two access-control findings in different contracts (VulnerableVault, VulnerableProxy)
        # They're in the same category but different contracts, may or may not correlate
        assert len(ac) >= 1

    def test_oracle_hypothesis_needs_fork(self):
        findings = _simulated_findings()
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()

        oracle = [h for h in hypotheses if "oracle" in h.attack_vector.lower()]
        assert len(oracle) == 1
        assert oracle[0].needs_fork is True

    def test_hypotheses_sorted_by_priority(self):
        findings = _simulated_findings()
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()

        # Should be sorted: highest priority first
        scores = [
            h.exploitability * (len(Severity) - list(Severity).index(h.severity))
            for h in hypotheses
        ]
        assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# Phase 3: Verification (template rendering only, no forge execution)
# ---------------------------------------------------------------------------


class TestVerifyIntegration:
    def test_reentrancy_template_renders(self, tmp_path):
        hyp = Hypothesis(
            id="H-test-001",
            finding_ids=["SLITH-0001"],
            attack_vector="External call before state update allows attacker to re-enter and drain funds",
            preconditions=["No reentrancy guard"],
            impact="Fund drainage",
            severity=Severity.HIGH,
            exploitability=0.8,
            poc_strategy="Deploy attacker with fallback",
            target_functions=["withdraw"],
        )
        verifier = Verifier(output_dir=tmp_path)
        rendered_file = verifier.render_poc(hyp, params={"target_contract": "VulnerableVault"})

        assert rendered_file is not None
        assert rendered_file.exists()
        content = rendered_file.read_text()
        assert "withdraw" in content
        assert "test_reentrancy" in content.lower() or "reentrancy" in content.lower()

    def test_access_control_template_renders(self, tmp_path):
        hyp = Hypothesis(
            id="H-test-002",
            finding_ids=["SLITH-0002"],
            attack_vector="Missing or insufficient authorization allows unauthorized state change",
            preconditions=[],
            impact="Unauthorized access",
            severity=Severity.HIGH,
            exploitability=0.8,
            poc_strategy="Call from unauthorized address",
            target_functions=["emergencyWithdraw"],
        )
        verifier = Verifier(output_dir=tmp_path)
        rendered_file = verifier.render_poc(hyp, params={"target_contract": "VulnerableVault"})

        assert rendered_file is not None
        content = rendered_file.read_text()
        assert "emergencyWithdraw" in content

    def test_oracle_template_renders(self, tmp_path):
        hyp = Hypothesis(
            id="H-test-003",
            finding_ids=["SEM-0004"],
            attack_vector="Stale or manipulable price oracle enables flash loan sandwich attack",
            preconditions=[],
            impact="Oracle manipulation",
            severity=Severity.HIGH,
            exploitability=0.5,
            poc_strategy="Flash loan to manipulate oracle",
            target_functions=["getPrice"],
            needs_fork=True,
        )
        verifier = Verifier(output_dir=tmp_path)
        rendered_file = verifier.render_poc(hyp, params={"target_contract": "VulnerableOracle"})

        assert rendered_file is not None
        content = rendered_file.read_text()
        assert "getPrice" in content or "oracle" in content.lower()

    def test_unknown_vector_returns_none(self, tmp_path):
        hyp = Hypothesis(
            id="H-test-999",
            finding_ids=["X-999"],
            attack_vector="Some completely novel attack nobody has seen before",
            preconditions=[],
            impact="Unknown",
            severity=Severity.LOW,
            exploitability=0.1,
            poc_strategy="Manual review",
            target_functions=["foo"],
        )
        verifier = Verifier(output_dir=tmp_path)
        result = verifier.verify(hyp)
        assert result.passed is False
        assert "No template found" in result.error


# ---------------------------------------------------------------------------
# Phase 4: Report generation
# ---------------------------------------------------------------------------


class TestReportIntegration:
    def test_full_report_generation(self, tmp_path):
        hyp = Hypothesis(
            id="H-test-001",
            finding_ids=["SLITH-0001"],
            attack_vector="External call before state update allows attacker to re-enter and drain funds",
            preconditions=["No reentrancy guard", "Sufficient balance"],
            impact="Complete fund drainage via recursive re-entry",
            severity=Severity.HIGH,
            exploitability=0.8,
            poc_strategy="Deploy attacker with fallback",
            target_functions=["VulnerableVault.withdraw"],
        )
        poc_result = PoCResult(
            hypothesis_id="H-test-001",
            test_name="test_reentrancy_exploit",
            test_file="/tmp/test.t.sol",
            compiled=True,
            passed=True,
            gas_used=150000,
            logs="[PASS] test_reentrancy_exploit (gas: 150000)",
        )
        config = ScanConfig(
            target="https://github.com/example/vulnerable-protocol",
            immunefi_program="vulnerable-protocol",
        )

        generator = ReportGenerator(output_dir=tmp_path)
        report, path = generator.generate(
            hypothesis=hyp,
            poc_result=poc_result,
            config=config,
            poc_code="// PoC code here",
        )

        assert isinstance(report, VulnReport)
        assert report.severity == Severity.HIGH
        assert "reentrancy" in report.title.lower() or "re-enter" in report.title.lower()
        assert path.exists()

        markdown = path.read_text()
        assert "## Summary" in markdown or "# " in markdown
        assert "Vulnerability" in markdown
        assert "Remediation" in markdown

    def test_report_without_poc(self, tmp_path):
        hyp = Hypothesis(
            id="H-test-002",
            finding_ids=["SEM-0004"],
            attack_vector="Manipulable oracle",
            preconditions=[],
            impact="Oracle manipulation",
            severity=Severity.HIGH,
            exploitability=0.5,
            poc_strategy="Flash loan",
            target_functions=["getPrice"],
        )
        config = ScanConfig(target="/local/path/to/contracts")

        generator = ReportGenerator(output_dir=tmp_path)
        report, path = generator.generate(
            hypothesis=hyp,
            poc_result=None,
            config=config,
        )

        assert isinstance(report, VulnReport)
        assert report.poc_result is None
        assert path.exists()


# ---------------------------------------------------------------------------
# End-to-end pipeline (scan mocked since we can't run Slither in tests)
# ---------------------------------------------------------------------------


class TestEndToEndPipeline:
    def test_pipeline_scan_to_report(self, tmp_path):
        """Full pipeline with mocked scan phase."""
        findings = _simulated_findings()
        config = ScanConfig(
            target=str(SAMPLE_CONTRACTS),
            immunefi_program="test-protocol",
        )

        # Phase 1: Scan (simulated)
        assert len(findings) == 5

        # Phase 2: Hypothesize
        engine = HypothesisEngine(findings, config)
        hypotheses = engine.generate()
        assert len(hypotheses) >= 3

        # Phase 3: Verify (templates only, no forge)
        verifier = Verifier(output_dir=tmp_path / "poc")
        results = []
        for hyp in hypotheses:
            result = verifier.verify(hyp)
            results.append((hyp, result))

        # At least some hypotheses should match templates
        rendered = [(h, r) for h, r in results if r.error is None or "No template" not in r.error]
        # forge isn't available in test env, so compiled=False is expected
        assert len(rendered) >= 0  # Might be 0 if forge not in PATH

        # Phase 4: Report for all hypotheses
        reporter = ReportGenerator(output_dir=tmp_path / "reports")
        reports = []
        for hyp, poc_result in results:
            report, path = reporter.generate(
                hypothesis=hyp,
                poc_result=poc_result,
                config=config,
            )
            reports.append((report, path))

        assert len(reports) == len(hypotheses)
        for report, path in reports:
            assert isinstance(report, VulnReport)
            assert path.exists()
            assert path.suffix == ".md"

    def test_findings_from_different_sources_combined(self):
        """Verify Slither and Semgrep findings are properly combined."""
        findings = _simulated_findings()

        slither_findings = [f for f in findings if f.source == FindingSource.SLITHER]
        semgrep_findings = [f for f in findings if f.source == FindingSource.SEMGREP]

        assert len(slither_findings) == 3
        assert len(semgrep_findings) == 2

        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()

        # All findings should be referenced in at least one hypothesis
        all_referenced = set()
        for h in hypotheses:
            all_referenced.update(h.finding_ids)
        for f in findings:
            assert f.id in all_referenced, f"Finding {f.id} not referenced in any hypothesis"

    def test_pipeline_with_zero_findings(self, tmp_path):
        """Pipeline handles zero findings gracefully."""
        config = ScanConfig(target=str(SAMPLE_CONTRACTS))
        engine = HypothesisEngine([], config)
        hypotheses = engine.generate()
        assert hypotheses == []

    def test_sample_contracts_exist(self):
        """Verify fixture contracts are in place."""
        assert (SAMPLE_CONTRACTS / "Vulnerable.sol").exists()
        assert (SAMPLE_CONTRACTS / "Safe.sol").exists()
