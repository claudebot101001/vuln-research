"""Integration tests: verify pipeline v2 modules work together."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pipeline.models import (
    AcquiredTarget,
    CodeContext,
    Finding,
    FindingSource,
    FreshnessReport,
    Hypothesis,
    PoCResult,
    ScanConfig,
    Severity,
    VulnReport,
)

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE_CONTRACTS = FIXTURES / "sample_contracts"


# ---------------------------------------------------------------------------
# Helpers
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
# Module import smoke tests
# ---------------------------------------------------------------------------


class TestModuleImports:
    """Verify all v2 pipeline modules import without error."""

    def test_import_acquire(self):
        from pipeline.acquire import TargetAcquirer

        assert TargetAcquirer is not None

    def test_import_context(self):
        from pipeline.context import ContextExtractor

        assert ContextExtractor is not None

    def test_import_triage(self):
        from pipeline.triage import Triager

        assert Triager is not None

    def test_import_analyze(self):
        from pipeline.analyze import Analyzer

        assert Analyzer is not None

    def test_import_poc_gen(self):
        from pipeline.poc_gen import PoCGenerator

        assert PoCGenerator is not None

    def test_import_report(self):
        from pipeline.report import ReportGenerator

        assert ReportGenerator is not None

    def test_import_orchestrator(self):
        from pipeline.orchestrator import PipelineOrchestrator

        assert PipelineOrchestrator is not None

    def test_import_llm(self):
        from pipeline.llm import LLMClient

        assert LLMClient is not None

    def test_import_verify(self):
        from pipeline.verify import ForgeExecutor

        assert ForgeExecutor is not None


# ---------------------------------------------------------------------------
# Data model compatibility
# ---------------------------------------------------------------------------


class TestModelCompatibility:
    def test_findings_from_different_sources(self):
        """Verify Slither and Semgrep findings are properly combined."""
        findings = _simulated_findings()

        slither_findings = [f for f in findings if f.source == FindingSource.SLITHER]
        semgrep_findings = [f for f in findings if f.source == FindingSource.SEMGREP]

        assert len(slither_findings) == 3
        assert len(semgrep_findings) == 2

    def test_acquired_target_model(self):
        target = AcquiredTarget(
            path=Path("/tmp/test"),
            solc_version="0.8.20",
            freshness=FreshnessReport(is_clean=True),
        )
        assert target.path == Path("/tmp/test")
        assert target.freshness.is_clean

    def test_code_context_model(self):
        ctx = CodeContext(
            finding_id="F-001",
            source_snippet="function withdraw() {",
            full_function="function withdraw() { ... }",
        )
        assert ctx.finding_id == "F-001"

    def test_hypothesis_v2_fields(self):
        hyp = Hypothesis(
            id="H-001",
            finding_ids=["F-001"],
            attack_vector="reentrancy",
            preconditions=[],
            impact="fund drain",
            severity=Severity.HIGH,
            exploitability=0.8,
            poc_strategy="test",
            target_functions=["Vault.withdraw"],
            root_cause="External call before state update",
            exploit_steps=["Step 1", "Step 2"],
            required_contracts=["IERC20"],
            poc_solidity_hints="vm.prank(attacker);",
        )
        assert hyp.root_cause != ""
        assert len(hyp.exploit_steps) == 2

    def test_poc_result_v2_fields(self):
        result = PoCResult(
            hypothesis_id="H-001",
            test_name="test_exploit",
            test_file="/tmp/test.t.sol",
            compiled=True,
            passed=True,
            attempt=2,
            previous_errors=["Attempt 1 failed"],
            validated=True,
            validation_reason="PoC demonstrates drain",
        )
        assert result.attempt == 2
        assert result.validated

    def test_scan_config_v2_fields(self):
        config = ScanConfig(
            target="test",
            max_llm_calls=100,
            force=True,
            no_cache=True,
            platform="immunefi",
        )
        assert config.max_llm_calls == 100
        assert config.force
        assert config.platform == "immunefi"


# ---------------------------------------------------------------------------
# Report generation (mocked LLM)
# ---------------------------------------------------------------------------


class TestReportIntegration:
    def test_full_report_generation(self, tmp_path):
        from pipeline.llm import LLMClient
        from pipeline.report import ReportGenerator

        llm = MagicMock(spec=LLMClient)
        llm.ask.return_value = (
            "# Reentrancy in Vault.withdraw\n"
            "## Summary\nReentrancy vulnerability.\n"
            "## Vulnerability Detail\nExternal call before state update.\n"
            "## Impact\nFund drainage.\n"
            "## Attack Scenario\nDeploy attacker.\n"
            "## Proof of Concept\nPoC here.\n"
            "## Remediation\nUse ReentrancyGuard.\n"
        )

        hyp = Hypothesis(
            id="H-test-001",
            finding_ids=["SLITH-0001"],
            attack_vector="Reentrancy via external call before state update",
            preconditions=["No reentrancy guard"],
            impact="Complete fund drainage",
            severity=Severity.HIGH,
            exploitability=0.8,
            poc_strategy="Deploy attacker with fallback",
            target_functions=["VulnerableVault.withdraw"],
            root_cause="External call before state update",
        )
        poc_result = PoCResult(
            hypothesis_id="H-test-001",
            test_name="test_reentrancy_exploit",
            test_file="/tmp/test.t.sol",
            compiled=True,
            passed=True,
            gas_used=150000,
            logs="[PASS] test_reentrancy_exploit (gas: 150000)",
            validated=True,
        )
        config = ScanConfig(
            target="https://github.com/example/vulnerable-protocol",
            immunefi_program="vulnerable-protocol",
        )

        generator = ReportGenerator(llm=llm, output_dir=tmp_path)
        report, path = generator.generate(
            hypothesis=hyp,
            poc_result=poc_result,
            poc_code="// PoC code here",
            config=config,
        )

        assert isinstance(report, VulnReport)
        assert report.severity == Severity.HIGH
        assert path.exists()
        assert llm.ask.called

    def test_report_without_immunefi_program(self, tmp_path):
        from pipeline.llm import LLMClient
        from pipeline.report import ReportGenerator

        llm = MagicMock(spec=LLMClient)
        llm.ask.return_value = (
            "# Title\n## Summary\nSummary.\n## Remediation\nFix it.\n"
        )

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
        poc_result = PoCResult(
            hypothesis_id="H-test-002",
            test_name="test_exploit",
            test_file="/tmp/test.t.sol",
            compiled=True,
            passed=True,
        )
        config = ScanConfig(target="/local/path/to/contracts")

        generator = ReportGenerator(llm=llm, output_dir=tmp_path)
        report, path = generator.generate(
            hypothesis=hyp,
            poc_result=poc_result,
            poc_code="",
            config=config,
        )

        assert isinstance(report, VulnReport)
        assert report.immunefi_program is None
        assert path.exists()


# ---------------------------------------------------------------------------
# Fixture verification
# ---------------------------------------------------------------------------


class TestFixtures:
    def test_sample_contracts_exist(self):
        assert (SAMPLE_CONTRACTS / "Vulnerable.sol").exists()
        assert (SAMPLE_CONTRACTS / "Safe.sol").exists()
