import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from pipeline.models import (
    Finding,
    FindingSource,
    Hypothesis,
    PoCResult,
    ScanConfig,
    Severity,
    VulnReport,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_finding(**overrides) -> Finding:
    """Create a Finding with the minimum required fields."""
    defaults = {
        "id": "F-001",
        "source": FindingSource.SLITHER,
        "detector": "reentrancy-eth",
        "severity": Severity.HIGH,
        "confidence": 0.9,
        "title": "Reentrancy in withdraw()",
        "description": "State change after external call",
        "contract": "Vault",
        "file_path": "src/Vault.sol",
        "category": "reentrancy",
    }
    defaults.update(overrides)
    return Finding(**defaults)


def _full_finding() -> Finding:
    """Create a Finding with every field populated."""
    return Finding(
        id="F-002",
        source=FindingSource.SEMGREP,
        detector="erc20-reentrancy",
        severity=Severity.CRITICAL,
        confidence=0.95,
        title="Cross-function reentrancy",
        description="ERC-20 callback allows re-entry into deposit()",
        contract="LendingPool",
        function="deposit",
        file_path="src/LendingPool.sol",
        line_start=42,
        line_end=58,
        code_snippet="function deposit() external { ... }",
        category="reentrancy",
        raw_output={"detector_id": "erc20-reentrancy", "extra": True},
    )


# ---------------------------------------------------------------------------
# Severity enum
# ---------------------------------------------------------------------------


class TestSeverity:
    def test_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.INFO.value == "info"

    def test_ordering(self):
        """Severity members are ordered CRITICAL < HIGH < MEDIUM < LOW < INFO."""
        members = list(Severity)
        assert members == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]

    def test_string_coercion(self):
        assert Severity("high") is Severity.HIGH


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class TestFinding:
    def test_minimal(self):
        f = _minimal_finding()
        assert f.function is None
        assert f.line_start is None
        assert f.line_end is None
        assert f.code_snippet == ""
        assert f.raw_output == {}

    def test_full(self):
        f = _full_finding()
        assert f.function == "deposit"
        assert f.line_start == 42
        assert f.line_end == 58
        assert f.raw_output["extra"] is True

    def test_confidence_bounds(self):
        with pytest.raises(ValidationError):
            _minimal_finding(confidence=1.5)
        with pytest.raises(ValidationError):
            _minimal_finding(confidence=-0.1)

    def test_confidence_edge_values(self):
        assert _minimal_finding(confidence=0.0).confidence == 0.0
        assert _minimal_finding(confidence=1.0).confidence == 1.0


# ---------------------------------------------------------------------------
# Hypothesis
# ---------------------------------------------------------------------------


class TestHypothesis:
    def test_creation(self):
        h = Hypothesis(
            id="H-001",
            finding_ids=["F-001", "F-002"],
            attack_vector="Flash loan + reentrancy",
            preconditions=["Pool has > 100 ETH", "No reentrancy guard"],
            impact="Drain pool funds",
            severity=Severity.CRITICAL,
            exploitability=0.8,
            poc_strategy="Forge test with flash loan callback",
            target_functions=["withdraw", "deposit"],
        )
        assert h.needs_fork is False
        assert h.fork_block is None

    def test_with_fork(self):
        h = Hypothesis(
            id="H-002",
            finding_ids=["F-001"],
            attack_vector="Oracle manipulation",
            preconditions=["Chainlink stale price"],
            impact="Under-collateralized liquidation",
            severity=Severity.HIGH,
            exploitability=0.6,
            poc_strategy="Fork mainnet at block with stale oracle",
            target_functions=["liquidate"],
            needs_fork=True,
            fork_block=18_000_000,
        )
        assert h.needs_fork is True
        assert h.fork_block == 18_000_000


# ---------------------------------------------------------------------------
# PoCResult
# ---------------------------------------------------------------------------


class TestPoCResult:
    def test_creation(self):
        r = PoCResult(
            hypothesis_id="H-001",
            test_name="test_drain_pool",
            test_file="test/Exploit.t.sol",
            compiled=True,
            passed=True,
            gas_used=250_000,
            profit_usd=150_000.0,
            logs="[PASS] test_drain_pool",
        )
        assert r.error is None
        assert r.profit_usd == 150_000.0

    def test_failed_result(self):
        r = PoCResult(
            hypothesis_id="H-001",
            test_name="test_drain_pool",
            test_file="test/Exploit.t.sol",
            compiled=True,
            passed=False,
            error="Revert: ReentrancyGuard",
        )
        assert r.passed is False
        assert r.gas_used is None


# ---------------------------------------------------------------------------
# VulnReport
# ---------------------------------------------------------------------------


class TestVulnReport:
    def _make_report(self) -> VulnReport:
        return VulnReport(
            title="Reentrancy in Vault.withdraw()",
            severity=Severity.CRITICAL,
            target_protocol="ExampleFi",
            target_contracts=["Vault", "VaultProxy"],
            summary="Reentrancy allows draining the vault.",
            vulnerability_detail="The withdraw function sends ETH before updating state.",
            impact_detail="Complete loss of deposited funds.",
            attack_scenario="Attacker deploys contract that re-enters withdraw().",
            poc_code="contract Exploit { ... }",
            remediation="Apply checks-effects-interactions pattern.",
            references=["https://swcregistry.io/docs/SWC-107"],
            immunefi_program="examplefi",
        )

    def test_creation(self):
        r = self._make_report()
        assert r.poc_result is None
        assert isinstance(r.created_at, datetime)

    def test_serialization_to_dict(self):
        r = self._make_report()
        d = r.model_dump()
        assert isinstance(d, dict)
        assert d["severity"] == "critical"
        assert d["target_contracts"] == ["Vault", "VaultProxy"]
        assert isinstance(d["created_at"], datetime)

    def test_serialization_to_json(self):
        r = self._make_report()
        j = r.model_dump_json()
        parsed = json.loads(j)
        assert parsed["title"] == "Reentrancy in Vault.withdraw()"
        assert parsed["severity"] == "critical"
        assert isinstance(parsed["created_at"], str)

    def test_roundtrip(self):
        original = self._make_report()
        j = original.model_dump_json()
        restored = VulnReport.model_validate_json(j)
        assert restored.title == original.title
        assert restored.severity == original.severity


# ---------------------------------------------------------------------------
# ScanConfig
# ---------------------------------------------------------------------------


class TestScanConfig:
    def test_defaults(self):
        cfg = ScanConfig(target="https://github.com/example/protocol")
        assert cfg.scope_contracts == []
        assert cfg.exclude_patterns == [
            "test/",
            "script/",
            "lib/",
            "node_modules/",
        ]
        assert cfg.solc_version is None
        assert cfg.min_severity == Severity.LOW
        assert cfg.min_confidence == 0.3
        assert cfg.fork_url is None
        assert cfg.fork_block is None
        assert cfg.immunefi_program is None

    def test_custom_values(self):
        cfg = ScanConfig(
            target="https://github.com/example/protocol",
            scope_contracts=["Vault.sol", "Router.sol"],
            exclude_patterns=["test/"],
            solc_version="0.8.20",
            min_severity=Severity.HIGH,
            min_confidence=0.7,
            fork_url="https://eth-mainnet.g.alchemy.com/v2/KEY",
            fork_block=18_000_000,
            immunefi_program="examplefi",
        )
        assert cfg.min_severity == Severity.HIGH
        assert cfg.fork_block == 18_000_000

    def test_exclude_patterns_are_independent(self):
        """Each ScanConfig instance gets its own list (no shared mutable default)."""
        a = ScanConfig(target="a")
        b = ScanConfig(target="b")
        a.exclude_patterns.append("custom/")
        assert "custom/" not in b.exclude_patterns
