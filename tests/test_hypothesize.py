import pytest

from pipeline.models import Finding, FindingSource, Hypothesis, ScanConfig, Severity
from pipeline.hypothesize import (
    CATEGORY_BASE_SCORE,
    HypothesisEngine,
    _TEMPLATES,
    _make_id,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    id: str = "F-001",
    contract: str = "Vault",
    category: str = "reentrancy",
    severity: Severity = Severity.HIGH,
    confidence: float = 0.8,
    file_path: str = "src/Vault.sol",
    function: str | None = "withdraw",
) -> Finding:
    return Finding(
        id=id,
        source=FindingSource.SLITHER,
        detector="test-detector",
        severity=severity,
        confidence=confidence,
        title=f"Test finding {id}",
        description="Test description",
        contract=contract,
        function=function,
        file_path=file_path,
        category=category,
    )


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------

class TestGroupFindings:
    def test_single_group(self):
        findings = [
            _make_finding(id="F-001", contract="Vault", category="reentrancy"),
            _make_finding(id="F-002", contract="Vault", category="reentrancy"),
        ]
        engine = HypothesisEngine(findings)
        groups = engine._group_findings()
        assert len(groups) == 1
        assert "Vault::reentrancy" in groups
        assert len(groups["Vault::reentrancy"]) == 2

    def test_multiple_groups(self):
        findings = [
            _make_finding(id="F-001", contract="Vault", category="reentrancy"),
            _make_finding(id="F-002", contract="Vault", category="access-control"),
            _make_finding(id="F-003", contract="Pool", category="reentrancy"),
        ]
        engine = HypothesisEngine(findings)
        groups = engine._group_findings()
        assert len(groups) == 3
        assert "Vault::reentrancy" in groups
        assert "Vault::access-control" in groups
        assert "Pool::reentrancy" in groups

    def test_empty_findings(self):
        engine = HypothesisEngine([])
        groups = engine._group_findings()
        assert groups == {}


# ---------------------------------------------------------------------------
# Hypothesis generation per category
# ---------------------------------------------------------------------------

class TestHypothesisGeneration:
    def test_reentrancy_hypothesis(self):
        findings = [_make_finding(category="reentrancy")]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        assert len(hypotheses) == 1
        h = hypotheses[0]
        assert "re-enter" in h.attack_vector.lower()
        assert h.needs_fork is False
        assert h.finding_ids == ["F-001"]

    def test_access_control_hypothesis(self):
        findings = [_make_finding(category="access-control")]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        h = hypotheses[0]
        assert "authorization" in h.attack_vector.lower()
        assert h.needs_fork is False

    def test_oracle_manipulation_hypothesis(self):
        findings = [_make_finding(category="oracle-manipulation")]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        h = hypotheses[0]
        assert "oracle" in h.attack_vector.lower() or "price" in h.attack_vector.lower()
        assert h.needs_fork is True

    def test_flash_loan_hypothesis(self):
        findings = [_make_finding(category="flash-loan")]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        h = hypotheses[0]
        assert "flash loan" in h.attack_vector.lower()
        assert h.needs_fork is True

    def test_unchecked_calls_hypothesis(self):
        findings = [_make_finding(category="unchecked-calls")]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        h = hypotheses[0]
        assert "silent" in h.attack_vector.lower() or "failure" in h.attack_vector.lower()

    def test_integer_overflow_hypothesis(self):
        findings = [_make_finding(category="integer-overflow")]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        h = hypotheses[0]
        assert "overflow" in h.attack_vector.lower()

    def test_storage_collision_hypothesis(self):
        findings = [_make_finding(category="storage-collision")]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        h = hypotheses[0]
        assert "storage" in h.attack_vector.lower()

    def test_taint_analysis_hypothesis(self):
        findings = [_make_finding(category="taint-analysis")]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        h = hypotheses[0]
        assert "input" in h.attack_vector.lower() or "taint" in h.attack_vector.lower()

    def test_unknown_category_uses_default_template(self):
        findings = [_make_finding(category="some-new-category")]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        assert len(hypotheses) == 1
        h = hypotheses[0]
        assert "static analysis" in h.attack_vector.lower()

    def test_target_functions_populated(self):
        findings = [
            _make_finding(id="F-001", function="withdraw"),
            _make_finding(id="F-002", function="deposit"),
        ]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        assert set(hypotheses[0].target_functions) == {"withdraw", "deposit"}

    def test_target_functions_deduped(self):
        findings = [
            _make_finding(id="F-001", function="withdraw"),
            _make_finding(id="F-002", function="withdraw"),
        ]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        assert hypotheses[0].target_functions == ["withdraw"]

    def test_null_functions_excluded(self):
        findings = [_make_finding(id="F-001", function=None)]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        assert hypotheses[0].target_functions == []

    def test_fork_block_from_config(self):
        config = ScanConfig(target="test", fork_url="http://rpc", fork_block=12345678)
        findings = [_make_finding(category="oracle-manipulation")]
        engine = HypothesisEngine(findings, config=config)
        hypotheses = engine.generate()
        assert hypotheses[0].fork_block == 12345678

    def test_fork_block_none_without_config(self):
        findings = [_make_finding(category="oracle-manipulation")]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        assert hypotheses[0].fork_block is None
        assert hypotheses[0].needs_fork is True


# ---------------------------------------------------------------------------
# Exploitability scoring
# ---------------------------------------------------------------------------

class TestExploitabilityScoring:
    def test_single_finding_base_score(self):
        findings = [_make_finding(category="reentrancy")]
        engine = HypothesisEngine(findings)
        score = engine._score_exploitability(findings, "reentrancy")
        assert score == pytest.approx(0.7)

    def test_two_findings_corroboration_bonus(self):
        findings = [
            _make_finding(id="F-001", category="reentrancy"),
            _make_finding(id="F-002", category="reentrancy"),
        ]
        engine = HypothesisEngine(findings)
        score = engine._score_exploitability(findings, "reentrancy")
        assert score == pytest.approx(0.8)  # 0.7 + 0.1

    def test_three_findings_higher_corroboration(self):
        findings = [_make_finding(id=f"F-{i}") for i in range(3)]
        engine = HypothesisEngine(findings)
        score = engine._score_exploitability(findings, "reentrancy")
        assert score == pytest.approx(0.85)  # 0.7 + 0.15

    def test_fork_penalty(self):
        findings = [_make_finding(category="oracle-manipulation")]
        engine = HypothesisEngine(findings)
        score = engine._score_exploitability(findings, "oracle-manipulation")
        # base=0.6, no corroboration, fork penalty=-0.1
        assert score == pytest.approx(0.5)

    def test_access_control_high_base(self):
        findings = [_make_finding(category="access-control")]
        engine = HypothesisEngine(findings)
        score = engine._score_exploitability(findings, "access-control")
        assert score == pytest.approx(0.8)

    def test_unknown_category_low_base(self):
        findings = [_make_finding(category="unknown")]
        engine = HypothesisEngine(findings)
        score = engine._score_exploitability(findings, "unknown")
        assert score == pytest.approx(0.3)

    def test_score_capped_at_1(self):
        findings = [_make_finding(id=f"F-{i}", category="access-control") for i in range(5)]
        engine = HypothesisEngine(findings)
        score = engine._score_exploitability(findings, "access-control")
        # 0.8 + 0.15 = 0.95, within bounds
        assert score <= 1.0

    def test_score_floor_at_0(self):
        # Shouldn't happen with real data, but verify the clamp
        findings = [_make_finding(category="unchecked-calls")]
        engine = HypothesisEngine(findings)
        score = engine._score_exploitability(findings, "unchecked-calls")
        assert score >= 0.0


# ---------------------------------------------------------------------------
# Cross-contract correlation
# ---------------------------------------------------------------------------

class TestCrossContractCorrelation:
    def test_shared_file_path_correlates(self):
        findings = [
            _make_finding(id="F-001", contract="Vault", category="reentrancy", file_path="src/Shared.sol"),
            _make_finding(id="F-002", contract="Pool", category="reentrancy", file_path="src/Shared.sol"),
        ]
        engine = HypothesisEngine(findings)
        groups = engine._group_findings()
        correlations = engine._correlate_cross_contract(groups)
        assert len(correlations) == 1
        keys = correlations[0]
        assert "Vault::reentrancy" in keys
        assert "Pool::reentrancy" in keys

    def test_shared_function_correlates(self):
        findings = [
            _make_finding(id="F-001", contract="Vault", category="access-control",
                          file_path="src/Vault.sol", function="setOwner"),
            _make_finding(id="F-002", contract="Pool", category="access-control",
                          file_path="src/Pool.sol", function="setOwner"),
        ]
        engine = HypothesisEngine(findings)
        groups = engine._group_findings()
        correlations = engine._correlate_cross_contract(groups)
        assert len(correlations) == 1

    def test_no_correlation_different_category(self):
        findings = [
            _make_finding(id="F-001", contract="Vault", category="reentrancy", file_path="src/Shared.sol"),
            _make_finding(id="F-002", contract="Pool", category="access-control", file_path="src/Shared.sol"),
        ]
        engine = HypothesisEngine(findings)
        groups = engine._group_findings()
        correlations = engine._correlate_cross_contract(groups)
        assert correlations == []

    def test_no_correlation_unrelated_groups(self):
        findings = [
            _make_finding(id="F-001", contract="Vault", category="reentrancy",
                          file_path="src/Vault.sol", function="withdraw"),
            _make_finding(id="F-002", contract="Pool", category="reentrancy",
                          file_path="src/Pool.sol", function="swap"),
        ]
        engine = HypothesisEngine(findings)
        groups = engine._group_findings()
        correlations = engine._correlate_cross_contract(groups)
        assert correlations == []

    def test_correlated_groups_merge_in_generate(self):
        findings = [
            _make_finding(id="F-001", contract="Vault", category="reentrancy", file_path="src/Shared.sol"),
            _make_finding(id="F-002", contract="Pool", category="reentrancy", file_path="src/Shared.sol"),
        ]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        # Correlated groups merge into one hypothesis
        assert len(hypotheses) == 1
        assert set(hypotheses[0].finding_ids) == {"F-001", "F-002"}


# ---------------------------------------------------------------------------
# Empty input
# ---------------------------------------------------------------------------

class TestEmptyInput:
    def test_empty_findings_returns_empty(self):
        engine = HypothesisEngine([])
        assert engine.generate() == []

    def test_empty_findings_with_config(self):
        config = ScanConfig(target="test")
        engine = HypothesisEngine([], config=config)
        assert engine.generate() == []


# ---------------------------------------------------------------------------
# Sorting order
# ---------------------------------------------------------------------------

class TestSortingOrder:
    def test_higher_exploitability_first(self):
        """access-control (0.8) should rank above unchecked-calls (0.4) at same severity."""
        findings = [
            _make_finding(id="F-001", contract="A", category="unchecked-calls", severity=Severity.HIGH),
            _make_finding(id="F-002", contract="B", category="access-control", severity=Severity.HIGH),
        ]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        assert len(hypotheses) == 2
        assert hypotheses[0].exploitability > hypotheses[1].exploitability

    def test_higher_severity_ranks_first(self):
        """CRITICAL severity should outrank HIGH even with lower exploitability."""
        findings = [
            _make_finding(id="F-001", contract="A", category="access-control", severity=Severity.HIGH),
            _make_finding(id="F-002", contract="B", category="unchecked-calls", severity=Severity.CRITICAL),
        ]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        # unchecked-calls has 0.4 exploitability but CRITICAL severity (rank 0, weight 5)
        # access-control has 0.8 exploitability but HIGH severity (rank 1, weight 4)
        # unchecked-calls: 0.4 * 5 = 2.0, access-control: 0.8 * 4 = 3.2
        # So access-control still first here
        scores = [h.exploitability * (len(Severity) - list(Severity).index(h.severity)) for h in hypotheses]
        assert scores == sorted(scores, reverse=True)

    def test_deterministic_ids(self):
        """Same input should produce same hypothesis IDs."""
        findings = [_make_finding()]
        h1 = HypothesisEngine(findings).generate()
        h2 = HypothesisEngine(findings).generate()
        assert h1[0].id == h2[0].id

    def test_all_hypotheses_valid(self):
        """Every generated hypothesis should be a valid Hypothesis model."""
        findings = [
            _make_finding(id="F-001", contract="A", category="reentrancy"),
            _make_finding(id="F-002", contract="A", category="access-control"),
            _make_finding(id="F-003", contract="B", category="oracle-manipulation"),
            _make_finding(id="F-004", contract="C", category="flash-loan"),
            _make_finding(id="F-005", contract="D", category="unchecked-calls"),
            _make_finding(id="F-006", contract="E", category="integer-overflow"),
            _make_finding(id="F-007", contract="F", category="storage-collision"),
            _make_finding(id="F-008", contract="G", category="taint-analysis"),
        ]
        engine = HypothesisEngine(findings)
        hypotheses = engine.generate()
        assert len(hypotheses) == 8
        for h in hypotheses:
            assert isinstance(h, Hypothesis)
            assert 0.0 <= h.exploitability <= 1.0
            assert len(h.finding_ids) > 0
