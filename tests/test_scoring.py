import pytest

from pipeline.models import Finding, FindingSource, Severity, sev_rank
from pipeline.scoring import (
    CATEGORY_SEVERITY,
    score_finding,
    severity_to_immunefi,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    category: str = "reentrancy",
    confidence: float = 0.8,
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        id="F-001",
        source=FindingSource.SLITHER,
        detector="test-detector",
        severity=severity,
        confidence=confidence,
        title="Test finding",
        description="Test description",
        contract="TestContract",
        file_path="src/Test.sol",
        category=category,
    )


# ---------------------------------------------------------------------------
# score_finding
# ---------------------------------------------------------------------------


class TestScoreFinding:
    def test_boosts_confidence_for_reentrancy(self):
        f = _make_finding(category="reentrancy", confidence=0.8)
        scored = score_finding(f)
        assert scored.confidence == pytest.approx(0.8 * 1.2)

    def test_boosts_confidence_for_storage_collision(self):
        f = _make_finding(category="storage-collision", confidence=0.7)
        scored = score_finding(f)
        assert scored.confidence == pytest.approx(0.7 * 1.2)

    def test_boosts_confidence_for_access_control(self):
        f = _make_finding(category="access-control", confidence=0.5)
        scored = score_finding(f)
        assert scored.confidence == pytest.approx(0.5 * 1.2)

    def test_confidence_capped_at_1(self):
        f = _make_finding(category="reentrancy", confidence=0.95)
        scored = score_finding(f)
        assert scored.confidence == 1.0

    def test_no_modification_for_unknown_category(self):
        f = _make_finding(category="unknown-category", confidence=0.5)
        scored = score_finding(f)
        assert scored.confidence == 0.5
        assert scored.severity == f.severity

    def test_no_modification_for_non_boosted_known_category(self):
        """Categories like 'flash-loan' are in CATEGORY_SEVERITY but not in the boost list."""
        f = _make_finding(category="flash-loan", confidence=0.6)
        scored = score_finding(f)
        assert scored.confidence == 0.6

    def test_returns_new_model_instance(self):
        """score_finding should not mutate the original Finding."""
        f = _make_finding(category="reentrancy", confidence=0.8)
        scored = score_finding(f)
        assert f.confidence == 0.8  # original unchanged
        assert scored is not f


# ---------------------------------------------------------------------------
# sev_rank
# ---------------------------------------------------------------------------


class TestSevRank:
    def test_critical_is_lowest_rank(self):
        assert sev_rank(Severity.CRITICAL) == 0

    def test_info_is_highest_rank(self):
        assert sev_rank(Severity.INFO) == 4

    def test_ordering(self):
        ranks = [sev_rank(s) for s in Severity]
        assert ranks == [0, 1, 2, 3, 4]

    def test_critical_less_than_high(self):
        assert sev_rank(Severity.CRITICAL) < sev_rank(Severity.HIGH)

    def test_high_less_than_medium(self):
        assert sev_rank(Severity.HIGH) < sev_rank(Severity.MEDIUM)


# ---------------------------------------------------------------------------
# severity_to_immunefi
# ---------------------------------------------------------------------------


class TestSeverityToImmunefi:
    def test_all_mappings(self):
        assert severity_to_immunefi(Severity.CRITICAL) == "Critical"
        assert severity_to_immunefi(Severity.HIGH) == "High"
        assert severity_to_immunefi(Severity.MEDIUM) == "Medium"
        assert severity_to_immunefi(Severity.LOW) == "Low"
        assert severity_to_immunefi(Severity.INFO) == "Informational"

    def test_returns_string(self):
        for sev in Severity:
            result = severity_to_immunefi(sev)
            assert isinstance(result, str)
