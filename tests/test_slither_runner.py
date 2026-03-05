import json
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzers.slither_runner import parse_slither_json
from pipeline.models import FindingSource, Severity

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class TestParseSlitherJson:
    def test_parses_all_detectors(self):
        findings = parse_slither_json(FIXTURES_DIR / "slither_output.json")
        assert len(findings) == 7

    def test_reentrancy_finding(self):
        findings = parse_slither_json(FIXTURES_DIR / "slither_output.json")
        reentrancy = findings[0]

        assert reentrancy.source == FindingSource.SLITHER
        assert reentrancy.detector == "reentrancy-eth"
        assert reentrancy.severity == Severity.HIGH
        assert reentrancy.confidence == 0.6  # Medium confidence
        assert reentrancy.category == "reentrancy"
        assert reentrancy.contract == "Vault"
        assert reentrancy.function == "withdraw"
        assert reentrancy.file_path == "src/Vault.sol"
        assert reentrancy.line_start == 45
        assert "reentrancy-eth" in reentrancy.id

    def test_arbitrary_send_finding(self):
        findings = parse_slither_json(FIXTURES_DIR / "slither_output.json")
        arb_send = findings[1]

        assert arb_send.detector == "arbitrary-send-eth"
        assert arb_send.severity == Severity.HIGH
        assert arb_send.confidence == 0.9  # High confidence
        assert arb_send.category == "access-control"
        assert arb_send.contract == "Vault"
        assert arb_send.function == "emergencyWithdraw"

    def test_divide_before_multiply(self):
        findings = parse_slither_json(FIXTURES_DIR / "slither_output.json")
        dbm = findings[2]

        assert dbm.detector == "divide-before-multiply"
        assert dbm.severity == Severity.MEDIUM
        assert dbm.category == "integer-overflow"
        assert dbm.contract == "PriceOracle"
        assert dbm.function == "getPrice"

    def test_unchecked_lowlevel(self):
        findings = parse_slither_json(FIXTURES_DIR / "slither_output.json")
        unchecked = findings[3]

        assert unchecked.detector == "unchecked-lowlevel"
        assert unchecked.severity == Severity.MEDIUM
        assert unchecked.category == "unchecked-calls"
        assert unchecked.contract == "TokenBridge"

    def test_suicidal_finding(self):
        findings = parse_slither_json(FIXTURES_DIR / "slither_output.json")
        suicidal = findings[4]

        assert suicidal.detector == "suicidal"
        assert suicidal.severity == Severity.HIGH
        assert suicidal.confidence == 0.9
        assert suicidal.category == "access-control"

    def test_controlled_delegatecall(self):
        findings = parse_slither_json(FIXTURES_DIR / "slither_output.json")
        delegatecall = findings[5]

        assert delegatecall.detector == "controlled-delegatecall"
        assert delegatecall.category == "access-control"
        assert delegatecall.contract == "Proxy"

    def test_uninitialized_storage(self):
        findings = parse_slither_json(FIXTURES_DIR / "slither_output.json")
        uninit = findings[6]

        assert uninit.detector == "uninitialized-storage"
        assert uninit.category == "storage-collision"
        assert uninit.contract == "StakingPool"

    def test_finding_id_format(self):
        findings = parse_slither_json(FIXTURES_DIR / "slither_output.json")
        for i, f in enumerate(findings):
            assert f.id.startswith(f"SLITH-{i:04d}-")

    def test_finding_source_is_slither(self):
        findings = parse_slither_json(FIXTURES_DIR / "slither_output.json")
        for f in findings:
            assert f.source == FindingSource.SLITHER

    def test_nonexistent_file_returns_empty(self):
        findings = parse_slither_json("/nonexistent/path.json")
        assert findings == []

    def test_title_contains_detector(self):
        findings = parse_slither_json(FIXTURES_DIR / "slither_output.json")
        for f in findings:
            assert f.detector in f.title

    def test_description_is_populated(self):
        findings = parse_slither_json(FIXTURES_DIR / "slither_output.json")
        for f in findings:
            assert len(f.description) > 0

    def test_severity_mapping_completeness(self):
        """All severity values in fixture map to valid Severity enum."""
        findings = parse_slither_json(FIXTURES_DIR / "slither_output.json")
        valid_severities = set(Severity)
        for f in findings:
            assert f.severity in valid_severities

    def test_confidence_range(self):
        """All confidence values are between 0 and 1."""
        findings = parse_slither_json(FIXTURES_DIR / "slither_output.json")
        for f in findings:
            assert 0.0 <= f.confidence <= 1.0

    def test_code_snippet_from_source_mapping(self):
        findings = parse_slither_json(FIXTURES_DIR / "slither_output.json")
        # First finding (reentrancy) has content in source_mapping
        reentrancy = findings[0]
        assert "withdraw" in reentrancy.code_snippet

    def test_unknown_detector_maps_to_other(self):
        """Detectors not in DETECTOR_CATEGORY_MAP get 'other' category."""
        data = {
            "results": {
                "detectors": [
                    {
                        "check": "some-unknown-check",
                        "impact": "Low",
                        "confidence": "Low",
                        "description": "Unknown detector test",
                        "elements": [
                            {
                                "type": "contract",
                                "name": "Test",
                                "source_mapping": {
                                    "filename_relative": "test.sol",
                                    "lines": [1],
                                    "content": "",
                                },
                            }
                        ],
                    }
                ]
            }
        }
        import tempfile

        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w"
        ) as f:
            json.dump(data, f)
            tmp_path = f.name

        findings = parse_slither_json(tmp_path)
        assert len(findings) == 1
        assert findings[0].category == "other"
        Path(tmp_path).unlink()
