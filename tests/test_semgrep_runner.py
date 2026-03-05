import json
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzers.semgrep_runner import parse_semgrep_json
from pipeline.models import FindingSource, Severity

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def load_fixture():
    with open(FIXTURES_DIR / "semgrep_output.json") as f:
        return json.load(f)


class TestParseSemgrepJson:
    def test_parses_all_results(self):
        data = load_fixture()
        findings = parse_semgrep_json(data)
        assert len(findings) == 6

    def test_reentrancy_finding(self):
        data = load_fixture()
        findings = parse_semgrep_json(data)
        reentrancy = findings[0]

        assert reentrancy.source == FindingSource.SEMGREP
        assert reentrancy.detector == "solidity.reentrancy.external-call-before-state-update"
        assert reentrancy.severity == Severity.HIGH  # ERROR -> HIGH
        assert reentrancy.confidence == 0.9  # high
        assert reentrancy.category == "reentrancy"
        assert reentrancy.file_path == "src/Vault.sol"
        assert reentrancy.line_start == 48
        assert reentrancy.line_end == 52
        assert "call{value:" in reentrancy.code_snippet

    def test_access_control_finding(self):
        data = load_fixture()
        findings = parse_semgrep_json(data)
        ac = findings[1]

        assert ac.detector == "solidity.access-control.unprotected-selfdestruct"
        assert ac.severity == Severity.HIGH
        assert ac.category == "access-control"
        assert ac.file_path == "src/Implementation.sol"
        assert ac.line_start == 10
        assert "selfdestruct" in ac.code_snippet

    def test_oracle_finding(self):
        data = load_fixture()
        findings = parse_semgrep_json(data)
        oracle = findings[2]

        assert oracle.detector == "solidity.oracle.stale-price-no-updatedAt-check"
        assert oracle.severity == Severity.HIGH
        assert oracle.category == "oracle-manipulation"
        assert "latestRoundData" in oracle.code_snippet

    def test_unchecked_erc20_transfer(self):
        data = load_fixture()
        findings = parse_semgrep_json(data)
        transfer = findings[3]

        assert transfer.severity == Severity.MEDIUM  # WARNING -> MEDIUM
        assert transfer.category == "unchecked-calls"
        assert transfer.confidence == 0.9  # high

    def test_integer_overflow_downcast(self):
        data = load_fixture()
        findings = parse_semgrep_json(data)
        downcast = findings[4]

        assert downcast.category == "integer-overflow"
        assert downcast.severity == Severity.MEDIUM
        assert downcast.confidence == 0.6  # medium

    def test_flash_loan_finding(self):
        data = load_fixture()
        findings = parse_semgrep_json(data)
        flash = findings[5]

        assert flash.category == "flash-loan"
        assert flash.severity == Severity.HIGH
        assert "balanceOf" in flash.code_snippet

    def test_finding_id_format(self):
        data = load_fixture()
        findings = parse_semgrep_json(data)
        for i, f in enumerate(findings):
            assert f.id.startswith(f"SGRP-{i:04d}-")

    def test_finding_source_is_semgrep(self):
        data = load_fixture()
        findings = parse_semgrep_json(data)
        for f in findings:
            assert f.source == FindingSource.SEMGREP

    def test_contract_name_from_path(self):
        data = load_fixture()
        findings = parse_semgrep_json(data)
        # Contract name extracted from path stem
        assert findings[0].contract == "Vault"
        assert findings[1].contract == "Implementation"
        assert findings[2].contract == "PriceOracle"

    def test_empty_results_returns_empty(self):
        data = {"results": [], "errors": []}
        findings = parse_semgrep_json(data)
        assert findings == []

    def test_missing_results_key_returns_empty(self):
        data = {"errors": []}
        findings = parse_semgrep_json(data)
        assert findings == []

    def test_title_contains_rule_id(self):
        data = load_fixture()
        findings = parse_semgrep_json(data)
        for f in findings:
            assert f.detector in f.title or f.detector.split(".")[-1] in f.title

    def test_description_matches_message(self):
        data = load_fixture()
        findings = parse_semgrep_json(data)
        for f in findings:
            assert len(f.description) > 0

    def test_severity_mapping(self):
        """ERROR->HIGH, WARNING->MEDIUM, INFO->LOW."""
        data = load_fixture()
        findings = parse_semgrep_json(data)
        # First three are ERROR -> HIGH
        assert findings[0].severity == Severity.HIGH
        assert findings[1].severity == Severity.HIGH
        assert findings[2].severity == Severity.HIGH
        # Fourth is WARNING -> MEDIUM
        assert findings[3].severity == Severity.MEDIUM

    def test_confidence_range(self):
        data = load_fixture()
        findings = parse_semgrep_json(data)
        for f in findings:
            assert 0.0 <= f.confidence <= 1.0

    def test_raw_output_preserved(self):
        data = load_fixture()
        findings = parse_semgrep_json(data)
        for f in findings:
            assert isinstance(f.raw_output, dict)
            assert "check_id" in f.raw_output

    def test_default_confidence_for_unknown(self):
        """Unknown confidence string defaults to 0.5."""
        data = {
            "results": [
                {
                    "check_id": "test.rule",
                    "path": "test.sol",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {
                        "severity": "INFO",
                        "message": "Test finding",
                        "lines": "test code",
                        "metadata": {
                            "category": "test",
                            "confidence": "unknown-level",
                        },
                    },
                }
            ]
        }
        findings = parse_semgrep_json(data)
        assert len(findings) == 1
        assert findings[0].confidence == 0.5
