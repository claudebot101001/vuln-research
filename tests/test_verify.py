import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pipeline.models import Hypothesis, PoCResult, Severity
from pipeline.verify import TEMPLATE_MAP, Verifier, _test_name_from_template


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_hypothesis(
    attack_vector: str = "reentrancy",
    target_functions: list[str] | None = None,
    **overrides,
) -> Hypothesis:
    defaults = {
        "id": "H-001",
        "finding_ids": ["F-001"],
        "attack_vector": attack_vector,
        "preconditions": ["No reentrancy guard"],
        "impact": "Drain funds",
        "severity": Severity.HIGH,
        "exploitability": 0.8,
        "poc_strategy": "Forge test with reentrancy callback",
        "target_functions": target_functions or ["withdraw"],
    }
    defaults.update(overrides)
    return Hypothesis(**defaults)


# ---------------------------------------------------------------------------
# Template selection
# ---------------------------------------------------------------------------

class TestTemplateSelection:
    def test_reentrancy_vector(self):
        v = Verifier()
        h = _make_hypothesis(attack_vector="reentrancy in withdraw()")
        assert v.select_template(h) == "reentrancy_poc.sol.j2"

    def test_flash_loan_vector(self):
        v = Verifier()
        h = _make_hypothesis(attack_vector="flash_loan price manipulation")
        assert v.select_template(h) == "flash_loan_poc.sol.j2"

    def test_flash_loan_hyphenated(self):
        v = Verifier()
        h = _make_hypothesis(attack_vector="flash-loan attack")
        assert v.select_template(h) == "flash_loan_poc.sol.j2"

    def test_access_control_vector(self):
        v = Verifier()
        h = _make_hypothesis(attack_vector="access_control bypass")
        assert v.select_template(h) == "access_control_poc.sol.j2"

    def test_access_control_hyphenated(self):
        v = Verifier()
        h = _make_hypothesis(attack_vector="access-control missing modifier")
        assert v.select_template(h) == "access_control_poc.sol.j2"

    def test_oracle_manipulation_vector(self):
        v = Verifier()
        h = _make_hypothesis(attack_vector="oracle manipulation via TWAP")
        assert v.select_template(h) == "oracle_manipulation_poc.sol.j2"

    def test_integer_overflow_vector(self):
        v = Verifier()
        h = _make_hypothesis(attack_vector="integer_overflow in balance calculation")
        assert v.select_template(h) == "integer_overflow_poc.sol.j2"

    def test_overflow_keyword(self):
        v = Verifier()
        h = _make_hypothesis(attack_vector="arithmetic overflow")
        assert v.select_template(h) == "integer_overflow_poc.sol.j2"

    def test_underflow_keyword(self):
        v = Verifier()
        h = _make_hypothesis(attack_vector="underflow in withdrawal")
        assert v.select_template(h) == "integer_overflow_poc.sol.j2"

    def test_unknown_vector_returns_none(self):
        v = Verifier()
        h = _make_hypothesis(attack_vector="novel zero-day exploit")
        assert v.select_template(h) is None

    def test_case_insensitive(self):
        v = Verifier()
        h = _make_hypothesis(attack_vector="REENTRANCY ATTACK")
        assert v.select_template(h) == "reentrancy_poc.sol.j2"


# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------

class TestTemplateRendering:
    def test_render_reentrancy(self, tmp_path):
        v = Verifier(output_dir=tmp_path)
        h = _make_hypothesis(attack_vector="reentrancy")
        params = {"target_contract": "0x1234", "attack_value": "1 ether"}

        test_file = v.render_poc(h, params)

        assert test_file is not None
        assert test_file.exists()
        assert test_file.suffix == ".sol"
        content = test_file.read_text()
        assert "ReentrancyExploitTest" in content
        assert "withdraw" in content

    def test_render_access_control(self, tmp_path):
        v = Verifier(output_dir=tmp_path)
        h = _make_hypothesis(
            attack_vector="access-control",
            target_functions=["setAdmin"],
        )
        params = {"target_contract": "0xABCD"}

        test_file = v.render_poc(h, params)

        assert test_file is not None
        content = test_file.read_text()
        assert "AccessControlExploitTest" in content
        assert "setAdmin" in content

    def test_render_returns_none_for_unknown(self, tmp_path):
        v = Verifier(output_dir=tmp_path)
        h = _make_hypothesis(attack_vector="unknown exploit type")
        assert v.render_poc(h) is None

    def test_render_flash_loan(self, tmp_path):
        v = Verifier(output_dir=tmp_path)
        h = _make_hypothesis(attack_vector="flash_loan")
        params = {
            "target_contract": "0x5678",
            "flash_token": "0xAAAA",
            "flash_amount": "1000000 * 1e6",
        }

        test_file = v.render_poc(h, params)

        assert test_file is not None
        content = test_file.read_text()
        assert "FlashLoanExploitTest" in content


# ---------------------------------------------------------------------------
# Forge output parsing
# ---------------------------------------------------------------------------

FORGE_PASS_OUTPUT = """\
Compiling 1 files with Solc 0.8.20
Compiler run successful
Running 1 test for test/Exploit.t.sol:ReentrancyExploitTest
[PASS] test_reentrancy_exploit() (gas: 250000)
Test result: ok. 1 passed; 0 failed; finished in 1.23s
"""

FORGE_FAIL_OUTPUT = """\
Compiling 1 files with Solc 0.8.20
Compiler run successful
Running 1 test for test/Exploit.t.sol:ReentrancyExploitTest
[FAIL. Reason: Revert: ReentrancyGuard] test_reentrancy_exploit() (gas: 150000)
Test result: FAILED. 0 passed; 1 failed; finished in 0.85s
"""

FORGE_COMPILE_FAIL_OUTPUT = """\
Error:
Compiler run failed:
Error (6275): DeclarationError: Undeclared identifier.
"""


class TestForgeOutputParsing:
    def test_parse_passing_test(self, tmp_path):
        v = Verifier(output_dir=tmp_path)
        test_file = tmp_path / "H-001.t.sol"
        test_file.write_text("// placeholder")

        result = v._parse_forge_output(
            stdout=FORGE_PASS_OUTPUT,
            test_file=test_file,
            match_test="test_reentrancy_exploit",
        )

        assert result.compiled is True
        assert result.passed is True
        assert result.gas_used == 250000
        assert result.error is None

    def test_parse_failing_test(self, tmp_path):
        v = Verifier(output_dir=tmp_path)
        test_file = tmp_path / "H-002.t.sol"
        test_file.write_text("// placeholder")

        result = v._parse_forge_output(
            stdout=FORGE_FAIL_OUTPUT,
            test_file=test_file,
            match_test="test_reentrancy_exploit",
        )

        assert result.compiled is True
        assert result.passed is False
        assert result.gas_used == 150000
        assert result.error is not None
        assert "ReentrancyGuard" in result.error

    def test_parse_compilation_failure(self, tmp_path):
        v = Verifier(output_dir=tmp_path)
        test_file = tmp_path / "H-003.t.sol"
        test_file.write_text("// placeholder")

        result = v._parse_forge_output(
            stdout=FORGE_COMPILE_FAIL_OUTPUT,
            test_file=test_file,
            match_test="test_exploit",
        )

        assert result.compiled is False
        assert result.passed is False
        assert result.error is not None
        assert "failed" in result.error.lower()


# ---------------------------------------------------------------------------
# run_forge with mocked subprocess
# ---------------------------------------------------------------------------

class TestRunForge:
    @patch("shutil.which", return_value=None)
    def test_forge_not_in_path(self, mock_which, tmp_path):
        v = Verifier(output_dir=tmp_path)
        test_file = tmp_path / "H-001.t.sol"
        test_file.write_text("// placeholder")

        result = v.run_forge(test_file, match_test="test_exploit")

        assert result.compiled is False
        assert result.passed is False
        assert "forge not found" in result.error

    @patch("shutil.which", return_value="/usr/bin/forge")
    @patch("subprocess.run")
    def test_forge_pass(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = MagicMock(
            stdout=FORGE_PASS_OUTPUT,
            stderr="",
            returncode=0,
        )

        v = Verifier(output_dir=tmp_path)
        test_file = tmp_path / "H-001.t.sol"
        test_file.write_text("// placeholder")

        result = v.run_forge(test_file, match_test="test_reentrancy_exploit")

        assert result.passed is True
        assert result.gas_used == 250000
        mock_run.assert_called_once()

    @patch("shutil.which", return_value="/usr/bin/forge")
    @patch("subprocess.run")
    def test_forge_fail(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = MagicMock(
            stdout=FORGE_FAIL_OUTPUT,
            stderr="",
            returncode=1,
        )

        v = Verifier(output_dir=tmp_path)
        test_file = tmp_path / "H-001.t.sol"
        test_file.write_text("// placeholder")

        result = v.run_forge(test_file, match_test="test_reentrancy_exploit")

        assert result.passed is False
        assert "ReentrancyGuard" in result.error

    @patch("shutil.which", return_value="/usr/bin/forge")
    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="forge", timeout=300))
    def test_forge_timeout(self, mock_run, mock_which, tmp_path):
        v = Verifier(output_dir=tmp_path)
        test_file = tmp_path / "H-001.t.sol"
        test_file.write_text("// placeholder")

        result = v.run_forge(test_file, match_test="test_exploit")

        assert result.compiled is False
        assert result.passed is False
        assert "timed out" in result.error


# ---------------------------------------------------------------------------
# End-to-end verify
# ---------------------------------------------------------------------------

class TestVerifyEndToEnd:
    def test_unknown_vector_returns_error(self, tmp_path):
        v = Verifier(output_dir=tmp_path)
        h = _make_hypothesis(attack_vector="zero-day magic")

        result = v.verify(h)

        assert result.passed is False
        assert "No template found" in result.error

    @patch("shutil.which", return_value=None)
    def test_verify_without_forge(self, mock_which, tmp_path):
        v = Verifier(output_dir=tmp_path)
        h = _make_hypothesis(attack_vector="reentrancy")
        params = {"target_contract": "0x1234"}

        result = v.verify(h, params)

        assert result.compiled is False
        assert "forge not found" in result.error


# ---------------------------------------------------------------------------
# _test_name_from_template
# ---------------------------------------------------------------------------

class TestTestNameFromTemplate:
    def test_reentrancy(self):
        assert _test_name_from_template("reentrancy_poc.sol.j2") == "test_reentrancy_exploit"

    def test_flash_loan(self):
        assert _test_name_from_template("flash_loan_poc.sol.j2") == "test_flash_loan_exploit"

    def test_access_control(self):
        assert _test_name_from_template("access_control_poc.sol.j2") == "test_access_control_bypass"

    def test_oracle(self):
        assert _test_name_from_template("oracle_manipulation_poc.sol.j2") == "test_oracle_manipulation"

    def test_integer_overflow(self):
        assert _test_name_from_template("integer_overflow_poc.sol.j2") == "test_integer_overflow"

    def test_unknown_template(self):
        assert _test_name_from_template("custom_thing.sol.j2") == "test_"
