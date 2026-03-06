import subprocess
from unittest.mock import MagicMock, patch

from pipeline.verify import ForgeExecutor


# ---------------------------------------------------------------------------
# Forge output fixtures
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


# ---------------------------------------------------------------------------
# Forge output parsing
# ---------------------------------------------------------------------------


class TestForgeOutputParsing:
    def test_parse_passing_test(self, tmp_path):
        executor = ForgeExecutor()
        test_file = tmp_path / "H-001.t.sol"
        test_file.write_text("// placeholder")

        result = executor._parse_forge_output(
            stdout=FORGE_PASS_OUTPUT,
            test_file=test_file,
            match_test="test_reentrancy_exploit",
        )

        assert result.compiled is True
        assert result.passed is True
        assert result.gas_used == 250000
        assert result.error is None

    def test_parse_failing_test(self, tmp_path):
        executor = ForgeExecutor()
        test_file = tmp_path / "H-002.t.sol"
        test_file.write_text("// placeholder")

        result = executor._parse_forge_output(
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
        executor = ForgeExecutor()
        test_file = tmp_path / "H-003.t.sol"
        test_file.write_text("// placeholder")

        result = executor._parse_forge_output(
            stdout=FORGE_COMPILE_FAIL_OUTPUT,
            test_file=test_file,
            match_test="test_exploit",
        )

        assert result.compiled is False
        assert result.passed is False
        assert result.error is not None
        assert "failed" in result.error.lower()

    def test_parse_gas_extraction(self, tmp_path):
        executor = ForgeExecutor()
        test_file = tmp_path / "H-004.t.sol"
        test_file.write_text("// placeholder")

        result = executor._parse_forge_output(
            stdout=FORGE_PASS_OUTPUT,
            test_file=test_file,
            match_test=None,
        )

        assert result.gas_used == 250000


# ---------------------------------------------------------------------------
# run() with mocked subprocess
# ---------------------------------------------------------------------------


class TestRunForge:
    @patch("shutil.which", return_value=None)
    def test_forge_not_in_path(self, mock_which, tmp_path):
        executor = ForgeExecutor()
        test_file = tmp_path / "H-001.t.sol"
        test_file.write_text("// placeholder")

        result = executor.run(test_file, match_test="test_exploit")

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

        executor = ForgeExecutor()
        test_file = tmp_path / "H-001.t.sol"
        test_file.write_text("// placeholder")

        result = executor.run(test_file, match_test="test_reentrancy_exploit")

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

        executor = ForgeExecutor()
        test_file = tmp_path / "H-001.t.sol"
        test_file.write_text("// placeholder")

        result = executor.run(test_file, match_test="test_reentrancy_exploit")

        assert result.passed is False
        assert "ReentrancyGuard" in result.error

    @patch("shutil.which", return_value="/usr/bin/forge")
    @patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="forge", timeout=300),
    )
    def test_forge_timeout(self, mock_run, mock_which, tmp_path):
        executor = ForgeExecutor()
        test_file = tmp_path / "H-001.t.sol"
        test_file.write_text("// placeholder")

        result = executor.run(test_file, match_test="test_exploit")

        assert result.compiled is False
        assert result.passed is False
        assert "timed out" in result.error

    @patch("shutil.which", return_value="/usr/bin/forge")
    @patch("subprocess.run")
    def test_forge_with_custom_cwd(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = MagicMock(
            stdout=FORGE_PASS_OUTPUT,
            stderr="",
            returncode=0,
        )

        executor = ForgeExecutor()
        test_file = tmp_path / "H-001.t.sol"
        test_file.write_text("// placeholder")
        custom_cwd = tmp_path / "project"
        custom_cwd.mkdir()

        executor.run(test_file, cwd=custom_cwd)

        call_kwargs = mock_run.call_args
        assert call_kwargs.kwargs["cwd"] == custom_cwd
