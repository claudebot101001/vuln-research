from unittest.mock import MagicMock, patch

from pipeline.models import CodeContext, Hypothesis, PoCResult, ScanConfig, Severity
from pipeline.poc_gen import PoCGenerator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_SOLIDITY = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
contract ExploitTest is Test {
    function test_exploit() public {
        assertGt(1, 0);
    }
}
"""


def _make_hypothesis(**overrides) -> Hypothesis:
    defaults = {
        "id": "H-001",
        "finding_ids": ["F-001"],
        "attack_vector": "reentrancy in withdraw()",
        "preconditions": ["No reentrancy guard"],
        "impact": "Drain funds",
        "severity": Severity.HIGH,
        "exploitability": 0.8,
        "poc_strategy": "Call withdraw repeatedly via fallback",
        "target_functions": ["Vault.withdraw"],
        "root_cause": "External call before state update in withdraw()",
        "exploit_steps": [
            "Deploy attacker contract",
            "Call withdraw()",
            "Re-enter via fallback",
        ],
    }
    defaults.update(overrides)
    return Hypothesis(**defaults)


def _make_context(**overrides) -> CodeContext:
    defaults = {
        "finding_id": "F-001",
        "source_snippet": "function withdraw() external { ... }",
        "full_function": 'function withdraw() external {\n    uint bal = balances[msg.sender];\n    (bool ok,) = msg.sender.call{value: bal}("");\n    require(ok);\n    balances[msg.sender] = 0;\n}',
        "contract_source": "contract Vault { ... }",
        "call_graph": ["Vault.withdraw -> msg.sender.call"],
        "state_variables": ["mapping(address => uint256) public balances"],
        "inheritance_chain": ["Vault"],
        "related_functions": ["deposit"],
    }
    defaults.update(overrides)
    return CodeContext(**defaults)


def _make_config(**overrides) -> ScanConfig:
    defaults = {
        "target": "/tmp/test-project",
        "fork_url": "https://eth-mainnet.alchemyapi.io/v2/xxx",
        "fork_block": 18000000,
    }
    defaults.update(overrides)
    return ScanConfig(**defaults)


def _make_poc_result(passed=True, compiled=True, **overrides) -> PoCResult:
    defaults = {
        "hypothesis_id": "H-001",
        "test_name": "test_exploit",
        "test_file": "/tmp/poc/H-001_attempt1.t.sol",
        "compiled": compiled,
        "passed": passed,
        "gas_used": 250000,
        "logs": "[PASS] test_exploit() (gas: 250000)",
        "error": None if passed else "assertion failed",
    }
    defaults.update(overrides)
    return PoCResult(**defaults)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestGenerateAndVerifySuccess:
    """PoC passes on first attempt and validation succeeds."""

    def test_all_pass_first_try(self, tmp_path):
        mock_llm = MagicMock()
        # First call: generate PoC code
        mock_llm.ask.return_value = f"```solidity\n{SAMPLE_SOLIDITY}\n```"
        # Second call: validation
        mock_llm.ask_structured.return_value = {
            "valid": True,
            "reason": "Assertions verify balance drain",
        }

        gen = PoCGenerator(llm=mock_llm, output_dir=tmp_path / "poc")

        passing_result = _make_poc_result(passed=True, compiled=True)
        with patch.object(gen.forge, "run", return_value=passing_result):
            result = gen.generate_and_verify(
                _make_hypothesis(), _make_context(), _make_config()
            )

        assert result.passed is True
        assert result.validated is True
        assert result.validation_reason == "Assertions verify balance drain"
        assert result.attempt == 1
        assert result.previous_errors == []
        assert mock_llm.ask.call_count == 1
        assert mock_llm.ask_structured.call_count == 1


class TestRetryOnCompilationFailure:
    """First attempt fails compilation, second succeeds."""

    def test_retry_after_compile_error(self, tmp_path):
        mock_llm = MagicMock()
        mock_llm.ask.return_value = f"```solidity\n{SAMPLE_SOLIDITY}\n```"
        mock_llm.ask_structured.return_value = {
            "valid": True,
            "reason": "Valid exploit",
        }

        gen = PoCGenerator(llm=mock_llm, output_dir=tmp_path / "poc")

        fail_result = _make_poc_result(
            passed=False,
            compiled=False,
            error="Compilation failed",
            logs="Error: Compiler run failed",
        )
        pass_result = _make_poc_result(passed=True, compiled=True)

        call_count = 0

        def mock_forge_run(test_file, cwd=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return fail_result
            return pass_result

        with patch.object(gen.forge, "run", side_effect=mock_forge_run):
            result = gen.generate_and_verify(
                _make_hypothesis(), _make_context(), _make_config()
            )

        assert result.passed is True
        assert result.validated is True
        assert result.attempt == 2
        assert len(result.previous_errors) == 1
        assert "compilation failed" in result.previous_errors[0].lower()
        assert mock_llm.ask.call_count == 2


class TestValidationFailureRetry:
    """Test passes forge but validation says invalid, retries."""

    def test_retry_after_validation_failure(self, tmp_path):
        mock_llm = MagicMock()
        mock_llm.ask.return_value = f"```solidity\n{SAMPLE_SOLIDITY}\n```"

        validation_calls = 0

        def mock_ask_structured(prompt, system_prompt=None, timeout=None):
            nonlocal validation_calls
            validation_calls += 1
            if validation_calls == 1:
                return {
                    "valid": False,
                    "reason": "Assertions are trivially true (assertGt(1, 0))",
                }
            return {"valid": True, "reason": "Now has meaningful assertions"}

        mock_llm.ask_structured.side_effect = mock_ask_structured

        gen = PoCGenerator(llm=mock_llm, output_dir=tmp_path / "poc")

        passing_result = _make_poc_result(passed=True, compiled=True)
        with patch.object(gen.forge, "run", return_value=passing_result):
            result = gen.generate_and_verify(
                _make_hypothesis(), _make_context(), _make_config()
            )

        assert result.passed is True
        assert result.validated is True
        assert result.attempt == 2
        assert len(result.previous_errors) == 1
        assert "DOES NOT demonstrate" in result.previous_errors[0]
        assert mock_llm.ask.call_count == 2
        assert mock_llm.ask_structured.call_count == 2


class TestMaxRetriesExhausted:
    """All 3 attempts fail — returns last result."""

    def test_exhausted_retries(self, tmp_path):
        mock_llm = MagicMock()
        mock_llm.ask.return_value = f"```solidity\n{SAMPLE_SOLIDITY}\n```"

        gen = PoCGenerator(llm=mock_llm, output_dir=tmp_path / "poc")

        fail_result = _make_poc_result(
            passed=False,
            compiled=True,
            error="assertion failed: balance unchanged",
            logs="[FAIL] test_exploit()",
        )

        with patch.object(gen.forge, "run", return_value=fail_result):
            result = gen.generate_and_verify(
                _make_hypothesis(), _make_context(), _make_config()
            )

        assert result.passed is False
        assert result.validated is False
        assert result.attempt == 3
        assert len(result.previous_errors) == 2  # errors from attempts 1 and 2
        assert mock_llm.ask.call_count == 3


class TestPoCResultFields:
    """PoCResult fields are correctly populated."""

    def test_result_fields_on_success(self, tmp_path):
        mock_llm = MagicMock()
        mock_llm.ask.return_value = f"```solidity\n{SAMPLE_SOLIDITY}\n```"
        mock_llm.ask_structured.return_value = {
            "valid": True,
            "reason": "Exploits reentrancy correctly",
        }

        gen = PoCGenerator(llm=mock_llm, output_dir=tmp_path / "poc")

        passing_result = _make_poc_result(passed=True, compiled=True, gas_used=300000)
        with patch.object(gen.forge, "run", return_value=passing_result):
            result = gen.generate_and_verify(
                _make_hypothesis(), _make_context(), _make_config()
            )

        assert result.attempt == 1
        assert result.previous_errors == []
        assert result.validated is True
        assert result.validation_reason == "Exploits reentrancy correctly"
        assert result.gas_used == 300000


class TestWritePoC:
    """PoC files are written to the correct location."""

    def test_write_poc_creates_file(self, tmp_path):
        mock_llm = MagicMock()
        gen = PoCGenerator(llm=mock_llm, output_dir=tmp_path / "poc")

        path = gen._write_poc("H-001", SAMPLE_SOLIDITY, 1)

        assert path.exists()
        assert path.name == "H-001_attempt1.t.sol"
        assert path.read_text() == SAMPLE_SOLIDITY

    def test_write_poc_creates_directory(self, tmp_path):
        mock_llm = MagicMock()
        output_dir = tmp_path / "nested" / "poc"
        gen = PoCGenerator(llm=mock_llm, output_dir=output_dir)

        path = gen._write_poc("H-002", SAMPLE_SOLIDITY, 2)

        assert path.exists()
        assert output_dir.exists()
        assert path.name == "H-002_attempt2.t.sol"


class TestBuildPoCPrompt:
    """Prompt construction includes all relevant information."""

    def test_prompt_contains_hypothesis_details(self, tmp_path):
        mock_llm = MagicMock()
        gen = PoCGenerator(llm=mock_llm, output_dir=tmp_path)

        hypothesis = _make_hypothesis()
        context = _make_context()
        config = _make_config()

        prompt = gen._build_poc_prompt(hypothesis, context, config)

        assert "reentrancy" in prompt.lower()
        assert "withdraw" in prompt.lower()
        assert "External call before state update" in prompt
        assert "Vault.withdraw" in prompt

    def test_prompt_includes_fork_config(self, tmp_path):
        mock_llm = MagicMock()
        gen = PoCGenerator(llm=mock_llm, output_dir=tmp_path)

        config = _make_config(fork_url="https://rpc.example.com", fork_block=12345678)
        prompt = gen._build_poc_prompt(_make_hypothesis(), _make_context(), config)

        assert "https://rpc.example.com" in prompt
        assert "12345678" in prompt

    def test_prompt_includes_previous_error(self, tmp_path):
        mock_llm = MagicMock()
        gen = PoCGenerator(llm=mock_llm, output_dir=tmp_path)

        prompt = gen._build_poc_prompt(
            _make_hypothesis(),
            _make_context(),
            _make_config(),
            previous_error="DeclarationError: Undeclared identifier",
        )

        assert "PREVIOUS ATTEMPT FAILED" in prompt
        assert "DeclarationError" in prompt

    def test_prompt_no_fork(self, tmp_path):
        mock_llm = MagicMock()
        gen = PoCGenerator(llm=mock_llm, output_dir=tmp_path)

        config = _make_config(fork_url=None, fork_block=None)
        prompt = gen._build_poc_prompt(_make_hypothesis(), _make_context(), config)

        assert "No fork required" in prompt
