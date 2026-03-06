"""Tests for pipeline/analyze.py — LLM deep analysis, hypothesis construction."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

import pytest

from pipeline.analyze import ANALYSIS_SYSTEM_PROMPT, Analyzer, _make_id
from pipeline.llm import LLMClient
from pipeline.models import CodeContext, Finding, FindingSource, Hypothesis, Severity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_finding(id: str = "F-1", **kwargs) -> Finding:
    defaults = dict(
        id=id,
        source=FindingSource.SLITHER,
        detector="reentrancy-eth",
        severity=Severity.HIGH,
        confidence=0.8,
        title="Reentrancy in withdraw",
        description="External call before state update",
        contract="Vault",
        function="withdraw",
        file_path="src/Vault.sol",
        line_start=42,
        category="reentrancy",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _make_context(finding_id: str = "F-1") -> CodeContext:
    return CodeContext(
        finding_id=finding_id,
        source_snippet="function withdraw() external {\n  token.transfer(msg.sender, balance);\n  balances[msg.sender] = 0;\n}",
        full_function="function withdraw() external {\n  uint256 balance = balances[msg.sender];\n  token.transfer(msg.sender, balance);\n  balances[msg.sender] = 0;\n}",
        contract_source="contract Vault { ... }",
        call_graph=["Vault.withdraw -> IERC20.transfer"],
        state_variables=["mapping(address => uint256) public balances;"],
        inheritance_chain=["Vault", "Ownable"],
        related_functions=["deposit", "balanceOf"],
    )


_EXPLOITABLE_RESPONSE = {
    "exploitable": True,
    "root_cause": "State update after external call in withdraw()",
    "attack_vector": "Reentrant call during token.transfer callback",
    "preconditions": ["Vault must hold tokens", "Attacker has a deposit"],
    "impact": "Drain all tokens from Vault",
    "severity": "critical",
    "exploitability_score": 0.95,
    "poc_strategy": "Deploy attacker contract, deposit, call withdraw with reentrant fallback",
    "target_functions": ["Vault.withdraw"],
    "exploit_steps": [
        "Deploy attacker contract",
        "Deposit tokens into Vault",
        "Call withdraw() triggering reentrant callback",
        "Drain remaining balance",
    ],
    "needs_fork": False,
    "required_contracts": ["IERC20"],
    "poc_solidity_hints": "function attack() { vault.withdraw(); } receive() { vault.withdraw(); }",
}

_NOT_EXPLOITABLE_RESPONSE = {
    "exploitable": False,
    "root_cause": "Pattern detected but reentrancy guard is present",
    "attack_vector": "",
    "preconditions": [],
    "impact": "",
    "severity": "low",
    "exploitability_score": 0.05,
    "poc_strategy": "",
    "target_functions": [],
    "exploit_steps": [],
    "needs_fork": False,
    "required_contracts": [],
    "poc_solidity_hints": "",
}


def _mock_subprocess_factory(stdout: str):
    return subprocess.CompletedProcess(
        args=["claude", "-p"], returncode=0, stdout=stdout, stderr=""
    )


# ---------------------------------------------------------------------------
# _make_id
# ---------------------------------------------------------------------------


class TestMakeId:
    def test_deterministic(self):
        assert _make_id("F-1") == _make_id("F-1")

    def test_different_inputs_different_ids(self):
        assert _make_id("F-1") != _make_id("F-2")

    def test_starts_with_H_prefix(self):
        assert _make_id("F-1").startswith("H-")

    def test_fixed_length(self):
        # "H-" + 12 hex chars = 14 chars
        assert len(_make_id("F-1")) == 14
        assert len(_make_id("some-very-long-finding-id-12345")) == 14


# ---------------------------------------------------------------------------
# Analyzer.analyze — exploitable finding
# ---------------------------------------------------------------------------


class TestAnalyzeExploitable:
    def test_returns_hypothesis(self):
        analyzer = Analyzer(LLMClient())
        response_str = json.dumps(_EXPLOITABLE_RESPONSE)
        with patch(
            "pipeline.llm.subprocess.run",
            return_value=_mock_subprocess_factory(response_str),
        ):
            result = analyzer.analyze(_make_finding(), _make_context())

        assert isinstance(result, Hypothesis)

    def test_hypothesis_fields_populated(self):
        analyzer = Analyzer(LLMClient())
        response_str = json.dumps(_EXPLOITABLE_RESPONSE)
        with patch(
            "pipeline.llm.subprocess.run",
            return_value=_mock_subprocess_factory(response_str),
        ):
            h = analyzer.analyze(
                _make_finding(id="F-7"), _make_context(finding_id="F-7")
            )

        assert h is not None
        assert h.id == _make_id("F-7")
        assert h.finding_ids == ["F-7"]
        assert h.severity == Severity.CRITICAL
        assert h.exploitability == 0.95
        assert h.attack_vector == _EXPLOITABLE_RESPONSE["attack_vector"]
        assert h.root_cause == _EXPLOITABLE_RESPONSE["root_cause"]
        assert h.exploit_steps == _EXPLOITABLE_RESPONSE["exploit_steps"]
        assert h.poc_strategy == _EXPLOITABLE_RESPONSE["poc_strategy"]
        assert h.target_functions == ["Vault.withdraw"]
        assert h.needs_fork is False
        assert h.required_contracts == ["IERC20"]
        assert "vault.withdraw" in h.poc_solidity_hints.lower()
        assert h.preconditions == _EXPLOITABLE_RESPONSE["preconditions"]
        assert h.impact == _EXPLOITABLE_RESPONSE["impact"]

    def test_optional_fields_default(self):
        """Response without optional fields should still produce a valid Hypothesis."""
        analyzer = Analyzer(LLMClient())
        minimal = dict(_EXPLOITABLE_RESPONSE)
        del minimal["needs_fork"]
        del minimal["required_contracts"]
        del minimal["poc_solidity_hints"]
        response_str = json.dumps(minimal)
        with patch(
            "pipeline.llm.subprocess.run",
            return_value=_mock_subprocess_factory(response_str),
        ):
            h = analyzer.analyze(_make_finding(), _make_context())

        assert h is not None
        assert h.needs_fork is False
        assert h.required_contracts == []
        assert h.poc_solidity_hints == ""


# ---------------------------------------------------------------------------
# Analyzer.analyze — not exploitable
# ---------------------------------------------------------------------------


class TestAnalyzeNotExploitable:
    def test_returns_none(self):
        analyzer = Analyzer(LLMClient())
        response_str = json.dumps(_NOT_EXPLOITABLE_RESPONSE)
        with patch(
            "pipeline.llm.subprocess.run",
            return_value=_mock_subprocess_factory(response_str),
        ):
            result = analyzer.analyze(_make_finding(), _make_context())

        assert result is None

    def test_missing_exploitable_field_treated_as_false(self):
        analyzer = Analyzer(LLMClient())
        response_str = json.dumps({"some_other_field": "value"})
        with patch(
            "pipeline.llm.subprocess.run",
            return_value=_mock_subprocess_factory(response_str),
        ):
            result = analyzer.analyze(_make_finding(), _make_context())

        assert result is None


# ---------------------------------------------------------------------------
# LLM parse error handling
# ---------------------------------------------------------------------------


class TestAnalyzeParseError:
    def test_parse_error_returns_none(self):
        analyzer = Analyzer(LLMClient())
        with patch(
            "pipeline.llm.subprocess.run",
            return_value=_mock_subprocess_factory(
                "This is not JSON at all, just rambling text."
            ),
        ):
            result = analyzer.analyze(_make_finding(), _make_context())

        assert result is None


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


class TestBuildAnalysisPrompt:
    def test_includes_finding_details(self):
        analyzer = Analyzer(LLMClient())
        finding = _make_finding(id="F-99", title="Access control bypass")
        context = _make_context(finding_id="F-99")
        prompt = analyzer._build_analysis_prompt(finding, context)

        assert "F-99" in prompt
        assert "Access control bypass" in prompt
        assert "reentrancy-eth" in prompt
        assert "Vault" in prompt
        assert "withdraw" in prompt

    def test_includes_full_context(self):
        analyzer = Analyzer(LLMClient())
        context = _make_context()
        finding = _make_finding()
        prompt = analyzer._build_analysis_prompt(finding, context)

        assert "IERC20.transfer" in prompt
        assert "mapping(address => uint256)" in prompt
        assert "Vault -> Ownable" in prompt
        assert "deposit" in prompt  # related_functions
        assert "contract Vault" in prompt  # contract_source

    def test_handles_empty_context_fields(self):
        analyzer = Analyzer(LLMClient())
        context = CodeContext(finding_id="F-1")
        finding = _make_finding()
        prompt = analyzer._build_analysis_prompt(finding, context)

        assert "(not available)" in prompt
        # Should not crash with empty fields
        assert "F-1" in prompt
