"""Tests for pipeline/triage.py — adaptive batching, LLM triage, edge cases."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline.context import ContextExtractor
from pipeline.llm import LLMClient, LLMParseError
from pipeline.models import CodeContext, Finding, FindingSource, Severity
from pipeline.triage import MAX_TRIAGE_TOKENS, Triager, _abbreviate_context


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
        title="Reentrancy vulnerability",
        description="External call before state update",
        contract="Vault",
        function="withdraw",
        file_path="src/Vault.sol",
        line_start=42,
        category="reentrancy",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _make_context(
    finding_id: str = "F-1",
    snippet_size: int = 200,
    function_size: int = 300,
    contract_size: int = 1000,
    call_graph_count: int = 3,
    state_var_count: int = 5,
) -> CodeContext:
    return CodeContext(
        finding_id=finding_id,
        source_snippet="x" * snippet_size,
        full_function="y" * function_size,
        contract_source="z" * contract_size,
        call_graph=[f"A -> B{i}" for i in range(call_graph_count)],
        state_variables=[f"uint256 public var{i};" for i in range(state_var_count)],
        inheritance_chain=["Vault", "Ownable"],
        related_functions=["deposit", "balanceOf"],
    )


def _make_triage_response(findings: list[tuple[str, bool]]) -> str:
    """Build a JSON response string for triage."""
    data = {
        "findings": [
            {"id": fid, "keep": keep, "confidence": 0.9, "reason": "test"}
            for fid, keep in findings
        ]
    }
    return json.dumps(data)


def _mock_subprocess_factory(stdout: str):
    """Create a mock subprocess.run result."""
    import subprocess

    return subprocess.CompletedProcess(
        args=["claude", "-p"], returncode=0, stdout=stdout, stderr=""
    )


# ---------------------------------------------------------------------------
# _abbreviate_context
# ---------------------------------------------------------------------------


class TestAbbreviateContext:
    def test_truncates_full_function(self):
        ctx = _make_context(function_size=1000)
        abbrev = _abbreviate_context(ctx)
        assert len(abbrev.full_function) == 500

    def test_keeps_short_function(self):
        ctx = _make_context(function_size=100)
        abbrev = _abbreviate_context(ctx)
        assert len(abbrev.full_function) == 100

    def test_empties_contract_source(self):
        ctx = _make_context(contract_size=5000)
        abbrev = _abbreviate_context(ctx)
        assert abbrev.contract_source == ""

    def test_limits_call_graph(self):
        ctx = _make_context(call_graph_count=20)
        abbrev = _abbreviate_context(ctx)
        assert len(abbrev.call_graph) == 5

    def test_limits_state_variables(self):
        ctx = _make_context(state_var_count=30)
        abbrev = _abbreviate_context(ctx)
        assert len(abbrev.state_variables) == 10

    def test_empties_related_functions(self):
        ctx = _make_context()
        abbrev = _abbreviate_context(ctx)
        assert abbrev.related_functions == []

    def test_preserves_finding_id(self):
        ctx = _make_context(finding_id="F-99")
        abbrev = _abbreviate_context(ctx)
        assert abbrev.finding_id == "F-99"

    def test_preserves_inheritance_chain(self):
        ctx = _make_context()
        abbrev = _abbreviate_context(ctx)
        assert abbrev.inheritance_chain == ["Vault", "Ownable"]


# ---------------------------------------------------------------------------
# Adaptive batching
# ---------------------------------------------------------------------------


class TestAdaptiveBatch:
    def _make_extractor(self) -> ContextExtractor:
        """Create a ContextExtractor with Slither disabled (regex-only)."""
        with patch.object(ContextExtractor, "_try_load_slither", return_value=None):
            return ContextExtractor("/tmp/fake")

    def test_single_batch_for_small_findings(self):
        extractor = self._make_extractor()
        triager = Triager(LLMClient())
        pairs = [
            (_make_finding(id=f"F-{i}"), _make_context(finding_id=f"F-{i}"))
            for i in range(3)
        ]
        batches = triager._adaptive_batch(pairs, extractor)
        assert len(batches) == 1
        assert len(batches[0]) == 3

    def test_splits_large_contexts_into_multiple_batches(self):
        extractor = self._make_extractor()
        triager = Triager(LLMClient())
        # Each context is ~10k tokens after abbreviation → should split around 3 per batch
        pairs = [
            (
                _make_finding(id=f"F-{i}"),
                _make_context(
                    finding_id=f"F-{i}",
                    snippet_size=20000,
                    function_size=20000,
                ),
            )
            for i in range(6)
        ]
        batches = triager._adaptive_batch(pairs, extractor)
        assert len(batches) > 1
        # Every finding should be in some batch
        all_ids = {f.id for batch in batches for f, _ in batch}
        assert all_ids == {f"F-{i}" for i in range(6)}

    def test_empty_pairs_returns_empty_batches(self):
        extractor = self._make_extractor()
        triager = Triager(LLMClient())
        batches = triager._adaptive_batch([], extractor)
        assert batches == []

    def test_single_oversized_finding_gets_own_batch(self):
        """A finding that alone exceeds MAX_TRIAGE_TOKENS still gets its own batch."""
        extractor = self._make_extractor()
        triager = Triager(LLMClient())
        # snippet_size large enough that abbreviated context exceeds budget
        huge = _make_context(finding_id="F-big", snippet_size=MAX_TRIAGE_TOKENS * 5)
        small = _make_context(finding_id="F-small", snippet_size=100)
        pairs = [
            (_make_finding(id="F-big"), huge),
            (_make_finding(id="F-small"), small),
        ]
        batches = triager._adaptive_batch(pairs, extractor)
        # The big one should be alone, the small one separate
        assert len(batches) == 2


# ---------------------------------------------------------------------------
# Triage batch
# ---------------------------------------------------------------------------


class TestTriageBatch:
    def test_keeps_only_flagged_findings(self):
        triager = Triager(LLMClient())
        response = _make_triage_response([("F-1", True), ("F-2", False), ("F-3", True)])
        with patch(
            "pipeline.llm.subprocess.run",
            return_value=_mock_subprocess_factory(response),
        ):
            batch = [
                (_make_finding(id="F-1"), _make_context(finding_id="F-1")),
                (_make_finding(id="F-2"), _make_context(finding_id="F-2")),
                (_make_finding(id="F-3"), _make_context(finding_id="F-3")),
            ]
            kept = triager._triage_batch(batch)
        assert [f.id for f in kept] == ["F-1", "F-3"]

    def test_parse_error_keeps_all(self):
        triager = Triager(LLMClient())
        with patch(
            "pipeline.llm.subprocess.run",
            return_value=_mock_subprocess_factory("not valid json at all!!!"),
        ):
            batch = [
                (_make_finding(id="F-1"), _make_context(finding_id="F-1")),
                (_make_finding(id="F-2"), _make_context(finding_id="F-2")),
            ]
            kept = triager._triage_batch(batch)
        # On parse error, all findings should be kept (safe fallback)
        assert len(kept) == 2

    def test_empty_findings_in_response(self):
        triager = Triager(LLMClient())
        response = json.dumps({"findings": []})
        with patch(
            "pipeline.llm.subprocess.run",
            return_value=_mock_subprocess_factory(response),
        ):
            batch = [
                (_make_finding(id="F-1"), _make_context(finding_id="F-1")),
            ]
            kept = triager._triage_batch(batch)
        assert kept == []


# ---------------------------------------------------------------------------
# Full triage flow
# ---------------------------------------------------------------------------


class TestTriageFlow:
    def test_empty_findings_returns_empty(self):
        triager = Triager(LLMClient())
        result = triager.triage([], [], ContextExtractor.__new__(ContextExtractor))
        assert result == []

    def test_full_triage_filters_correctly(self):
        response = _make_triage_response([("F-1", True), ("F-2", False)])
        with patch.object(ContextExtractor, "_try_load_slither", return_value=None):
            extractor = ContextExtractor("/tmp/fake")
        triager = Triager(LLMClient())

        findings = [_make_finding(id="F-1"), _make_finding(id="F-2")]
        contexts = [_make_context(finding_id="F-1"), _make_context(finding_id="F-2")]

        with patch(
            "pipeline.llm.subprocess.run",
            return_value=_mock_subprocess_factory(response),
        ):
            kept = triager.triage(findings, contexts, extractor)

        assert len(kept) == 1
        assert kept[0].id == "F-1"


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


class TestBuildTriagePrompt:
    def test_includes_finding_details(self):
        triager = Triager(LLMClient())
        finding = _make_finding(id="F-42", title="Price oracle manipulation")
        context = _make_context(finding_id="F-42")
        abbreviated = _abbreviate_context(context)
        prompt = triager._build_triage_prompt([(finding, abbreviated)])

        assert "F-42" in prompt
        assert "Price oracle manipulation" in prompt
        assert "reentrancy-eth" in prompt
        assert "Vault" in prompt
        assert "withdraw" in prompt

    def test_includes_code_context(self):
        triager = Triager(LLMClient())
        ctx = CodeContext(
            finding_id="F-1",
            source_snippet="require(msg.sender == owner);",
            full_function="function withdraw() external {",
            call_graph=["Vault.withdraw -> IERC20.transfer"],
            state_variables=["mapping(address => uint256) public balances;"],
            inheritance_chain=["Vault", "Ownable"],
        )
        finding = _make_finding()
        prompt = triager._build_triage_prompt([(finding, ctx)])

        assert "require(msg.sender == owner)" in prompt
        assert "function withdraw()" in prompt
        assert "Vault.withdraw -> IERC20.transfer" in prompt
        assert "mapping(address => uint256)" in prompt
        assert "Vault -> Ownable" in prompt
