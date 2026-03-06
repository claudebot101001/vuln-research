"""Tests for pipeline.context — Code context extraction.

Tests both regex fallback mode and Slither graceful degradation.
Slither API tests use mocking since Slither + solc may not be available in CI.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from pipeline.context import (
    ContextExtractor,
    _find_matching_brace,
    _regex_extract_contract,
    _regex_extract_function,
    _regex_extract_state_variables,
)
from pipeline.models import CodeContext, Finding, FindingSource, Severity

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sample_contracts"


def _make_finding(
    *,
    contract: str = "SimpleVault",
    function: str | None = "withdraw",
    file_path: str | None = None,
    line_start: int = 25,
) -> Finding:
    """Create a minimal Finding for testing."""
    if file_path is None:
        file_path = str(FIXTURES_DIR / "SimpleVault.sol")
    return Finding(
        id="TEST-001",
        source=FindingSource.SLITHER,
        detector="reentrancy-eth",
        severity=Severity.HIGH,
        confidence=0.8,
        title="Reentrancy in withdraw",
        description="External call after state update",
        contract=contract,
        function=function,
        file_path=file_path,
        line_start=line_start,
        category="reentrancy",
    )


# ------------------------------------------------------------------
# Regex mode: extract source snippet around a line number
# ------------------------------------------------------------------


class TestSnippetExtraction:
    def test_extract_snippet_centers_on_line(self):
        """Snippet should include ~25 lines before and after the target line."""
        extractor = ContextExtractor(FIXTURES_DIR)
        finding = _make_finding(line_start=25)
        ctx = extractor._extract_via_regex(finding)
        assert ctx.source_snippet != ""
        lines = ctx.source_snippet.split("\n")
        # Should have up to 50 lines (25 + line + 24)
        assert len(lines) >= 10  # At minimum, some context around line 25
        # The withdraw function line should be in the snippet
        assert "withdraw" in ctx.source_snippet

    def test_extract_snippet_beginning_of_file(self):
        """Snippet near start of file should not go negative."""
        extractor = ContextExtractor(FIXTURES_DIR)
        finding = _make_finding(line_start=3)
        ctx = extractor._extract_via_regex(finding)
        assert ctx.source_snippet != ""
        # First line of file should be present
        assert "SPDX-License-Identifier" in ctx.source_snippet

    def test_extract_snippet_missing_file(self):
        """Missing file should return empty snippet or code_snippet fallback."""
        extractor = ContextExtractor(FIXTURES_DIR)
        finding = _make_finding(file_path="/nonexistent/file.sol")
        ctx = extractor._extract_via_regex(finding)
        assert ctx.source_snippet == ""


# ------------------------------------------------------------------
# Regex mode: extract function body
# ------------------------------------------------------------------


class TestFunctionExtraction:
    def test_extract_function_body(self):
        """Should extract complete function with matching braces."""
        source = (FIXTURES_DIR / "SimpleVault.sol").read_text()
        result = _regex_extract_function(source, "withdraw")
        assert result != ""
        assert "function withdraw" in result
        assert "msg.sender.call" in result
        assert result.count("{") == result.count("}")

    def test_extract_function_deposit(self):
        source = (FIXTURES_DIR / "SimpleVault.sol").read_text()
        result = _regex_extract_function(source, "deposit")
        assert "function deposit" in result
        assert "msg.value" in result

    def test_extract_function_not_found(self):
        source = (FIXTURES_DIR / "SimpleVault.sol").read_text()
        result = _regex_extract_function(source, "nonexistentFunction")
        assert result == ""

    def test_extract_function_with_modifiers(self):
        """Functions with modifiers (onlyOwner) should be extracted correctly."""
        source = (FIXTURES_DIR / "SimpleVault.sol").read_text()
        result = _regex_extract_function(source, "pause")
        assert "function pause" in result
        assert "paused = true" in result

    def test_extract_function_view(self):
        """View functions should be extracted."""
        source = (FIXTURES_DIR / "SimpleVault.sol").read_text()
        result = _regex_extract_function(source, "getBalance")
        assert "function getBalance" in result
        assert "returns" in result


# ------------------------------------------------------------------
# Regex mode: extract inheritance chain
# ------------------------------------------------------------------


class TestInheritanceExtraction:
    def test_single_inheritance(self):
        source = (FIXTURES_DIR / "SimpleVault.sol").read_text()
        _, chain = _regex_extract_contract(source, "SimpleVault")
        assert chain == ["SimpleVault", "Ownable"]

    def test_multiple_inheritance(self):
        source = (FIXTURES_DIR / "InheritanceChain.sol").read_text()
        _, chain = _regex_extract_contract(source, "ManagedToken")
        assert chain == ["ManagedToken", "Pausable", "AccessControl"]

    def test_no_inheritance(self):
        source = (FIXTURES_DIR / "MultiContract.sol").read_text()
        _, chain = _regex_extract_contract(source, "TokenHolder")
        assert chain == ["TokenHolder"]

    def test_contract_not_found(self):
        source = (FIXTURES_DIR / "SimpleVault.sol").read_text()
        body, chain = _regex_extract_contract(source, "NonExistent")
        assert body == ""
        assert chain == []

    def test_interface_extraction(self):
        source = (FIXTURES_DIR / "MultiContract.sol").read_text()
        body, chain = _regex_extract_contract(source, "IERC20")
        assert "interface IERC20" in body
        assert chain == ["IERC20"]


# ------------------------------------------------------------------
# Regex mode: extract state variables
# ------------------------------------------------------------------


class TestStateVariableExtraction:
    def test_extract_state_vars_simple_vault(self):
        source = (FIXTURES_DIR / "SimpleVault.sol").read_text()
        contract_source, _ = _regex_extract_contract(source, "SimpleVault")
        vars_ = _regex_extract_state_variables(contract_source)
        var_text = " ".join(vars_)
        assert "balances" in var_text
        assert "totalDeposits" in var_text
        assert "paused" in var_text

    def test_extract_mapping_type(self):
        source = (FIXTURES_DIR / "InheritanceChain.sol").read_text()
        contract_source, _ = _regex_extract_contract(source, "ManagedToken")
        vars_ = _regex_extract_state_variables(contract_source)
        var_text = " ".join(vars_)
        assert "balanceOf" in var_text
        assert "totalSupply" in var_text

    def test_no_functions_in_state_vars(self):
        """State variables should not include function declarations."""
        source = (FIXTURES_DIR / "SimpleVault.sol").read_text()
        contract_source, _ = _regex_extract_contract(source, "SimpleVault")
        vars_ = _regex_extract_state_variables(contract_source)
        for v in vars_:
            assert "function " not in v


# ------------------------------------------------------------------
# Regex mode: handle multi-contract file
# ------------------------------------------------------------------


class TestMultiContractFile:
    def test_extract_first_contract(self):
        source = (FIXTURES_DIR / "MultiContract.sol").read_text()
        body, _chain = _regex_extract_contract(source, "TokenHolder")
        assert "contract TokenHolder" in body
        assert "withdrawToken" in body
        # Should NOT contain TokenVault code
        assert "depositToken" not in body

    def test_extract_second_contract(self):
        source = (FIXTURES_DIR / "MultiContract.sol").read_text()
        body, chain = _regex_extract_contract(source, "TokenVault")
        assert "contract TokenVault" in body
        assert "depositToken" in body
        assert chain == ["TokenVault", "TokenHolder"]

    def test_full_context_extraction_multi_contract(self):
        """ContextExtractor should handle multi-contract files via regex."""
        extractor = ContextExtractor(FIXTURES_DIR)
        finding = _make_finding(
            contract="TokenVault",
            function="withdrawDeposit",
            file_path=str(FIXTURES_DIR / "MultiContract.sol"),
            line_start=37,
        )
        ctx = extractor.extract(finding)
        assert ctx.finding_id == "TEST-001"
        assert "withdrawDeposit" in ctx.full_function
        assert "TokenVault" in ctx.contract_source
        assert "TokenHolder" in ctx.inheritance_chain


# ------------------------------------------------------------------
# estimate_token_count
# ------------------------------------------------------------------


class TestTokenEstimate:
    def test_basic_estimate(self):
        ctx = CodeContext(
            finding_id="T-001",
            source_snippet="a" * 400,
            full_function="b" * 800,
            contract_source="c" * 1200,
            call_graph=["x -> y"] * 5,  # 5 * 6 = 30 chars
            state_variables=["uint256 public v"] * 3,  # 3 * 16 = 48 chars
            inheritance_chain=["A", "B"],  # 2 chars
            related_functions=["foo", "bar"],  # 6 chars
        )
        expected = (400 + 800 + 1200 + 30 + 48 + 2 + 6) // 4
        result = ContextExtractor("/tmp").estimate_token_count(ctx)
        assert result == expected

    def test_empty_context(self):
        ctx = CodeContext(
            finding_id="T-002",
            source_snippet="",
            full_function="",
            contract_source="",
            call_graph=[],
            state_variables=[],
            inheritance_chain=[],
            related_functions=[],
        )
        assert ContextExtractor("/tmp").estimate_token_count(ctx) == 0


# ------------------------------------------------------------------
# Slither mode: graceful fallback when Slither not available
# ------------------------------------------------------------------


class TestSlitherFallback:
    def test_slither_not_installed(self):
        """When Slither is not importable, extractor falls back to regex."""
        with patch("pipeline.context.ContextExtractor._try_load_slither", return_value=None):
            extractor = ContextExtractor(FIXTURES_DIR)
            assert extractor._slither is None
            finding = _make_finding()
            ctx = extractor.extract(finding)
            # Should still produce results via regex
            assert ctx.finding_id == "TEST-001"
            assert ctx.source_snippet != ""

    def test_slither_load_failure(self):
        """Slither load failure should not crash, should use regex."""
        with patch("pipeline.context.ContextExtractor._try_load_slither", return_value=None):
            extractor = ContextExtractor(FIXTURES_DIR)
            finding = _make_finding()
            ctx = extractor.extract(finding)
            assert isinstance(ctx, CodeContext)
            # call_graph and related_functions are empty in regex mode
            assert ctx.call_graph == []
            assert ctx.related_functions == []

    def test_slither_extraction_error_falls_back(self):
        """If Slither extraction raises, should fall back to regex."""
        mock_slither = MagicMock()
        mock_slither.contracts = []  # No contracts found
        with patch(
            "pipeline.context.ContextExtractor._try_load_slither",
            return_value=mock_slither,
        ):
            extractor = ContextExtractor(FIXTURES_DIR)
            finding = _make_finding()
            # _extract_via_slither will fail to find contract, fall back to regex
            ctx = extractor.extract(finding)
            assert ctx.finding_id == "TEST-001"
            assert ctx.source_snippet != ""


# ------------------------------------------------------------------
# Brace matching edge cases
# ------------------------------------------------------------------


class TestBraceMatching:
    def test_simple_braces(self):
        assert _find_matching_brace("{ }", 0) == 2

    def test_nested_braces(self):
        assert _find_matching_brace("{ { } }", 0) == 6

    def test_string_with_braces(self):
        # Braces inside strings should be ignored
        assert _find_matching_brace('{ "}" }', 0) == 6

    def test_comment_with_braces(self):
        # Braces inside comments should be ignored
        assert _find_matching_brace("{ // }\n}", 0) == 7

    def test_block_comment_with_braces(self):
        assert _find_matching_brace("{ /* } */ }", 0) == 10

    def test_no_match(self):
        assert _find_matching_brace("{ { }", 0) == -1
