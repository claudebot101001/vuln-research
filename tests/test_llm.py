"""Tests for pipeline/llm.py — JSON/Solidity extraction, CostTracker, LLMClient."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

import pytest

from pipeline.llm import (
    CostTracker,
    LLMClient,
    LLMError,
    LLMParseError,
    _extract_json,
    _extract_solidity,
)


# ---------------------------------------------------------------------------
# _extract_json — 5 strategies + failure
# ---------------------------------------------------------------------------


class TestExtractJson:
    def test_strategy1_direct_parse(self):
        raw = json.dumps({"key": "value", "num": 42})
        assert _extract_json(raw) == {"key": "value", "num": 42}

    def test_strategy1_with_whitespace(self):
        raw = "  \n " + json.dumps({"a": 1}) + " \n "
        assert _extract_json(raw) == {"a": 1}

    def test_strategy2_json_code_fence(self):
        raw = '```json\n{"keep": true}\n```'
        assert _extract_json(raw) == {"keep": True}

    def test_strategy3_generic_code_fence(self):
        raw = '```\n{"items": [1, 2, 3]}\n```'
        assert _extract_json(raw) == {"items": [1, 2, 3]}

    def test_strategy4_brace_extraction(self):
        raw = 'Preamble {"exploitable": false, "reason": "safe"} trailing'
        assert _extract_json(raw) == {"exploitable": False, "reason": "safe"}

    def test_strategy5_failure_raises_parse_error(self):
        raw = "This has no JSON at all, just text."
        with pytest.raises(LLMParseError) as exc_info:
            _extract_json(raw)
        assert exc_info.value.raw_response == raw
        assert "Could not extract JSON" in str(exc_info.value)

    def test_nested_json_in_fence(self):
        data = {"findings": [{"id": "F-1", "keep": True}]}
        raw = f"```json\n{json.dumps(data, indent=2)}\n```"
        assert _extract_json(raw) == data


# ---------------------------------------------------------------------------
# _extract_solidity
# ---------------------------------------------------------------------------


class TestExtractSolidity:
    def test_solidity_fence(self):
        raw = "Here:\n```solidity\npragma solidity ^0.8.0;\ncontract X {}\n```\nDone."
        result = _extract_solidity(raw)
        assert "pragma solidity" in result
        assert "contract X" in result

    def test_generic_fence(self):
        raw = "```\ncontract Y { function f() {} }\n```"
        result = _extract_solidity(raw)
        assert "contract Y" in result

    def test_raw_code_no_fence(self):
        raw = "  pragma solidity ^0.8.0;\n  contract Z {}  "
        result = _extract_solidity(raw)
        assert result == "pragma solidity ^0.8.0;\n  contract Z {}"

    def test_prefers_solidity_fence_over_generic(self):
        raw = "```solidity\ncontract A {}\n```\n\n```\ncontract B {}\n```"
        result = _extract_solidity(raw)
        assert "contract A" in result


# ---------------------------------------------------------------------------
# CostTracker
# ---------------------------------------------------------------------------


class TestCostTracker:
    def test_record_and_count(self):
        ct = CostTracker(max_calls=10)
        ct.record(100, 200)
        ct.record(150, 300)
        assert ct.call_count == 2
        assert ct.total_prompt_chars == 250
        assert ct.total_response_chars == 500

    def test_budget_enforcement(self):
        ct = CostTracker(max_calls=2)
        ct.record(10, 20)
        ct.record(10, 20)
        # Now at limit — next check should raise
        with pytest.raises(LLMError, match="budget exhausted"):
            ct.check_budget()

    def test_budget_ok_when_under_limit(self):
        ct = CostTracker(max_calls=5)
        ct.record(10, 20)
        ct.check_budget()  # Should not raise

    def test_estimated_cost(self):
        ct = CostTracker()
        ct.record(1000, 1000)
        # (1000 * 0.01 + 1000 * 0.03) / 1000 = 0.04
        assert ct.estimated_cost_usd == pytest.approx(0.04)


# ---------------------------------------------------------------------------
# LLMClient — caching + timeout
# ---------------------------------------------------------------------------


def _make_completed_process(stdout: str = '{"ok": true}', returncode: int = 0):
    return subprocess.CompletedProcess(
        args=["claude", "-p"],
        returncode=returncode,
        stdout=stdout,
        stderr="",
    )


class TestLLMClientCaching:
    def test_cache_hit_skips_subprocess(self, tmp_path):
        cache_dir = tmp_path / "cache"
        client = LLMClient(cache_dir=cache_dir)

        # First call: subprocess runs
        with patch(
            "pipeline.llm.subprocess.run", return_value=_make_completed_process()
        ) as mock_run:
            result1 = client.ask("test prompt")
            assert mock_run.call_count == 1

        # Second call: cache hit, subprocess NOT called
        with patch("pipeline.llm.subprocess.run") as mock_run:
            result2 = client.ask("test prompt")
            mock_run.assert_not_called()

        assert result1 == result2

    def test_no_cache_dir_always_calls_subprocess(self):
        client = LLMClient(cache_dir=None)
        with patch(
            "pipeline.llm.subprocess.run", return_value=_make_completed_process()
        ) as mock_run:
            client.ask("prompt1")
            client.ask("prompt1")
            assert mock_run.call_count == 2


class TestLLMClientTimeout:
    def test_timeout_wrapped_in_llm_error(self):
        client = LLMClient(default_timeout=5)
        with patch(
            "pipeline.llm.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="claude", timeout=5),
        ):
            with pytest.raises(LLMError, match="timed out"):
                client.ask("prompt")

    def test_custom_timeout_passed_to_subprocess(self):
        client = LLMClient(default_timeout=180)
        with patch(
            "pipeline.llm.subprocess.run", return_value=_make_completed_process()
        ) as mock_run:
            client.ask("prompt", timeout=30)
            call_kwargs = mock_run.call_args.kwargs
            assert call_kwargs["timeout"] == 30

    def test_nonzero_returncode_raises_llm_error(self):
        client = LLMClient()
        bad_result = subprocess.CompletedProcess(
            args=["claude", "-p"],
            returncode=1,
            stdout="",
            stderr="Error: something went wrong",
        )
        with patch("pipeline.llm.subprocess.run", return_value=bad_result):
            with pytest.raises(LLMError, match="claude -p failed"):
                client.ask("prompt")

    def test_budget_checked_before_call(self):
        client = LLMClient(max_calls=0)
        with pytest.raises(LLMError, match="budget exhausted"):
            client.ask("prompt")


class TestLLMClientAskStructured:
    def test_returns_parsed_json(self):
        client = LLMClient()
        response = json.dumps({"result": "ok"})
        with patch(
            "pipeline.llm.subprocess.run",
            return_value=_make_completed_process(stdout=response),
        ):
            result = client.ask_structured("give me json")
            assert result == {"result": "ok"}
