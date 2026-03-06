"""Tests for LLM-based ReportGenerator."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from pipeline.llm import LLMClient
from pipeline.models import Hypothesis, PoCResult, ScanConfig, Severity, VulnReport
from pipeline.report import (
    ReportGenerator,
    _extract_sections,
    _extract_title,
    _protocol_from_target,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_REPORT_MD = """\
# Reentrancy in Vault.withdraw

## Summary
A reentrancy vulnerability in the withdraw function allows an attacker to drain all funds.

## Vulnerability Detail
The withdraw function makes an external call before updating state.

## Impact
Complete fund drainage via recursive re-entry.

## Attack Scenario
1. Attacker deploys malicious contract with receive/fallback
2. Calls withdraw, re-enters during external call

## Proof of Concept
```solidity
contract Exploit { }
```

## Remediation
Apply checks-effects-interactions pattern.
"""


def _make_llm(response: str = SAMPLE_REPORT_MD) -> LLMClient:
    llm = MagicMock(spec=LLMClient)
    llm.ask.return_value = response
    llm.cost = MagicMock()
    llm.cost.call_count = 0
    llm.cost.max_calls = 50
    return llm


def _make_hypothesis(**overrides) -> Hypothesis:
    defaults = {
        "id": "H-001",
        "finding_ids": ["F-001"],
        "attack_vector": "reentrancy",
        "preconditions": ["No reentrancy guard", "ETH pool > 100 ETH"],
        "impact": "Complete drain of pool funds",
        "severity": Severity.CRITICAL,
        "exploitability": 0.85,
        "poc_strategy": "Deploy attacker contract with fallback re-entry",
        "target_functions": ["Vault.withdraw"],
        "root_cause": "External call before state update",
    }
    defaults.update(overrides)
    return Hypothesis(**defaults)


def _make_poc_result(**overrides) -> PoCResult:
    defaults = {
        "hypothesis_id": "H-001",
        "test_name": "test_reentrancy_exploit",
        "test_file": "output/poc/H-001.t.sol",
        "compiled": True,
        "passed": True,
        "gas_used": 250_000,
        "profit_usd": 150_000.0,
        "logs": "[PASS] test_reentrancy_exploit() (gas: 250000)",
        "validated": True,
        "validation_reason": "PoC demonstrates fund drainage",
    }
    defaults.update(overrides)
    return PoCResult(**defaults)


def _make_config(**overrides) -> ScanConfig:
    defaults = {
        "target": "https://github.com/example/vault-protocol",
        "immunefi_program": "vault-protocol",
    }
    defaults.update(overrides)
    return ScanConfig(**defaults)


# ---------------------------------------------------------------------------
# ReportGenerator.generate
# ---------------------------------------------------------------------------


class TestGenerate:
    def test_generates_report_and_file(self, tmp_path):
        llm = _make_llm()
        gen = ReportGenerator(llm=llm, output_dir=tmp_path)
        hyp = _make_hypothesis()
        poc = _make_poc_result()
        cfg = _make_config()

        report, path = gen.generate(hyp, poc, "contract Exploit { }", cfg)

        assert isinstance(report, VulnReport)
        assert report.severity == Severity.CRITICAL
        assert report.immunefi_program == "vault-protocol"
        assert report.poc_code == "contract Exploit { }"
        assert report.poc_result is poc
        assert path.exists()
        assert path.suffix == ".md"
        assert "critical" in path.name

    def test_filename_includes_hypothesis_id(self, tmp_path):
        llm = _make_llm()
        gen = ReportGenerator(llm=llm, output_dir=tmp_path)
        hyp = _make_hypothesis(id="H-042")
        poc = _make_poc_result()
        cfg = _make_config()

        _, path = gen.generate(hyp, poc, "", cfg)

        assert "H-042" in path.name

    def test_llm_called_with_system_prompt(self, tmp_path):
        llm = _make_llm()
        gen = ReportGenerator(llm=llm, output_dir=tmp_path, platform="immunefi")
        hyp = _make_hypothesis()
        poc = _make_poc_result()
        cfg = _make_config()

        gen.generate(hyp, poc, "code", cfg)

        call_args = llm.ask.call_args
        assert "Immunefi" in call_args.kwargs.get(
            "system_prompt", call_args[1] if len(call_args[0]) > 1 else ""
        )

    def test_report_written_to_disk(self, tmp_path):
        llm = _make_llm()
        gen = ReportGenerator(llm=llm, output_dir=tmp_path)
        hyp = _make_hypothesis()
        poc = _make_poc_result()
        cfg = _make_config()

        _, path = gen.generate(hyp, poc, "// PoC code", cfg)

        content = path.read_text()
        assert "Reentrancy" in content

    def test_target_contracts_from_functions(self, tmp_path):
        llm = _make_llm()
        gen = ReportGenerator(llm=llm, output_dir=tmp_path)
        hyp = _make_hypothesis(target_functions=["Pool.deposit", "Pool.withdraw"])
        poc = _make_poc_result()
        cfg = _make_config()

        report, _ = gen.generate(hyp, poc, "", cfg)

        assert report.target_contracts == ["Pool", "Pool"]

    def test_target_contracts_fallback_no_dot(self, tmp_path):
        llm = _make_llm()
        gen = ReportGenerator(llm=llm, output_dir=tmp_path)
        hyp = _make_hypothesis(target_functions=["withdraw"])
        poc = _make_poc_result()
        cfg = _make_config()

        report, _ = gen.generate(hyp, poc, "", cfg)

        assert "withdraw" in report.target_contracts


# ---------------------------------------------------------------------------
# Report parsing
# ---------------------------------------------------------------------------


class TestParseReport:
    def test_title_extracted_from_markdown(self, tmp_path):
        llm = _make_llm()
        gen = ReportGenerator(llm=llm, output_dir=tmp_path)
        hyp = _make_hypothesis()
        poc = _make_poc_result()
        cfg = _make_config()

        report, _ = gen.generate(hyp, poc, "", cfg)

        assert "Reentrancy" in report.title

    def test_sections_extracted(self, tmp_path):
        llm = _make_llm()
        gen = ReportGenerator(llm=llm, output_dir=tmp_path)
        hyp = _make_hypothesis()
        poc = _make_poc_result()
        cfg = _make_config()

        report, _ = gen.generate(hyp, poc, "", cfg)

        assert "reentrancy" in report.summary.lower()
        assert "withdraw" in report.vulnerability_detail.lower()
        assert "drain" in report.impact_detail.lower()
        assert "checks-effects-interactions" in report.remediation.lower()

    def test_fallback_when_no_title(self, tmp_path):
        llm = _make_llm(response="No heading here\nJust text")
        gen = ReportGenerator(llm=llm, output_dir=tmp_path)
        hyp = _make_hypothesis()
        poc = _make_poc_result()
        cfg = _make_config()

        report, _ = gen.generate(hyp, poc, "", cfg)

        # Falls back to hypothesis-based title
        assert "reentrancy" in report.title.lower()

    def test_fallback_when_no_sections(self, tmp_path):
        llm = _make_llm(response="# Title\nNo sections here")
        gen = ReportGenerator(llm=llm, output_dir=tmp_path)
        hyp = _make_hypothesis()
        poc = _make_poc_result()
        cfg = _make_config()

        report, _ = gen.generate(hyp, poc, "", cfg)

        # Falls back to hypothesis fields
        assert report.summary == hyp.impact
        assert report.attack_scenario == hyp.poc_strategy


# ---------------------------------------------------------------------------
# Platform system prompts
# ---------------------------------------------------------------------------


class TestPlatformPrompts:
    def test_cantina_platform(self, tmp_path):
        llm = _make_llm()
        gen = ReportGenerator(llm=llm, output_dir=tmp_path, platform="cantina")
        prompt = gen._get_report_system_prompt()
        assert "Cantina" in prompt

    def test_immunefi_platform(self, tmp_path):
        llm = _make_llm()
        gen = ReportGenerator(llm=llm, output_dir=tmp_path, platform="immunefi")
        prompt = gen._get_report_system_prompt()
        assert "Immunefi" in prompt

    def test_generic_platform(self, tmp_path):
        llm = _make_llm()
        gen = ReportGenerator(llm=llm, output_dir=tmp_path, platform="generic")
        prompt = gen._get_report_system_prompt()
        assert "security researcher" in prompt.lower()

    def test_unknown_platform_falls_back_to_generic(self, tmp_path):
        llm = _make_llm()
        gen = ReportGenerator(llm=llm, output_dir=tmp_path, platform="unknown")
        prompt = gen._get_report_system_prompt()
        assert "security researcher" in prompt.lower()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestProtocolFromTarget:
    def test_github_url(self):
        assert (
            _protocol_from_target("https://github.com/example/vault-protocol")
            == "vault-protocol"
        )

    def test_github_url_with_git_suffix(self):
        assert _protocol_from_target("https://github.com/example/vault.git") == "vault"

    def test_local_path(self):
        assert _protocol_from_target("/home/user/projects/my-defi") == "my-defi"

    def test_trailing_slash(self):
        assert (
            _protocol_from_target("https://github.com/example/protocol/") == "protocol"
        )


class TestExtractTitle:
    def test_extracts_h1(self):
        assert _extract_title("# My Title\n## Section") == "My Title"

    def test_ignores_h2(self):
        assert _extract_title("## Not a title\n# Real Title") == "Real Title"

    def test_empty_on_no_heading(self):
        assert _extract_title("No heading here") == ""


class TestExtractSections:
    def test_extracts_sections(self):
        md = "## Summary\nThe summary.\n## Impact\nThe impact."
        sections = _extract_sections(md)
        assert "summary" in sections
        assert "impact" in sections
        assert sections["summary"] == "The summary."
        assert sections["impact"] == "The impact."

    def test_empty_on_no_sections(self):
        sections = _extract_sections("No sections here")
        assert sections == {}
