from pathlib import Path

import pytest

from pipeline.models import Hypothesis, PoCResult, ScanConfig, Severity, VulnReport
from pipeline.report import (
    ReportGenerator,
    _build_vuln_detail,
    _protocol_from_target,
    _suggest_remediation,
)
from pipeline.scoring import severity_to_immunefi


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
# ReportGenerator.build_report
# ---------------------------------------------------------------------------

class TestBuildReport:
    def test_basic_report(self):
        gen = ReportGenerator()
        hyp = _make_hypothesis()
        poc = _make_poc_result()
        cfg = _make_config()

        report = gen.build_report(hyp, poc, cfg, poc_code="contract Exploit { }")

        assert isinstance(report, VulnReport)
        assert report.severity == Severity.CRITICAL
        assert report.immunefi_program == "vault-protocol"
        assert "Vault" in report.target_contracts
        assert report.poc_result is poc
        assert report.poc_code == "contract Exploit { }"

    def test_report_without_poc(self):
        gen = ReportGenerator()
        hyp = _make_hypothesis()
        cfg = _make_config()

        report = gen.build_report(hyp, None, cfg)

        assert report.poc_result is None
        assert report.poc_code == ""

    def test_target_contracts_from_functions(self):
        gen = ReportGenerator()
        hyp = _make_hypothesis(target_functions=["Pool.deposit", "Pool.withdraw"])
        cfg = _make_config()

        report = gen.build_report(hyp, None, cfg)

        assert report.target_contracts == ["Pool", "Pool"]

    def test_target_contracts_fallback_to_scope(self):
        gen = ReportGenerator()
        hyp = _make_hypothesis(target_functions=["withdraw"])
        cfg = _make_config(scope_contracts=["Vault.sol", "Router.sol"])

        report = gen.build_report(hyp, None, cfg)

        # No dot in "withdraw", so it becomes the contract name directly
        assert "withdraw" in report.target_contracts

    def test_title_includes_attack_vector(self):
        gen = ReportGenerator()
        hyp = _make_hypothesis(attack_vector="flash_loan + reentrancy")
        cfg = _make_config()

        report = gen.build_report(hyp, None, cfg)

        assert "flash_loan + reentrancy" in report.title


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

class TestRenderMarkdown:
    def test_markdown_contains_sections(self):
        gen = ReportGenerator()
        hyp = _make_hypothesis()
        poc = _make_poc_result()
        cfg = _make_config()

        report = gen.build_report(hyp, poc, cfg, poc_code="contract Exploit { }")
        md = gen.render_markdown(report)

        assert "# " in md
        assert "## Summary" in md
        assert "## Vulnerability Details" in md
        assert "## Impact" in md
        assert "## Attack Scenario" in md
        assert "## Proof of Concept" in md
        assert "## Remediation" in md
        assert "contract Exploit { }" in md

    def test_markdown_severity_label(self):
        gen = ReportGenerator()
        hyp = _make_hypothesis(severity=Severity.HIGH)
        cfg = _make_config()

        report = gen.build_report(hyp, None, cfg)
        md = gen.render_markdown(report)

        assert "High" in md

    def test_markdown_poc_results_table(self):
        gen = ReportGenerator()
        hyp = _make_hypothesis()
        poc = _make_poc_result(gas_used=500_000, profit_usd=75_000.0)
        cfg = _make_config()

        report = gen.build_report(hyp, poc, cfg)
        md = gen.render_markdown(report)

        assert "### PoC Results" in md
        assert "500000" in md
        assert "75000.00" in md

    def test_markdown_without_poc_result(self):
        gen = ReportGenerator()
        hyp = _make_hypothesis()
        cfg = _make_config()

        report = gen.build_report(hyp, None, cfg)
        md = gen.render_markdown(report)

        assert "### PoC Results" not in md

    def test_markdown_references(self):
        gen = ReportGenerator()
        hyp = _make_hypothesis()
        cfg = _make_config()

        report = gen.build_report(hyp, None, cfg)
        report = report.model_copy(
            update={"references": ["https://swcregistry.io/docs/SWC-107"]}
        )
        md = gen.render_markdown(report)

        assert "## References" in md
        assert "SWC-107" in md


# ---------------------------------------------------------------------------
# Full generate (file output)
# ---------------------------------------------------------------------------

class TestGenerate:
    def test_generates_file(self, tmp_path):
        gen = ReportGenerator(output_dir=tmp_path)
        hyp = _make_hypothesis()
        poc = _make_poc_result()
        cfg = _make_config()

        report, path = gen.generate(hyp, poc, cfg, poc_code="// PoC code")

        assert path.exists()
        assert path.suffix == ".md"
        assert "critical" in path.name
        content = path.read_text()
        assert "// PoC code" in content

    def test_filename_includes_hypothesis_id(self, tmp_path):
        gen = ReportGenerator(output_dir=tmp_path)
        hyp = _make_hypothesis(id="H-042")
        cfg = _make_config()

        _, path = gen.generate(hyp, None, cfg)

        assert "H-042" in path.name


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

class TestProtocolFromTarget:
    def test_github_url(self):
        assert _protocol_from_target("https://github.com/example/vault-protocol") == "vault-protocol"

    def test_github_url_with_git_suffix(self):
        assert _protocol_from_target("https://github.com/example/vault.git") == "vault"

    def test_local_path(self):
        assert _protocol_from_target("/home/user/projects/my-defi") == "my-defi"

    def test_trailing_slash(self):
        assert _protocol_from_target("https://github.com/example/protocol/") == "protocol"


class TestBuildVulnDetail:
    def test_contains_attack_vector(self):
        hyp = _make_hypothesis(attack_vector="reentrancy via fallback")
        detail = _build_vuln_detail(hyp)
        assert "reentrancy via fallback" in detail

    def test_contains_preconditions(self):
        hyp = _make_hypothesis(preconditions=["Pool has > 100 ETH"])
        detail = _build_vuln_detail(hyp)
        assert "Pool has > 100 ETH" in detail

    def test_contains_exploitability(self):
        hyp = _make_hypothesis(exploitability=0.85)
        detail = _build_vuln_detail(hyp)
        assert "85.0%" in detail


class TestSuggestRemediation:
    def test_reentrancy(self):
        r = _suggest_remediation("reentrancy")
        assert "ReentrancyGuard" in r

    def test_flash_loan(self):
        r = _suggest_remediation("flash loan attack")
        assert "TWAP" in r

    def test_access_control(self):
        r = _suggest_remediation("access control bypass")
        assert "AccessControl" in r

    def test_oracle(self):
        r = _suggest_remediation("oracle manipulation")
        assert "TWAP" in r

    def test_overflow(self):
        r = _suggest_remediation("integer overflow")
        assert "0.8.0" in r

    def test_unknown_returns_generic(self):
        r = _suggest_remediation("novel attack type")
        assert "best practices" in r
