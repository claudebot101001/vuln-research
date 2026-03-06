"""Phase 7: LLM-generated vulnerability report."""

from __future__ import annotations

from pathlib import Path

from .llm import LLMClient
from .models import Hypothesis, PoCResult, ScanConfig, Severity, VulnReport

REPORT_SYSTEM_PROMPT_CANTINA = """\
You are a senior smart contract security researcher writing a vulnerability report for \
submission to Cantina. Write in first person as a security researcher.

Follow Cantina's severity classification:
- Critical: Direct loss of funds or permanent freezing of funds
- High: Theft of unclaimed yield, permanent freezing of unclaimed yield, temporary freezing \
of funds, protocol insolvency
- Medium: Smart contract unable to operate, griefing, theft of gas
- Low: Contract fails to deliver promised returns but doesn't lose value

Structure the report with these sections:
# [Title]
## Summary
## Vulnerability Detail
## Impact
## Attack Scenario
## Proof of Concept
## Remediation

Include the PoC Solidity code and forge output in the Proof of Concept section.
Output the full markdown report. Do not include any text outside the markdown."""

REPORT_SYSTEM_PROMPT_IMMUNEFI = """\
You are a senior smart contract security researcher writing a vulnerability report for \
submission to Immunefi. Write in first person as a security researcher.

Follow Immunefi's severity classification:
- Critical: Direct theft of any user funds (principal, not yield), permanent freezing of funds, \
protocol insolvency, theft of unclaimed royalties
- High: Theft of unclaimed yield, permanent freezing of unclaimed yield, temporary freezing \
of funds for 1+ days
- Medium: Smart contract unable to operate, griefing (no profit for attacker at cost to users), \
unbounded gas consumption
- Low: Contract fails to deliver promised returns, function incorrect as per spec

Structure the report with these sections:
# [Title]
## Summary
## Vulnerability Detail
## Impact
## Attack Scenario
## Proof of Concept
## Remediation

Include the PoC Solidity code and forge output in the Proof of Concept section.
Output the full markdown report. Do not include any text outside the markdown."""

REPORT_SYSTEM_PROMPT_GENERIC = """\
You are a senior smart contract security researcher writing a vulnerability report. \
Write in first person as a security researcher.

Severity classification:
- Critical: Direct loss of funds, permanent denial of service
- High: Conditional loss of funds, privilege escalation
- Medium: Loss of functionality, griefing
- Low: Informational, best practice violation

Structure the report with these sections:
# [Title]
## Summary
## Vulnerability Detail
## Impact
## Attack Scenario
## Proof of Concept
## Remediation

Include the PoC Solidity code and forge output in the Proof of Concept section.
Output the full markdown report. Do not include any text outside the markdown."""

_SYSTEM_PROMPTS = {
    "cantina": REPORT_SYSTEM_PROMPT_CANTINA,
    "immunefi": REPORT_SYSTEM_PROMPT_IMMUNEFI,
    "generic": REPORT_SYSTEM_PROMPT_GENERIC,
}


class ReportGenerator:
    """LLM-based vulnerability report generator."""

    def __init__(
        self,
        llm: LLMClient,
        output_dir: Path | None = None,
        platform: str = "cantina",
    ):
        self.llm = llm
        self.output_dir = output_dir or Path("output") / "reports"
        self.platform = platform

    def generate(
        self,
        hypothesis: Hypothesis,
        poc_result: PoCResult,
        poc_code: str,
        config: ScanConfig,
    ) -> tuple[VulnReport, Path]:
        """LLM generates full vulnerability report."""
        prompt = self._build_report_prompt(hypothesis, poc_result, poc_code, config)
        system = self._get_report_system_prompt()
        markdown = self.llm.ask(prompt, system_prompt=system, timeout=120)

        report = self._parse_report(markdown, hypothesis, poc_result, poc_code, config)

        self.output_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{hypothesis.id}_{report.severity.value}_report.md"
        output_path = self.output_dir / filename
        output_path.write_text(markdown)

        return report, output_path

    def _get_report_system_prompt(self) -> str:
        """Platform-specific report system prompt."""
        return _SYSTEM_PROMPTS.get(self.platform, REPORT_SYSTEM_PROMPT_GENERIC)

    def _build_report_prompt(
        self,
        hypothesis: Hypothesis,
        poc_result: PoCResult,
        poc_code: str,
        config: ScanConfig,
    ) -> str:
        """Build the prompt for report generation."""
        parts: list[str] = []

        parts.append("Generate a vulnerability report for the following finding.\n")

        parts.append("## Vulnerability Details")
        parts.append(f"**Severity:** {hypothesis.severity.value}")
        parts.append(f"**Attack Vector:** {hypothesis.attack_vector}")
        parts.append(f"**Root Cause:** {hypothesis.root_cause}")
        parts.append(f"**Impact:** {hypothesis.impact}")
        parts.append(f"**Target Functions:** {', '.join(hypothesis.target_functions)}")
        if hypothesis.preconditions:
            parts.append("**Preconditions:**")
            for p in hypothesis.preconditions:
                parts.append(f"- {p}")
        if hypothesis.exploit_steps:
            parts.append("**Exploit Steps:**")
            for i, step in enumerate(hypothesis.exploit_steps, 1):
                parts.append(f"  {i}. {step}")

        parts.append("\n## Target Protocol")
        parts.append(
            f"**Protocol:** {config.immunefi_program or _protocol_from_target(config.target)}"
        )

        parts.append("\n## PoC Code")
        parts.append(f"```solidity\n{poc_code}\n```")

        parts.append("\n## Forge Output")
        parts.append(f"```\n{poc_result.logs[-3000:]}\n```")

        if poc_result.gas_used:
            parts.append(f"\n**Gas Used:** {poc_result.gas_used}")
        if poc_result.profit_usd:
            parts.append(f"**Estimated Profit:** ${poc_result.profit_usd:,.2f}")

        return "\n".join(parts)

    def _parse_report(
        self,
        markdown: str,
        hypothesis: Hypothesis,
        poc_result: PoCResult,
        poc_code: str,
        config: ScanConfig,
    ) -> VulnReport:
        """Parse LLM-generated markdown into VulnReport model."""
        title = _extract_title(markdown) or (
            f"{hypothesis.attack_vector} in {', '.join(hypothesis.target_functions)}"
        )

        sections = _extract_sections(markdown)

        target_contracts = []
        for func in hypothesis.target_functions:
            if "." in func:
                target_contracts.append(func.split(".")[0])
            else:
                target_contracts.append(func)
        if not target_contracts:
            target_contracts = config.scope_contracts or ["Unknown"]

        return VulnReport(
            title=title,
            severity=hypothesis.severity,
            target_protocol=config.immunefi_program
            or _protocol_from_target(config.target),
            target_contracts=target_contracts,
            summary=sections.get("summary", hypothesis.impact),
            vulnerability_detail=sections.get(
                "vulnerability detail", hypothesis.attack_vector
            ),
            impact_detail=sections.get("impact", hypothesis.impact),
            attack_scenario=sections.get("attack scenario", hypothesis.poc_strategy),
            poc_code=poc_code,
            poc_result=poc_result,
            remediation=sections.get(
                "remediation", "Review and apply security best practices."
            ),
            immunefi_program=config.immunefi_program,
        )


def _protocol_from_target(target: str) -> str:
    """Extract protocol name from target URL or path."""
    name = target.rstrip("/").split("/")[-1].replace(".git", "")
    return name


def _extract_title(markdown: str) -> str:
    """Extract the first H1 heading from markdown."""
    for line in markdown.split("\n"):
        line = line.strip()
        if line.startswith("# ") and not line.startswith("## "):
            return line[2:].strip()
    return ""


def _extract_sections(markdown: str) -> dict[str, str]:
    """Extract H2 sections from markdown into a dict keyed by lowercase heading."""
    sections: dict[str, str] = {}
    current_heading = ""
    current_lines: list[str] = []

    for line in markdown.split("\n"):
        stripped = line.strip()
        if stripped.startswith("## "):
            if current_heading:
                sections[current_heading] = "\n".join(current_lines).strip()
            current_heading = stripped[3:].strip().lower()
            current_lines = []
        elif current_heading:
            current_lines.append(line)

    if current_heading:
        sections[current_heading] = "\n".join(current_lines).strip()

    return sections
