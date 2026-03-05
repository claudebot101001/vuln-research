"""Phase 6: Vulnerability report generation."""

from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from .models import Hypothesis, PoCResult, ScanConfig, Severity, VulnReport
from .scoring import severity_to_immunefi

REPORT_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "reports" / "templates"


class ReportGenerator:
    def __init__(self, output_dir: Path | None = None):
        self.output_dir = output_dir or Path("output") / "reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.env = Environment(
            loader=FileSystemLoader(str(REPORT_TEMPLATES_DIR)),
            keep_trailing_newline=True,
        )

    def build_report(
        self,
        hypothesis: Hypothesis,
        poc_result: PoCResult | None,
        config: ScanConfig,
        poc_code: str = "",
    ) -> VulnReport:
        """Build a VulnReport model from hypothesis, PoC result, and config."""
        # Derive target contracts from hypothesis target_functions
        target_contracts = []
        for func in hypothesis.target_functions:
            if "." in func:
                target_contracts.append(func.split(".")[0])
            else:
                target_contracts.append(func)
        if not target_contracts:
            target_contracts = config.scope_contracts or ["Unknown"]

        return VulnReport(
            title=f"{hypothesis.attack_vector} in {', '.join(hypothesis.target_functions)}",
            severity=hypothesis.severity,
            target_protocol=config.immunefi_program or _protocol_from_target(config.target),
            target_contracts=target_contracts,
            summary=hypothesis.impact,
            vulnerability_detail=_build_vuln_detail(hypothesis),
            impact_detail=hypothesis.impact,
            attack_scenario=hypothesis.poc_strategy,
            poc_code=poc_code,
            poc_result=poc_result,
            remediation=_suggest_remediation(hypothesis.attack_vector),
            immunefi_program=config.immunefi_program,
        )

    def render_markdown(self, report: VulnReport) -> str:
        """Render a VulnReport to Immunefi-formatted markdown."""
        template = self.env.get_template("immunefi_report.md.j2")
        return template.render(
            title=report.title,
            immunefi_severity=severity_to_immunefi(report.severity),
            immunefi_program=report.immunefi_program,
            created_at=report.created_at.strftime("%Y-%m-%d"),
            summary=report.summary,
            target_protocol=report.target_protocol,
            target_contracts=report.target_contracts,
            vulnerability_detail=report.vulnerability_detail,
            impact_detail=report.impact_detail,
            attack_scenario=report.attack_scenario,
            poc_code=report.poc_code,
            poc_result=report.poc_result,
            remediation=report.remediation,
            references=report.references,
        )

    def generate(
        self,
        hypothesis: Hypothesis,
        poc_result: PoCResult | None,
        config: ScanConfig,
        poc_code: str = "",
    ) -> tuple[VulnReport, Path]:
        """Build report model, render markdown, write to file, return both."""
        report = self.build_report(hypothesis, poc_result, config, poc_code)
        markdown = self.render_markdown(report)

        filename = f"{hypothesis.id}_{report.severity.value}_report.md"
        output_path = self.output_dir / filename
        output_path.write_text(markdown)

        return report, output_path


def _protocol_from_target(target: str) -> str:
    """Extract protocol name from target URL or path."""
    name = target.rstrip("/").split("/")[-1].replace(".git", "")
    return name


def _build_vuln_detail(hypothesis: Hypothesis) -> str:
    """Build vulnerability detail string from hypothesis."""
    parts = [f"**Attack Vector**: {hypothesis.attack_vector}"]
    if hypothesis.preconditions:
        parts.append("**Preconditions**:")
        for p in hypothesis.preconditions:
            parts.append(f"- {p}")
    parts.append(f"**Exploitability Score**: {hypothesis.exploitability:.1%}")
    parts.append(f"**Target Functions**: {', '.join(hypothesis.target_functions)}")
    return "\n\n".join(parts)


def _suggest_remediation(attack_vector: str) -> str:
    """Suggest remediation based on attack vector keywords."""
    vector = attack_vector.lower()
    remediations = {
        "reentrancy": "Apply the checks-effects-interactions pattern. Use OpenZeppelin's ReentrancyGuard.",
        "flash": "Add flash loan protection. Use time-weighted average prices (TWAP) for oracle reads.",
        "access": "Implement proper access control using OpenZeppelin's Ownable or AccessControl.",
        "oracle": "Use time-weighted average prices (TWAP). Add staleness checks for Chainlink feeds. Consider using multiple oracle sources.",
        "overflow": "Use Solidity >=0.8.0 with built-in overflow checks. Audit any unchecked blocks carefully.",
        "underflow": "Use Solidity >=0.8.0 with built-in overflow checks. Audit any unchecked blocks carefully.",
    }
    for keyword, remedy in remediations.items():
        if keyword in vector:
            return remedy
    return "Review and apply security best practices for the identified vulnerability class."
