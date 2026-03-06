from .models import Finding, Severity, sev_rank

# Impact weights (higher = more severe)
CATEGORY_SEVERITY = {
    "reentrancy": Severity.HIGH,
    "access-control": Severity.HIGH,
    "oracle-manipulation": Severity.HIGH,
    "flash-loan": Severity.HIGH,
    "unchecked-calls": Severity.MEDIUM,
    "integer-overflow": Severity.HIGH,
    "taint-analysis": Severity.MEDIUM,
    "storage-collision": Severity.CRITICAL,
}


def score_finding(finding: Finding) -> Finding:
    """Adjust severity and confidence based on DeFi context."""
    # Boost confidence for high-impact categories
    if finding.category in ("reentrancy", "storage-collision", "access-control"):
        finding = finding.model_copy(
            update={"confidence": min(1.0, finding.confidence * 1.2)}
        )

    return finding


def severity_to_immunefi(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "Critical",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFO: "Informational",
    }[sev]
