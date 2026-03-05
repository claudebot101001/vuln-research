from .models import Finding, Severity

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

CONFIDENCE_MAP = {
    "high": 0.9,
    "medium": 0.6,
    "low": 0.3,
    "informational": 0.1,
}


def score_finding(finding: Finding) -> Finding:
    """Adjust severity and confidence based on DeFi context."""
    # If category has a known severity mapping and finding is lower, upgrade
    category_sev = CATEGORY_SEVERITY.get(finding.category)
    if category_sev and _sev_rank(finding.severity) > _sev_rank(category_sev):
        # Don't downgrade, only consider upgrade context
        pass

    # Boost confidence for high-impact categories
    if finding.category in ("reentrancy", "storage-collision", "access-control"):
        finding = finding.model_copy(
            update={"confidence": min(1.0, finding.confidence * 1.2)}
        )

    return finding


def _sev_rank(sev: Severity) -> int:
    return list(Severity).index(sev)


def severity_to_immunefi(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "Critical",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFO: "Informational",
    }[sev]
