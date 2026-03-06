from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


def sev_rank(sev: Severity) -> int:
    """Lower rank = higher severity. Canonical location (no more duplicates)."""
    return list(Severity).index(sev)


class FindingSource(str, Enum):
    SLITHER = "slither"
    SEMGREP = "semgrep"
    MANUAL = "manual"


class Finding(BaseModel):
    id: str
    source: FindingSource
    detector: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    description: str
    contract: str
    function: str | None = None
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    code_snippet: str = ""
    category: str  # reentrancy, access-control, oracle, etc.
    raw_output: dict = Field(default_factory=dict)


class Hypothesis(BaseModel):
    id: str
    finding_ids: list[str]
    attack_vector: str
    preconditions: list[str]
    impact: str
    severity: Severity
    exploitability: float = Field(ge=0.0, le=1.0)
    poc_strategy: str
    target_functions: list[str]
    needs_fork: bool = False
    fork_block: int | None = None
    # v2 extensions (all defaulted for backwards compat)
    root_cause: str = ""
    exploit_steps: list[str] = Field(default_factory=list)
    required_contracts: list[str] = Field(default_factory=list)
    poc_solidity_hints: str = ""


class PoCResult(BaseModel):
    hypothesis_id: str
    test_name: str
    test_file: str
    compiled: bool
    passed: bool
    gas_used: int | None = None
    profit_usd: float | None = None
    logs: str = ""
    error: str | None = None
    # v2 extensions (all defaulted for backwards compat)
    attempt: int = 1
    previous_errors: list[str] = Field(default_factory=list)
    validated: bool = False
    validation_reason: str = ""


class VulnReport(BaseModel):
    title: str
    severity: Severity
    target_protocol: str
    target_contracts: list[str]
    summary: str
    vulnerability_detail: str
    impact_detail: str
    attack_scenario: str
    poc_code: str
    poc_result: PoCResult | None = None
    remediation: str
    references: list[str] = []
    immunefi_program: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanConfig(BaseModel):
    target: str
    scope_contracts: list[str] = []
    exclude_patterns: list[str] = Field(
        default_factory=lambda: ["test/", "script/", "lib/", "node_modules/"]
    )
    solc_version: str | None = None
    min_severity: Severity = Severity.LOW
    min_confidence: float = 0.3
    fork_url: str | None = None
    fork_block: int | None = None
    immunefi_program: str | None = None
    # v2 extensions (all defaulted for backwards compat)
    max_llm_calls: int = 50
    force: bool = False
    no_cache: bool = False
    platform: str = "cantina"


# --- New v2 models ---


class FreshnessError(Exception):
    """Raised when freshness check fails and --force not set."""


class FreshnessReport(BaseModel):
    stale_files: list[dict] = Field(default_factory=list)
    superseded_files: list[dict] = Field(default_factory=list)
    scope_drift: list[dict] = Field(default_factory=list)
    is_clean: bool = True


class AcquiredTarget(BaseModel):
    path: Path
    solc_version: str | None = None
    freshness: FreshnessReport = Field(default_factory=FreshnessReport)


class CodeContext(BaseModel):
    finding_id: str
    source_snippet: str = ""
    full_function: str = ""
    contract_source: str = ""
    call_graph: list[str] = Field(default_factory=list)
    state_variables: list[str] = Field(default_factory=list)
    inheritance_chain: list[str] = Field(default_factory=list)
    related_functions: list[str] = Field(default_factory=list)
