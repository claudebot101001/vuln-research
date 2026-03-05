"""Phase 2: Hypothesis generation from static analysis findings."""

import hashlib
from collections import defaultdict

from .models import Finding, Hypothesis, ScanConfig, Severity

# Base exploitability scores per category
CATEGORY_BASE_SCORE: dict[str, float] = {
    "reentrancy": 0.7,
    "access-control": 0.8,
    "oracle-manipulation": 0.6,
    "flash-loan": 0.7,
    "unchecked-calls": 0.4,
    "integer-overflow": 0.5,
    "storage-collision": 0.6,
    "taint-analysis": 0.5,
}

# Structured hypothesis templates per category
_TEMPLATES: dict[str, dict[str, object]] = {
    "reentrancy": {
        "attack_vector": "External call before state update allows attacker to re-enter and drain funds",
        "preconditions": [
            "Contract performs external call before updating state",
            "No reentrancy guard on vulnerable function",
            "Sufficient balance in contract to drain",
        ],
        "impact": "Complete fund drainage via recursive re-entry",
        "poc_strategy": "Deploy attacker contract with fallback that re-enters the vulnerable function",
        "needs_fork": False,
    },
    "access-control": {
        "attack_vector": "Missing or insufficient authorization allows unauthorized state change or fund theft",
        "preconditions": [
            "Privileged function lacks access control modifier",
            "Attacker can call function directly",
        ],
        "impact": "Unauthorized state modification or fund extraction",
        "poc_strategy": "Call unprotected function from unauthorized address to modify state or extract funds",
        "needs_fork": False,
    },
    "oracle-manipulation": {
        "attack_vector": "Stale or manipulable price oracle enables flash loan sandwich attack",
        "preconditions": [
            "Protocol uses spot price or manipulable oracle",
            "Price can be moved within a single transaction",
            "Sufficient liquidity to execute flash loan",
        ],
        "impact": "Profit extraction via price manipulation in a single transaction",
        "poc_strategy": "Flash loan to manipulate oracle price, exploit mispricing, repay loan in single tx",
        "needs_fork": True,
    },
    "flash-loan": {
        "attack_vector": "Balance-dependent logic exploitable via single-transaction flash loan",
        "preconditions": [
            "Contract logic depends on token balance or reserves",
            "Flash loan providers available for required tokens",
        ],
        "impact": "Single-transaction exploitation bypassing balance assumptions",
        "poc_strategy": "Borrow via flash loan, trigger balance-dependent logic, extract profit, repay",
        "needs_fork": True,
    },
    "unchecked-calls": {
        "attack_vector": "Silent call failure leads to stuck funds or inconsistent state",
        "preconditions": [
            "Low-level call return value not checked",
            "Failure path leaves contract in inconsistent state",
        ],
        "impact": "Funds stuck in contract or incorrect state transitions",
        "poc_strategy": "Force external call to fail and verify contract enters inconsistent state",
        "needs_fork": False,
    },
    "integer-overflow": {
        "attack_vector": "Arithmetic overflow bypasses intended limits or invariants",
        "preconditions": [
            "Unchecked arithmetic on user-controlled input",
            "Solidity version < 0.8.0 or unchecked block used",
        ],
        "impact": "Bypassed balance checks, minting limits, or access controls",
        "poc_strategy": "Supply crafted input that causes overflow to bypass validation checks",
        "needs_fork": False,
    },
    "storage-collision": {
        "attack_vector": "Proxy storage slot collision corrupts state or escalates privileges",
        "preconditions": [
            "Proxy and implementation share storage slot layout",
            "Upgrade or initialization can overwrite critical slots",
        ],
        "impact": "Corrupted contract state or unauthorized privilege escalation",
        "poc_strategy": "Trigger storage write that overlaps with privileged slot in proxy layout",
        "needs_fork": False,
    },
    "taint-analysis": {
        "attack_vector": "User-controlled input flows to sensitive sink enabling arbitrary execution",
        "preconditions": [
            "Unsanitized user input reaches delegatecall, selfdestruct, or storage write",
            "No input validation on tainted data path",
        ],
        "impact": "Arbitrary code execution or contract destruction",
        "poc_strategy": "Craft malicious input that flows through tainted path to trigger sensitive operation",
        "needs_fork": False,
    },
}

_DEFAULT_TEMPLATE: dict[str, object] = {
    "attack_vector": "Potential vulnerability identified by static analysis",
    "preconditions": ["Findings indicate anomalous code pattern"],
    "impact": "Impact depends on specific code context",
    "poc_strategy": "Manual review and targeted testing of flagged code paths",
    "needs_fork": False,
}


def _sev_rank(sev: Severity) -> int:
    """Lower rank = higher severity."""
    return list(Severity).index(sev)


def _highest_severity(findings: list[Finding]) -> Severity:
    """Return the most severe severity among findings."""
    return min(findings, key=lambda f: _sev_rank(f.severity)).severity


def _make_id(group_key: str) -> str:
    """Deterministic hypothesis ID from group key."""
    h = hashlib.sha256(group_key.encode()).hexdigest()[:12]
    return f"H-{h}"


class HypothesisEngine:
    def __init__(self, findings: list[Finding], config: ScanConfig | None = None):
        self.findings = findings
        self.config = config

    def generate(self) -> list[Hypothesis]:
        """Generate hypotheses from findings, sorted by exploitability * severity_rank."""
        if not self.findings:
            return []

        groups = self._group_findings()
        cross_links = self._correlate_cross_contract(groups)

        # Merge cross-contract correlated groups
        merged = self._merge_correlated(groups, cross_links)

        hypotheses = []
        for group_key, findings in merged.items():
            h = self._make_hypothesis(group_key, findings)
            hypotheses.append(h)

        # Sort: higher exploitability * lower sev_rank = first
        # Use negative product so highest value comes first
        hypotheses.sort(
            key=lambda h: -(h.exploitability * (len(Severity) - _sev_rank(h.severity)))
        )
        return hypotheses

    def _group_findings(self) -> dict[str, list[Finding]]:
        """Group findings by (contract, category)."""
        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in self.findings:
            key = f"{f.contract}::{f.category}"
            groups[key].append(f)
        return dict(groups)

    def _correlate_cross_contract(
        self, groups: dict[str, list[Finding]]
    ) -> list[tuple[str, str]]:
        """Find pairs of groups in different contracts but same category,
        connected by shared file paths or function references."""
        # Index groups by category
        by_category: dict[str, list[str]] = defaultdict(list)
        for key in groups:
            _, category = key.split("::", 1)
            by_category[category].append(key)

        correlations: list[tuple[str, str]] = []
        for category, keys in by_category.items():
            if len(keys) < 2:
                continue
            for i in range(len(keys)):
                for j in range(i + 1, len(keys)):
                    if self._groups_connected(groups[keys[i]], groups[keys[j]]):
                        correlations.append((keys[i], keys[j]))
        return correlations

    def _groups_connected(
        self, group_a: list[Finding], group_b: list[Finding]
    ) -> bool:
        """Check if two groups share file paths or function references."""
        paths_a = {f.file_path for f in group_a}
        paths_b = {f.file_path for f in group_b}
        if paths_a & paths_b:
            return True

        funcs_a = {f.function for f in group_a if f.function}
        funcs_b = {f.function for f in group_b if f.function}
        if funcs_a & funcs_b:
            return True

        return False

    def _merge_correlated(
        self,
        groups: dict[str, list[Finding]],
        cross_links: list[tuple[str, str]],
    ) -> dict[str, list[Finding]]:
        """Merge cross-contract correlated groups into combined groups."""
        if not cross_links:
            return dict(groups)

        # Union-Find to merge connected groups
        parent: dict[str, str] = {k: k for k in groups}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        for a, b in cross_links:
            union(a, b)

        # Collect merged groups
        merged: dict[str, list[Finding]] = defaultdict(list)
        for key, findings in groups.items():
            root = find(key)
            merged[root].extend(findings)
        return dict(merged)

    def _make_hypothesis(
        self, group_key: str, findings: list[Finding]
    ) -> Hypothesis:
        """Create a Hypothesis from a group of related findings."""
        # Extract category from the group key (first component's category)
        category = group_key.split("::", 1)[1] if "::" in group_key else "other"

        template = _TEMPLATES.get(category, _DEFAULT_TEMPLATE)
        severity = _highest_severity(findings)
        exploitability = self._score_exploitability(findings, category)

        target_functions = list(
            dict.fromkeys(f.function for f in findings if f.function)
        )

        needs_fork = bool(template["needs_fork"])
        fork_block = None
        if needs_fork and self.config and self.config.fork_block:
            fork_block = self.config.fork_block

        return Hypothesis(
            id=_make_id(group_key),
            finding_ids=[f.id for f in findings],
            attack_vector=str(template["attack_vector"]),
            preconditions=list(template["preconditions"]),
            impact=str(template["impact"]),
            severity=severity,
            exploitability=exploitability,
            poc_strategy=str(template["poc_strategy"]),
            target_functions=target_functions,
            needs_fork=needs_fork,
            fork_block=fork_block,
        )

    def _score_exploitability(
        self, findings: list[Finding], category: str
    ) -> float:
        """Score exploitability based on category base score, corroboration, and fork requirement."""
        base = CATEGORY_BASE_SCORE.get(category, 0.3)

        # Corroboration bonus: more findings = more confidence (diminishing returns)
        count = len(findings)
        if count >= 3:
            corroboration = 0.15
        elif count == 2:
            corroboration = 0.1
        else:
            corroboration = 0.0

        # Fork penalty: needing a fork means harder to exploit in practice
        template = _TEMPLATES.get(category, _DEFAULT_TEMPLATE)
        fork_penalty = 0.1 if template["needs_fork"] else 0.0

        score = base + corroboration - fork_penalty
        return max(0.0, min(1.0, round(score, 4)))
