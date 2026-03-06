"""LLM deep analysis — per-finding vulnerability assessment."""

from __future__ import annotations

import hashlib
import logging

from .llm import LLMClient, LLMParseError
from .models import CodeContext, Finding, Hypothesis, Severity

logger = logging.getLogger(__name__)

ANALYSIS_SYSTEM_PROMPT = """\
You are an expert smart contract vulnerability researcher.
Analyze the following code and finding to determine if it represents an exploitable vulnerability.

Your analysis must be CODE-SPECIFIC — reference exact function names, variable names, and line numbers.
Do not produce generic descriptions. If you cannot identify a specific exploit path, say so.

Output a single JSON object. Do not include any text outside the JSON.
Fields:
- exploitable: bool
- root_cause: str (why the bug exists, referencing specific code)
- attack_vector: str (how an attacker exploits it, step by step)
- preconditions: list[str] (concrete on-chain conditions required)
- impact: str (what damage is possible, quantified if possible)
- severity: "critical"|"high"|"medium"|"low"
- exploitability_score: float 0.0-1.0
- poc_strategy: str (specific functions to call, parameters to use)
- target_functions: list[str] (contract.function format)
- exploit_steps: list[str] (ordered steps for exploitation)
- needs_fork: bool (requires mainnet fork?)
- required_contracts: list[str] (external contract addresses/interfaces needed)
- poc_solidity_hints: str (draft Solidity snippet for key exploit logic)"""


class Analyzer:
    """Deep per-finding LLM analysis producing Hypothesis objects."""

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def analyze(self, finding: Finding, context: CodeContext) -> Hypothesis | None:
        """Deep analysis of a single finding. Returns None if not exploitable."""
        prompt = self._build_analysis_prompt(finding, context)
        try:
            response = self.llm.ask_structured(
                prompt, system_prompt=ANALYSIS_SYSTEM_PROMPT, timeout=120
            )
        except LLMParseError as e:
            logger.warning("LLM analysis parse error for %s: %s", finding.id, e)
            return None

        if not response.get("exploitable"):
            return None

        return Hypothesis(
            id=_make_id(finding.id),
            finding_ids=[finding.id],
            attack_vector=response["attack_vector"],
            preconditions=response["preconditions"],
            impact=response["impact"],
            severity=Severity(response["severity"]),
            exploitability=response["exploitability_score"],
            poc_strategy=response["poc_strategy"],
            target_functions=response["target_functions"],
            needs_fork=response.get("needs_fork", False),
            fork_block=response.get("fork_block"),
            root_cause=response["root_cause"],
            exploit_steps=response["exploit_steps"],
            required_contracts=response.get("required_contracts", []),
            poc_solidity_hints=response.get("poc_solidity_hints", ""),
        )

    def _build_analysis_prompt(self, finding: Finding, context: CodeContext) -> str:
        """Format the full context into an analysis prompt."""
        parts: list[str] = []
        parts.append(
            "Analyze the following finding and code context for exploitability.\n"
        )

        parts.append("## Finding")
        parts.append(f"ID: {finding.id}")
        parts.append(f"Detector: {finding.detector}")
        parts.append(f"Severity: {finding.severity.value}")
        parts.append(f"Category: {finding.category}")
        parts.append(f"Title: {finding.title}")
        parts.append(f"Description: {finding.description}")
        parts.append(f"Contract: {finding.contract}")
        if finding.function:
            parts.append(f"Function: {finding.function}")
        parts.append(f"File: {finding.file_path}:{finding.line_start or '?'}")

        parts.append("\n## Source Snippet")
        if context.source_snippet:
            parts.append(f"```solidity\n{context.source_snippet}\n```")
        else:
            parts.append("(not available)")

        parts.append("\n## Full Function")
        if context.full_function:
            parts.append(f"```solidity\n{context.full_function}\n```")
        else:
            parts.append("(not available)")

        if context.contract_source:
            parts.append("\n## Contract Source")
            parts.append(f"```solidity\n{context.contract_source}\n```")

        if context.call_graph:
            parts.append("\n## Call Graph")
            for cg in context.call_graph:
                parts.append(f"  {cg}")

        if context.state_variables:
            parts.append("\n## State Variables")
            for sv in context.state_variables:
                parts.append(f"  {sv}")

        if context.inheritance_chain:
            parts.append(f"\n## Inheritance: {' -> '.join(context.inheritance_chain)}")

        if context.related_functions:
            parts.append("\n## Related Functions (share state variables)")
            for rf in context.related_functions:
                parts.append(f"  {rf}")

        return "\n".join(parts)


def _make_id(finding_id: str) -> str:
    """Generate a deterministic hypothesis ID from a finding ID."""
    return "H-" + hashlib.sha256(finding_id.encode()).hexdigest()[:12]
