"""LLM-based false positive filtering with adaptive batch sizing."""

from __future__ import annotations

import logging

from .context import ContextExtractor
from .llm import LLMClient, LLMParseError
from .models import CodeContext, Finding

logger = logging.getLogger(__name__)

MAX_TRIAGE_TOKENS = 30_000  # Conservative limit for batch prompt

TRIAGE_SYSTEM_PROMPT = """\
You are a senior smart contract security researcher triaging static analysis findings.
For each finding, determine if it is a true positive (likely exploitable vulnerability)
or a false positive (benign code pattern that triggered the detector).

Consider:
- Is the flagged pattern actually reachable by an attacker?
- Are there existing protections (modifiers, checks) that the static analyzer missed?
- Is this a known-safe pattern (e.g., reentrancy guard present but detector doesn't recognize it)?

Output a single JSON object. Do not include any text outside the JSON.
Format: {"findings": [{"id": "...", "keep": true/false, "confidence": 0.0-1.0, "reason": "..."}]}"""


class Triager:
    """Batch-filters static analysis findings using LLM triage."""

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def triage(
        self,
        findings: list[Finding],
        contexts: list[CodeContext],
        context_extractor: ContextExtractor,
    ) -> list[Finding]:
        """Batch-filter findings using LLM. Adaptive batch sizing."""
        if not findings:
            return []

        pairs = list(zip(findings, contexts))
        batches = self._adaptive_batch(pairs, context_extractor)
        kept: list[Finding] = []
        for batch in batches:
            results = self._triage_batch(batch)
            kept.extend(results)
        return kept

    def _adaptive_batch(
        self,
        pairs: list[tuple[Finding, CodeContext]],
        context_extractor: ContextExtractor,
    ) -> list[list[tuple[Finding, CodeContext]]]:
        """Build batches that fit within token budget.

        Uses abbreviated context for triage (source_snippet + truncated function
        + limited call graph/state vars, no contract_source/related_functions).
        """
        batches: list[list[tuple[Finding, CodeContext]]] = []
        current_batch: list[tuple[Finding, CodeContext]] = []
        current_tokens = 0

        for finding, context in pairs:
            abbreviated = _abbreviate_context(context)
            token_est = context_extractor.estimate_token_count(abbreviated) + 200
            if current_tokens + token_est > MAX_TRIAGE_TOKENS and current_batch:
                batches.append(current_batch)
                current_batch = []
                current_tokens = 0
            current_batch.append((finding, abbreviated))
            current_tokens += token_est

        if current_batch:
            batches.append(current_batch)
        return batches

    def _triage_batch(self, batch: list[tuple[Finding, CodeContext]]) -> list[Finding]:
        """Send a batch of findings to the LLM for triage filtering."""
        prompt = self._build_triage_prompt(batch)
        try:
            response = self.llm.ask_structured(
                prompt, system_prompt=TRIAGE_SYSTEM_PROMPT, timeout=180
            )
        except LLMParseError as e:
            logger.warning(
                "LLM triage parse error, keeping all %d findings in batch: %s",
                len(batch),
                e,
            )
            return [f for f, _ in batch]

        kept_ids = set()
        for f in response.get("findings", []):
            if f.get("keep"):
                kept_ids.add(f["id"])

        return [f for f, _ in batch if f.id in kept_ids]

    def _build_triage_prompt(self, batch: list[tuple[Finding, CodeContext]]) -> str:
        """Format findings + abbreviated context into a triage prompt."""
        parts: list[str] = []
        parts.append(
            f"Triage the following {len(batch)} static analysis finding(s). "
            "For each, decide whether to keep (true positive) or discard (false positive).\n"
        )

        for i, (finding, context) in enumerate(batch, 1):
            parts.append(f"--- Finding {i} ---")
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

            if context.source_snippet:
                parts.append(
                    f"\nSource snippet:\n```solidity\n{context.source_snippet}\n```"
                )
            if context.full_function:
                parts.append(
                    f"\nFunction body:\n```solidity\n{context.full_function}\n```"
                )
            if context.call_graph:
                parts.append(
                    f"\nCall graph:\n"
                    + "\n".join(f"  {cg}" for cg in context.call_graph)
                )
            if context.state_variables:
                parts.append(
                    f"\nState variables:\n"
                    + "\n".join(f"  {sv}" for sv in context.state_variables)
                )
            if context.inheritance_chain:
                parts.append(f"\nInheritance: {' -> '.join(context.inheritance_chain)}")
            parts.append("")

        return "\n".join(parts)


def _abbreviate_context(context: CodeContext) -> CodeContext:
    """Create an abbreviated context suitable for triage (reduced token usage)."""
    return CodeContext(
        finding_id=context.finding_id,
        source_snippet=context.source_snippet,
        full_function=context.full_function[:500],
        contract_source="",
        call_graph=context.call_graph[:5],
        state_variables=context.state_variables[:10],
        inheritance_chain=context.inheritance_chain,
        related_functions=[],
    )
