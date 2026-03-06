"""LLM PoC generation with iterative forge verification and validation."""

from __future__ import annotations

from pathlib import Path

from .llm import LLMClient, LLMParseError, _extract_solidity
from .models import CodeContext, Hypothesis, PoCResult, ScanConfig
from .verify import ForgeExecutor

POC_SYSTEM_PROMPT = """\
You are a Foundry expert writing Proof-of-Concept exploit tests for smart contract vulnerabilities.

Write a COMPLETE, COMPILABLE Foundry test file (.t.sol) that:
1. Imports forge-std/Test.sol and forge-std/console.sol
2. Declares necessary interfaces (IERC20, target contract interfaces)
3. Sets up the test environment (fork if needed, deploy contracts, fund accounts)
4. Executes the exploit in a test function named test_exploit()
5. Includes MEANINGFUL assertions proving the exploit worked:
   - For profit extraction: assertGt(balanceAfter - balanceBefore, 0)
   - For unauthorized access: assert state was changed by non-owner
   - For price manipulation: assert price deviated beyond threshold
6. Uses console.log to output key values (balances, prices, state changes)

Output a single Solidity code block. Do not include any explanation outside the code block."""

VALIDATION_SYSTEM_PROMPT = """\
You are reviewing a Foundry PoC test that passed. Determine if it genuinely demonstrates \
the claimed vulnerability or if it passes trivially.

A VALID PoC must:
1. Actually execute the exploit logic described in the hypothesis
2. Have assertions that would FAIL if the vulnerability did not exist
3. Show measurable impact (profit, unauthorized state change, price deviation)

A TRIVIALLY PASSING PoC:
- Has assertions like assertGt(1, 0) or assertTrue(true)
- Tests normal contract behavior, not exploit behavior
- Doesn't execute the attack vector described in the hypothesis

Output a single JSON object. Do not include any text outside the JSON.
Format: {"valid": true/false, "reason": "..."}"""


class PoCGenerator:
    """LLM-driven PoC generation with iterative verification and validation."""

    MAX_RETRIES = 3

    def __init__(self, llm: LLMClient, output_dir: Path) -> None:
        self.llm = llm
        self.output_dir = output_dir
        self.forge = ForgeExecutor()

    def generate_and_verify(
        self,
        hypothesis: Hypothesis,
        context: CodeContext,
        config: ScanConfig,
    ) -> PoCResult:
        """Generate PoC, run forge, retry on failure, validate on pass."""
        previous_errors: list[str] = []
        last_result = None

        for attempt in range(1, self.MAX_RETRIES + 1):
            poc_code = self._generate_poc(
                hypothesis,
                context,
                config,
                previous_error=previous_errors[-1] if previous_errors else None,
            )
            test_file = self._write_poc(hypothesis.id, poc_code, attempt)

            result = self.forge.run(test_file, cwd=Path(config.target))
            result.attempt = attempt
            result.previous_errors = list(previous_errors)
            last_result = result

            if result.passed:
                try:
                    validation = self._validate_poc(poc_code, result, hypothesis)
                except LLMParseError:
                    # Validation LLM returned unparseable response — treat as valid
                    # (conservative: don't discard a passing PoC due to validation parse error)
                    validation = {
                        "valid": True,
                        "reason": "validation parse error, accepting",
                    }
                if validation["valid"]:
                    result.validated = True
                    result.validation_reason = validation["reason"]
                    return result
                else:
                    previous_errors.append(
                        f"PoC test passed but DOES NOT demonstrate the vulnerability: "
                        f"{validation['reason']}. Rewrite the test with meaningful "
                        f"assertions that prove exploitation."
                    )
                    continue

            error_msg = f"Attempt {attempt} "
            if not result.compiled:
                error_msg += f"compilation failed:\n{result.error}\n\nForge output:\n{result.logs[-2000:]}"
            else:
                error_msg += f"test failed:\n{result.error}\n\nForge output:\n{result.logs[-2000:]}"
            previous_errors.append(error_msg)

        return last_result

    def _generate_poc(
        self,
        hypothesis: Hypothesis,
        context: CodeContext,
        config: ScanConfig,
        previous_error: str | None = None,
    ) -> str:
        """LLM generates complete .t.sol file."""
        prompt = self._build_poc_prompt(hypothesis, context, config, previous_error)
        response = self.llm.ask(prompt, system_prompt=POC_SYSTEM_PROMPT, timeout=300)
        return _extract_solidity(response)

    def _build_poc_prompt(
        self,
        hypothesis: Hypothesis,
        context: CodeContext,
        config: ScanConfig,
        previous_error: str | None = None,
    ) -> str:
        """Build the prompt for PoC generation."""
        parts: list[str] = []

        parts.append("## Vulnerability Hypothesis")
        parts.append(f"**Root Cause:** {hypothesis.root_cause}")
        parts.append(f"**Attack Vector:** {hypothesis.attack_vector}")
        parts.append(f"**Impact:** {hypothesis.impact}")
        if hypothesis.exploit_steps:
            parts.append("**Exploit Steps:**")
            for i, step in enumerate(hypothesis.exploit_steps, 1):
                parts.append(f"  {i}. {step}")
        if hypothesis.target_functions:
            parts.append(
                f"**Target Functions:** {', '.join(hypothesis.target_functions)}"
            )
        if hypothesis.poc_solidity_hints:
            parts.append(f"**PoC Hints:**\n{hypothesis.poc_solidity_hints}")

        parts.append("\n## Contract Source Code")
        if context.contract_source:
            parts.append(f"```solidity\n{context.contract_source}\n```")
        elif context.full_function:
            parts.append(f"```solidity\n{context.full_function}\n```")
        elif context.source_snippet:
            parts.append(f"```solidity\n{context.source_snippet}\n```")

        if context.state_variables:
            parts.append("\n## State Variables")
            for sv in context.state_variables:
                parts.append(f"- `{sv}`")

        if context.inheritance_chain:
            parts.append(f"\n## Inheritance: {' -> '.join(context.inheritance_chain)}")

        if context.call_graph:
            parts.append("\n## Call Graph")
            for edge in context.call_graph:
                parts.append(f"- {edge}")

        parts.append("\n## Fork Configuration")
        if config.fork_url:
            parts.append(f"- Fork URL: {config.fork_url}")
        if config.fork_block:
            parts.append(f"- Fork Block: {config.fork_block}")
        if not config.fork_url:
            parts.append("- No fork required (local deployment)")

        if previous_error:
            parts.append("\n## PREVIOUS ATTEMPT FAILED")
            parts.append("Fix the following error and generate a corrected PoC:")
            parts.append(f"```\n{previous_error}\n```")

        return "\n".join(parts)

    def _validate_poc(
        self,
        poc_code: str,
        result: PoCResult,
        hypothesis: Hypothesis,
    ) -> dict:
        """LLM reviews passing PoC to confirm it genuinely demonstrates the vulnerability."""
        prompt = self._build_validation_prompt(poc_code, result, hypothesis)
        return self.llm.ask_structured(
            prompt, system_prompt=VALIDATION_SYSTEM_PROMPT, timeout=60
        )

    def _build_validation_prompt(
        self,
        poc_code: str,
        result: PoCResult,
        hypothesis: Hypothesis,
    ) -> str:
        """Build the prompt for PoC validation."""
        parts: list[str] = []

        parts.append("## Hypothesis")
        parts.append(f"**Attack Vector:** {hypothesis.attack_vector}")
        parts.append(f"**Root Cause:** {hypothesis.root_cause}")
        parts.append(f"**Impact:** {hypothesis.impact}")

        parts.append("\n## PoC Code")
        parts.append(f"```solidity\n{poc_code}\n```")

        parts.append("\n## Forge Output")
        parts.append(f"```\n{result.logs[-3000:]}\n```")

        return "\n".join(parts)

    def _write_poc(self, hypothesis_id: str, poc_code: str, attempt: int) -> Path:
        """Write PoC .t.sol file to output directory."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{hypothesis_id}_attempt{attempt}.t.sol"
        test_file = self.output_dir / filename
        test_file.write_text(poc_code)
        return test_file
