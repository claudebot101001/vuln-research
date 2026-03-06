# Pipeline v2: LLM-Integrated Vulnerability Research

## Problem Statement

The current pipeline produces zero actionable results because:

1. **No LLM analysis** — hypothesize.py maps findings to hardcoded category templates (`_TEMPLATES` dict). Output is generic boilerplate like "External call before state update allows attacker to re-enter" regardless of the actual code.
2. **Unfilled PoC templates** — Jinja2 templates require `{{ target_contract }}`, `{{ oracle_address }}`, `{{ flash_token }}` etc. The orchestrator only passes `fork_url`, `fork_block`, `solc_version`. Jinja2 silently renders empty strings → invalid Solidity → forge "Nothing to compile".
3. **No code context** — Findings are `file:line` references. No function bodies, call graphs, state variables, or inheritance chains are extracted. The hypothesis engine can't reason about code it hasn't seen.
4. **No iterative verification** — forge failure = dead end. No retry loop, no error feedback.
5. **No code freshness verification** — The Rheo incident proved we can audit deprecated/fixed code. No `git log` check, no V2 detection.
6. **Reports from failed verifications** — `orchestrator.py:57` generates reports even when ALL PoCs fail.

### What works and should be kept

- **Slither/Semgrep runners** — `slither_runner.py`, `semgrep_runner.py` correctly invoke tools, parse output, produce `Finding[]`. Well-tested.
- **8 custom detectors** — `analyzers/detectors/*.py` extend Slither's detection.
- **8 Semgrep rules** — `rules/semgrep/*.yaml` catch additional patterns.
- **Data models** — `models.py` Pydantic schemas are clean. Need extension, not replacement.
- **Scoring** — `scoring.py` is simple but functional.
- **Target acquisition** — `scan.py._acquire_target()` handles clone + solc detection.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   1. Acquire  │────▶│   2. Scan     │────▶│  3. Context   │────▶│  4. Triage    │
│   + Freshness │     │  Slither+SG   │     │  Extraction   │     │  LLM Filter   │
└──────────────┘     └──────────────┘     └──────────────┘     └──────┬───────┘
                                                                       │
  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐          │
  │  7. Report   │◀────│  6. Verify    │◀────│  5. Analyze   │◀────────┘
  │  LLM Write   │     │  Forge+Retry  │     │  LLM Hypothe  │
  └──────────────┘     │  + Validate   │     └──────────────┘
                       └──────────────┘

  Cross-cutting: llm.py (Claude CLI wrapper + cost tracking + caching), models.py (shared types)
```

### Data Flow

```
Target URL/Path
  → acquire.py: clone, detect solc, freshness check → ABORT if superseded (unless --force)
  → scan.py: Slither + Semgrep → Finding[]
  → context.py: for each Finding, extract CodeContext (source, call graph, state vars)
  → triage.py: LLM batch call (adaptive sizing) → filter false positives → Finding[] (reduced)
  → analyze.py: LLM per-finding → Hypothesis[] (code-specific, with concrete PoC strategy)
  → poc_gen.py: LLM writes .t.sol → forge verify → feedback loop (max 3) → PoC validation
  → report.py: LLM generates platform-specific report from verified Hypothesis + passing PoC
  → orchestrator.py: coordinates the flow, checkpoints between phases, tracks LLM budget
```

## Module Design

### llm.py — Claude CLI Wrapper + Cost Tracking + Caching

The LLM transport layer. Encapsulates `claude -p` subprocess calls with structured prompt/response handling, cost tracking, and optional response caching.

```python
class LLMError(Exception):
    """Raised when LLM call fails."""

class LLMParseError(LLMError):
    """Raised when JSON extraction fails. Includes raw response."""
    def __init__(self, message: str, raw_response: str):
        super().__init__(message)
        self.raw_response = raw_response

class CostTracker:
    """Tracks LLM call count and estimated cost."""
    def __init__(self, max_calls: int = 50):
        self.max_calls = max_calls
        self.call_count = 0
        self.total_prompt_chars = 0
        self.total_response_chars = 0

    def record(self, prompt_len: int, response_len: int) -> None:
        self.call_count += 1
        self.total_prompt_chars += prompt_len
        self.total_response_chars += response_len

    def check_budget(self) -> None:
        if self.call_count >= self.max_calls:
            raise LLMError(
                f"LLM budget exhausted: {self.call_count}/{self.max_calls} calls used. "
                f"Increase max_llm_calls in config to continue."
            )

    @property
    def estimated_cost_usd(self) -> float:
        # Rough estimate: ~$0.01 per 1k chars input, ~$0.03 per 1k chars output
        return (self.total_prompt_chars * 0.01 + self.total_response_chars * 0.03) / 1000

class LLMClient:
    def __init__(self, default_timeout: int = 180, max_calls: int = 50,
                 cache_dir: Path | None = None):
        self.default_timeout = default_timeout
        self.cost = CostTracker(max_calls)
        self.cache_dir = cache_dir  # None = no caching

    def ask(self, prompt: str, system_prompt: str | None = None,
            timeout: int | None = None) -> str:
        """One-shot claude -p call. Returns text response."""
        # Check budget before calling
        self.cost.check_budget()

        # Check cache
        cache_key = self._cache_key(prompt, system_prompt)
        if self.cache_dir and (cached := self._cache_get(cache_key)):
            return cached

        cmd = ["claude", "-p"]
        if system_prompt:
            cmd.extend(["--system-prompt", system_prompt])
        result = subprocess.run(
            cmd, input=prompt, capture_output=True, text=True,
            timeout=timeout or self.default_timeout,
        )
        if result.returncode != 0:
            raise LLMError(f"claude -p failed: {result.stderr[:500]}")

        response = result.stdout
        self.cost.record(len(prompt), len(response))

        # Write cache
        if self.cache_dir:
            self._cache_put(cache_key, response)

        return response

    def ask_structured(self, prompt: str, system_prompt: str | None = None,
                       timeout: int | None = None) -> dict:
        """Ask and extract JSON from response."""
        response = self.ask(prompt, system_prompt, timeout)
        return _extract_json(response)

    def _cache_key(self, prompt: str, system_prompt: str | None) -> str:
        content = f"{system_prompt or ''}|{prompt}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _cache_get(self, key: str) -> str | None:
        path = self.cache_dir / f"{key}.txt"
        return path.read_text() if path.exists() else None

    def _cache_put(self, key: str, response: str) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        (self.cache_dir / f"{key}.txt").write_text(response)


def _extract_json(text: str) -> dict:
    """Extract JSON from LLM response. Handles common LLM output patterns.

    Strategy (in order):
    1. Try json.loads(text) directly
    2. Extract from ```json ... ``` fences
    3. Extract from ``` ... ``` fences
    4. Find first '{' to last '}' and parse
    5. Raise LLMParseError with raw response
    """
    import json, re

    # 1. Direct parse
    text_stripped = text.strip()
    try:
        return json.loads(text_stripped)
    except json.JSONDecodeError:
        pass

    # 2. JSON code fence
    match = re.search(r'```json\s*\n(.*?)\n\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # 3. Generic code fence
    match = re.search(r'```\s*\n(.*?)\n\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # 4. First '{' to last '}'
    first_brace = text.find('{')
    last_brace = text.rfind('}')
    if first_brace != -1 and last_brace > first_brace:
        try:
            return json.loads(text[first_brace:last_brace + 1])
        except json.JSONDecodeError:
            pass

    # 5. Give up
    raise LLMParseError(
        f"Could not extract JSON from LLM response ({len(text)} chars)",
        raw_response=text
    )


def _extract_solidity(text: str) -> str:
    """Extract Solidity code from LLM response."""
    import re
    match = re.search(r'```solidity\s*\n(.*?)\n\s*```', text, re.DOTALL)
    if match:
        return match.group(1)
    match = re.search(r'```\s*\n(.*?)\n\s*```', text, re.DOTALL)
    if match:
        return match.group(1)
    # If no fences, assume entire response is code
    return text.strip()
```

Key design decisions:
- **`claude -p`** subprocess: No API key needed, uses existing Claude Code auth. ~3-5s overhead per call.
- **Per-call timeout**: Default 180s, callers pass task-specific timeouts (triage: 60s, analysis: 120s, PoC gen: 300s).
- **CostTracker**: Counts calls, aborts when `max_llm_calls` exceeded. Default 50 calls per pipeline run.
- **Response caching**: Optional. Cache key = hash(system_prompt + prompt). Stored in `output/<target>/llm_cache/`. Use `--no-cache` to force fresh calls. Critical for development iteration.
- **`_extract_json()`**: 5-step extraction strategy with explicit failure (raises `LLMParseError` with raw response for debugging, never returns garbage).
- **`_extract_solidity()`**: Extracts code from markdown fences, falls back to raw text.

### acquire.py — Target Acquisition + Freshness (gates pipeline)

Extracted from scan.py. Freshness check is a **hard gate** — pipeline aborts if superseded files found (unless `--force`).

```python
class TargetAcquirer:
    def acquire(self, config: ScanConfig) -> AcquiredTarget:
        target_dir = self._clone_or_locate(config.target)
        solc_version = config.solc_version or self._detect_solc_version(target_dir)
        freshness = self._check_freshness(target_dir, config.scope_contracts)
        return AcquiredTarget(
            path=target_dir,
            solc_version=solc_version,
            freshness=freshness,
        )

    def _check_freshness(self, target_dir, scope_contracts) -> FreshnessReport:
        """For each in-scope contract:
        1. git log --since=60d -- <file>  (recent changes?)
        2. Search for V2/V3/renamed versions in same directory
        3. Check deploy scripts for references
        4. Compare HEAD vs bounty scope commit (if specified)
        Returns FreshnessReport with warnings for stale/superseded files.
        """

    def validate_freshness(self, freshness: FreshnessReport, force: bool = False) -> None:
        """Abort pipeline if freshness check fails. Unless force=True."""
        if freshness.superseded_files:
            msg = "ABORT: Found superseded files:\n"
            for sf in freshness.superseded_files:
                msg += f"  {sf['original']} → replaced by {sf['replacement']}\n"
            if not force:
                raise FreshnessError(msg + "Use --force to override.")
            else:
                print(f"WARNING (--force): {msg}")

        if not freshness.is_clean and not force:
            print("WARNING: Freshness issues detected. Use --force to override.")
            for sf in freshness.stale_files:
                print(f"  STALE: {sf['file']} (last modified {sf['days_ago']}d ago)")
```

### context.py — Code Context Extraction

For each finding, extracts the code context an analyst would read.

```python
class ContextExtractor:
    def __init__(self, target_dir: Path):
        self.target_dir = target_dir
        self._slither = self._try_load_slither(target_dir)

    def extract(self, finding: Finding) -> CodeContext:
        """Extract rich code context for a finding."""
        if self._slither:
            return self._extract_via_slither(finding)
        return self._extract_via_regex(finding)

    def _extract_via_slither(self, finding: Finding) -> CodeContext:
        """Use Slither's Python API for AST-level extraction."""
        # slither.core.declarations: Contract, Function, StateVariable
        # Accurate call graphs, state variable mapping, inheritance
        ...

    def _extract_via_regex(self, finding: Finding) -> CodeContext:
        """Best-effort regex extraction. Known limitations:
        - May miss multi-contract files
        - Assembly blocks can confuse function boundary detection
        - NatSpec comments may contain code-like patterns
        - 'using X for Y' directives not tracked
        Returns partial CodeContext with empty fields where extraction failed.
        """
        ...

    def estimate_token_count(self, context: CodeContext) -> int:
        """Rough token estimate for context (chars / 4)."""
        total_chars = sum(len(getattr(context, f)) for f in [
            'source_snippet', 'full_function', 'contract_source'
        ])
        total_chars += sum(len(s) for s in context.call_graph)
        total_chars += sum(len(s) for s in context.state_variables)
        return total_chars // 4
```

Two extraction modes:
1. **Slither API mode** (preferred): Uses `slither.core.declarations` for AST-level extraction. Accurate call graphs, state variable mapping, inheritance.
2. **Regex fallback mode**: Best-effort. Known to produce incomplete results for complex contracts. Fields may be empty where extraction failed. Middle ground: `solc --ast-compact-json` for compilation-only AST (future enhancement).

### triage.py — LLM False Positive Filter (adaptive batching)

Batch-filters findings with adaptive batch sizing to avoid context window overflow.

```python
MAX_TRIAGE_TOKENS = 30_000  # Conservative limit for batch prompt

class Triager:
    def __init__(self, llm: LLMClient):
        self.llm = llm

    def triage(self, findings: list[Finding], contexts: list[CodeContext],
               context_extractor: ContextExtractor) -> list[Finding]:
        """Batch-filter findings using LLM. Adaptive batch sizing."""
        pairs = list(zip(findings, contexts))
        batches = self._adaptive_batch(pairs, context_extractor)
        kept = []
        for batch in batches:
            results = self._triage_batch(batch)
            kept.extend(results)
        return kept

    def _adaptive_batch(self, pairs, context_extractor) -> list[list]:
        """Build batches that fit within token budget.
        Uses abbreviated context for triage (source_snippet + function signature only).
        """
        batches = []
        current_batch = []
        current_tokens = 0
        for finding, context in pairs:
            # Triage uses abbreviated context
            abbreviated = CodeContext(
                finding_id=context.finding_id,
                source_snippet=context.source_snippet,
                full_function=context.full_function[:500],  # First 500 chars only
                contract_source="",  # Omit for triage
                call_graph=context.call_graph[:5],  # Top 5 only
                state_variables=context.state_variables[:10],
                inheritance_chain=context.inheritance_chain,
                related_functions=[],  # Omit for triage
            )
            token_est = context_extractor.estimate_token_count(abbreviated) + 200  # overhead
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
        prompt = self._build_triage_prompt(batch)
        response = self.llm.ask_structured(
            prompt, system_prompt=TRIAGE_SYSTEM_PROMPT, timeout=60
        )
        kept_ids = {f["id"] for f in response["findings"] if f["keep"]}
        return [f for f, _ in batch if f.id in kept_ids]
```

### analyze.py — LLM Deep Analysis (replaces hypothesize.py)

The core analytical engine. One LLM call per triaged finding.

```python
class Analyzer:
    def __init__(self, llm: LLMClient):
        self.llm = llm

    def analyze(self, finding: Finding, context: CodeContext) -> Hypothesis | None:
        """Deep analysis of a single finding. Returns None if not exploitable."""
        prompt = self._build_analysis_prompt(finding, context)
        response = self.llm.ask_structured(
            prompt, system_prompt=ANALYSIS_SYSTEM_PROMPT, timeout=120
        )

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
```

### poc_gen.py — LLM PoC Generation + Iterative Verification + Validation

Replaces template-based verify.py. LLM writes complete Foundry test files. After forge passes, a **validation step** confirms the PoC actually demonstrates the vulnerability (not a trivially-passing test).

```python
class PoCGenerator:
    MAX_RETRIES = 3

    def __init__(self, llm: LLMClient, output_dir: Path):
        self.llm = llm
        self.output_dir = output_dir
        self.forge = ForgeExecutor()

    def generate_and_verify(self, hypothesis: Hypothesis, context: CodeContext,
                             config: ScanConfig) -> PoCResult:
        """Generate PoC, run forge, retry on failure, validate on pass."""
        previous_errors: list[str] = []
        last_result = None

        for attempt in range(1, self.MAX_RETRIES + 1):
            # Generate PoC
            poc_code = self._generate_poc(
                hypothesis, context, config,
                previous_error=previous_errors[-1] if previous_errors else None,
            )
            test_file = self._write_poc(hypothesis.id, poc_code, attempt)

            # Run forge
            result = self.forge.run(test_file, cwd=config.target_dir)
            result.attempt = attempt
            result.previous_errors = list(previous_errors)
            last_result = result

            if result.passed:
                # VALIDATION: confirm PoC actually demonstrates the vulnerability
                validation = self._validate_poc(poc_code, result, hypothesis)
                if validation["valid"]:
                    result.validated = True
                    result.validation_reason = validation["reason"]
                    return result
                else:
                    # PoC passes but doesn't demonstrate the vuln — treat as failure
                    previous_errors.append(
                        f"PoC test passed but DOES NOT demonstrate the vulnerability: "
                        f"{validation['reason']}. Rewrite the test with meaningful "
                        f"assertions that prove exploitation."
                    )
                    continue

            # Compilation or test failure
            error_msg = f"Attempt {attempt} "
            if not result.compiled:
                error_msg += f"compilation failed:\n{result.error}\n\nForge output:\n{result.logs[-2000:]}"
            else:
                error_msg += f"test failed:\n{result.error}\n\nForge output:\n{result.logs[-2000:]}"
            previous_errors.append(error_msg)

        return last_result

    def _validate_poc(self, poc_code: str, result: PoCResult,
                      hypothesis: Hypothesis) -> dict:
        """LLM reviews passing PoC to confirm it genuinely demonstrates the vulnerability.

        Checks:
        1. Assertions are meaningful (not trivially true)
        2. The exploit logic matches the hypothesis attack vector
        3. Console.log output shows evidence of exploitation (profit, state change)
        """
        prompt = self._build_validation_prompt(poc_code, result, hypothesis)
        return self.llm.ask_structured(
            prompt, system_prompt=VALIDATION_SYSTEM_PROMPT, timeout=60
        )
        # Returns: {"valid": bool, "reason": str}

    def _generate_poc(self, hypothesis, context, config, previous_error=None) -> str:
        """LLM generates complete .t.sol file."""
        prompt = self._build_poc_prompt(hypothesis, context, config, previous_error)
        response = self.llm.ask(
            prompt, system_prompt=POC_SYSTEM_PROMPT, timeout=300
        )
        return _extract_solidity(response)
```

### report.py — LLM Report Generation (refactored)

Replaces template-based report generation. AI disclosure policy is configurable.

```python
class ReportGenerator:
    def __init__(self, llm: LLMClient, output_dir: Path | None = None,
                 platform: str = "cantina"):
        self.llm = llm
        self.output_dir = output_dir or Path("output") / "reports"
        self.platform = platform  # "cantina", "immunefi", "generic"

    def generate(self, hypothesis: Hypothesis, poc_result: PoCResult,
                 poc_code: str, config: ScanConfig) -> tuple[VulnReport, Path]:
        """LLM generates full vulnerability report."""
        prompt = self._build_report_prompt(hypothesis, poc_result, poc_code, config)
        system = self._get_report_system_prompt()
        markdown = self.llm.ask(prompt, system_prompt=system, timeout=120)

        report = self._parse_report(markdown, hypothesis, poc_result, poc_code, config)

        filename = f"{hypothesis.id}_{report.severity.value}_report.md"
        output_path = self.output_dir / filename
        output_path.write_text(markdown)

        return report, output_path

    def _get_report_system_prompt(self) -> str:
        """Platform-specific report system prompt.
        AI disclosure policy follows platform ToS (configurable via config).
        """
        ...
```

### verify.py — Simplified Forge Executor

Stripped to just forge execution + output parsing. No template logic, no Jinja2.

```python
class ForgeExecutor:
    def run(self, test_file: Path, match_test: str | None = None,
            cwd: Path | None = None) -> PoCResult:
        """Run forge test on a .t.sol file and parse results."""
        # Reuse existing _parse_forge_output logic
        # Remove: select_template, render_poc, TEMPLATE_MAP, Jinja2 imports

    def _parse_forge_output(self, stdout, test_file, match_test) -> PoCResult:
        """Parse forge output. Keep existing regex logic."""
```

Tests to keep from existing test_verify.py: `TestForgeOutputParsing`, `TestRunForge`.
Tests to delete: `TestTemplateSelection`, `TestTemplateRendering`, `TestVerifyEndToEnd`, `TestTestNameFromTemplate`.

### orchestrator.py — Pipeline Coordinator with Checkpointing

```python
class PipelineOrchestrator:
    def __init__(self, config: ScanConfig):
        self.config = config
        cache_dir = Path("output") / self._target_name() / "llm_cache" if not config.no_cache else None
        self.llm = LLMClient(
            max_calls=config.max_llm_calls,
            cache_dir=cache_dir,
        )
        self.acquirer = TargetAcquirer()
        self.scanner = Scanner(config)
        self.context_extractor = None
        self.triager = Triager(self.llm)
        self.analyzer = Analyzer(self.llm)
        self.poc_gen = PoCGenerator(self.llm, output_dir=Path("output/poc"))
        self.reporter = ReportGenerator(self.llm, platform=config.platform)
        self.checkpoint_dir = Path("output") / self._target_name() / "checkpoints"

    def run(self) -> list[tuple[VulnReport, Path]]:
        # 1. Acquire + freshness check (hard gate)
        target = self._load_or_run("acquire", self._phase_acquire)
        self.acquirer.validate_freshness(target.freshness, force=self.config.force)

        # 2. Static scan
        findings = self._load_or_run("scan", self._phase_scan)
        if not findings:
            print("No findings. Pipeline complete.")
            return []
        print(f"[2/7] {len(findings)} findings from static analysis")

        # 3. Extract code context
        self.context_extractor = ContextExtractor(target.path)
        contexts = self._load_or_run("context", lambda: self._phase_context(findings))
        print(f"[3/7] Extracted context for {len(contexts)} findings")

        # 4. LLM triage
        triaged = self._load_or_run("triage", lambda: self._phase_triage(findings, contexts))
        print(f"[4/7] {len(triaged)}/{len(findings)} findings survived triage")
        print(f"  LLM budget: {self.llm.cost.call_count}/{self.llm.cost.max_calls} calls")

        # 5. LLM deep analysis
        hypotheses = self._load_or_run("analyze", lambda: self._phase_analyze(triaged, contexts))
        print(f"[5/7] {len(hypotheses)} exploitable hypotheses")
        print(f"  LLM budget: {self.llm.cost.call_count}/{self.llm.cost.max_calls} calls")

        # 6. PoC generation + verification + validation
        verified = self._load_or_run("verify", lambda: self._phase_verify(hypotheses, contexts))
        print(f"[6/7] {len(verified)} verified + validated PoCs")
        print(f"  LLM budget: {self.llm.cost.call_count}/{self.llm.cost.max_calls} calls")

        # 7. Report (ONLY for verified findings)
        if not verified:
            print("No verified vulnerabilities found.")
            return []

        reports = self._phase_report(verified)
        print(f"[7/7] {len(reports)} reports generated")
        print(f"  Total LLM calls: {self.llm.cost.call_count}, est. cost: ${self.llm.cost.estimated_cost_usd:.2f}")

        return reports

    def _load_or_run(self, phase_name: str, phase_fn):
        """Load checkpoint if exists, otherwise run phase and save checkpoint."""
        checkpoint = self.checkpoint_dir / f"{phase_name}.json"
        if checkpoint.exists():
            print(f"  (resuming from checkpoint: {phase_name})")
            return self._load_checkpoint(checkpoint)
        result = phase_fn()
        self._save_checkpoint(checkpoint, result)
        return result

    def _save_checkpoint(self, path: Path, data) -> None:
        """Serialize phase output to JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        # Use Pydantic model_dump for models, fallback to json
        ...

    def _load_checkpoint(self, path: Path):
        """Deserialize phase output from JSON."""
        ...
```

Key behavioral changes:
- **Freshness is a hard gate** — aborts if superseded files found (unless `--force`)
- **Checkpointing** — each phase serializes output to `output/<target>/checkpoints/`. Resume from last completed phase on restart.
- **LLM budget tracking** — prints call count and estimated cost after each LLM phase. Aborts when budget exhausted.
- **Only reports verified + validated findings**

### models.py — Extended Models

New/modified models:

```python
from pathlib import Path

def sev_rank(sev: Severity) -> int:
    """Lower rank = higher severity. Canonical location (no more duplicates)."""
    return list(Severity).index(sev)

# NEW
class AcquiredTarget(BaseModel):
    path: Path
    solc_version: str | None = None
    freshness: "FreshnessReport"

class FreshnessReport(BaseModel):
    stale_files: list[dict]       # {"file": str, "last_modified": str, "days_ago": int}
    superseded_files: list[dict]  # {"original": str, "replacement": str}
    scope_drift: list[dict]       # {"file": str, "scope_sha": str, "head_sha": str}
    is_clean: bool

class FreshnessError(Exception):
    """Raised when freshness check fails and --force not set."""

class CodeContext(BaseModel):
    finding_id: str
    source_snippet: str        # ~50 lines around the finding
    full_function: str         # Complete function body
    contract_source: str       # Full contract (truncated if >500 lines; empty in triage)
    call_graph: list[str]      # ["functionA -> functionB", ...]
    state_variables: list[str] # ["mapping(address => uint256) public balances", ...]
    inheritance_chain: list[str]  # ["MyContract", "BaseContract", "OpenZeppelinOwnable"]
    related_functions: list[str]  # Functions touching same state vars

# MODIFIED — add fields to Hypothesis
class Hypothesis(BaseModel):
    # ... existing fields kept with defaults for backwards compat ...
    root_cause: str = ""
    exploit_steps: list[str] = Field(default_factory=list)
    required_contracts: list[str] = Field(default_factory=list)
    poc_solidity_hints: str = ""

# MODIFIED — add fields to PoCResult
class PoCResult(BaseModel):
    # ... existing fields ...
    attempt: int = 1                       # Which retry attempt produced this result
    previous_errors: list[str] = Field(default_factory=list)  # Errors from prior attempts
    validated: bool = False                # True if PoC validation passed
    validation_reason: str = ""            # Why validation passed/failed

# MODIFIED — add fields to ScanConfig
class ScanConfig(BaseModel):
    # ... existing fields ...
    max_llm_calls: int = 50               # LLM budget cap
    force: bool = False                    # Override freshness check
    no_cache: bool = False                 # Disable LLM response caching
    platform: str = "cantina"             # Report platform: "cantina", "immunefi", "generic"
```

All new fields have defaults → existing tests that construct Hypothesis/PoCResult/ScanConfig continue to work.

### scan.py — Remove _acquire_target, fix imports

```python
# REMOVE: _acquire_target, _detect_solc_version, _ensure_solc (moved to acquire.py)
# FIX: Replace sys.path.insert hack with proper relative imports
from analyzers.slither_runner import run_slither   # → from ..analyzers.slither_runner
from analyzers.semgrep_runner import run_semgrep   # → from ..analyzers.semgrep_runner
# Or: make analyzers a proper subpackage by adding vuln-research to PYTHONPATH in pyproject.toml

# REPLACE: _sev_rank with import from models
from .models import sev_rank
```

## File Changes Summary

| File | Action | Description |
|------|--------|-------------|
| `pipeline/llm.py` | **CREATE** | Claude CLI wrapper + CostTracker + response caching + JSON/Solidity extraction |
| `pipeline/acquire.py` | **CREATE** | Target acquisition + freshness checks (hard gate) |
| `pipeline/context.py` | **CREATE** | Code context extraction (Slither API + regex fallback with documented limitations) |
| `pipeline/triage.py` | **CREATE** | LLM false positive filtering (adaptive batch sizing) |
| `pipeline/analyze.py` | **CREATE** | LLM deep analysis (replaces hypothesize.py) |
| `pipeline/poc_gen.py` | **CREATE** | LLM PoC generation + iterative forge verification + PoC validation |
| `pipeline/models.py` | **MODIFY** | Add new types, `sev_rank()` canonical location, extend Hypothesis/PoCResult/ScanConfig |
| `pipeline/verify.py` | **MODIFY** | Strip to ForgeExecutor; keep TestForgeOutputParsing + TestRunForge in tests |
| `pipeline/report.py` | **MODIFY** | LLM-based, platform-configurable, AI disclosure follows platform ToS |
| `pipeline/orchestrator.py` | **MODIFY** | New flow with checkpointing, budget tracking, freshness gate |
| `pipeline/scan.py` | **MODIFY** | Remove _acquire_target; fix sys.path.insert → proper imports; use models.sev_rank |
| `pipeline/scoring.py` | **MODIFY** | Use `models.sev_rank` instead of local `_sev_rank` |
| `pipeline/hypothesize.py` | **DELETE** | Replaced by analyze.py |
| `foundry/templates/*.j2` | **KEEP** | Retained as LLM prompt examples |
| `reports/templates/*.j2` | **DELETE** | LLM generates reports directly |
| `tests/test_hypothesize.py` | **DELETE** | Replaced by test_analyze.py |
| `tests/test_verify.py` | **MODIFY** | Keep forge parsing/execution tests, delete template tests |
| `tests/test_llm.py` | **CREATE** | Mock subprocess for LLM wrapper, JSON extraction, caching |
| `tests/test_acquire.py` | **CREATE** | Freshness checks (mock git commands) |
| `tests/test_context.py` | **CREATE** | Context extraction (mock Slither + regex on fixtures) |
| `tests/test_triage.py` | **CREATE** | Triage (mock LLM responses, test adaptive batching) |
| `tests/test_analyze.py` | **CREATE** | Analysis (mock LLM responses) |
| `tests/test_poc_gen.py` | **CREATE** | PoC generation + validation (mock LLM + forge) |

## LLM Prompt Design

### Triage System Prompt
```
You are a senior smart contract security researcher triaging static analysis findings.
For each finding, determine if it is a true positive (likely exploitable vulnerability)
or a false positive (benign code pattern that triggered the detector).

Consider:
- Is the flagged pattern actually reachable by an attacker?
- Are there existing protections (modifiers, checks) that the static analyzer missed?
- Is this a known-safe pattern (e.g., reentrancy guard present but detector doesn't recognize it)?

Output a single JSON object. Do not include any text outside the JSON.
Format: {"findings": [{"id": "...", "keep": true/false, "confidence": 0.0-1.0, "reason": "..."}]}
```

### Analysis System Prompt
```
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
- poc_solidity_hints: str (draft Solidity snippet for key exploit logic)
```

### PoC Generation System Prompt
```
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

Output a single Solidity code block. Do not include any explanation outside the code block.
```

### PoC Validation System Prompt
```
You are reviewing a Foundry PoC test that passed. Determine if it genuinely demonstrates
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
Format: {"valid": true/false, "reason": "..."}
```

## Implementation Phases (development-time parallelization)

Note: parallelization below refers to development work by different subagents, not runtime execution. Runtime is always sequential (each phase depends on prior output).

### Phase 1: Foundation (llm.py + models.py + acquire.py)
- `pipeline/llm.py` — LLMClient, CostTracker, caching, _extract_json, _extract_solidity
- `pipeline/models.py` — Add AcquiredTarget, FreshnessReport, CodeContext, extend Hypothesis/PoCResult/ScanConfig, add canonical sev_rank()
- `pipeline/acquire.py` — Target acquisition + freshness checks + validation gate
- `tests/test_llm.py`, `tests/test_acquire.py`
- **Dependencies**: None
- **Risk**: Low (new files, model extensions are backwards-compatible)

### Phase 2: Context Extraction (context.py)
- `pipeline/context.py` — Slither API extraction + regex fallback (with documented limitations)
- `tests/test_context.py` — Test both Slither and regex modes against fixture contracts
- **Dependencies**: Phase 1 (models — CodeContext type)
- **Risk**: Medium (Slither API edge cases; regex fallback produces best-effort results)

### Phase 3: LLM Analysis (triage.py + analyze.py)
- `pipeline/triage.py` — Batch filtering with adaptive sizing
- `pipeline/analyze.py` — Deep per-finding analysis
- `tests/test_triage.py`, `tests/test_analyze.py` — Mock LLM responses via monkeypatched subprocess
- **Dependencies**: Phase 1 (llm.py, models), Phase 2 (context.py — for adaptive batch sizing)
- **Risk**: Medium (prompt engineering quality determines output quality)

### Phase 4: PoC Generation + Verification (poc_gen.py + verify.py refactor)
- `pipeline/poc_gen.py` — LLM PoC generation + iterative retry + PoC validation
- `pipeline/verify.py` — Strip to ForgeExecutor (keep forge parsing, remove templates)
- `tests/test_poc_gen.py` — Mock LLM + forge for retry logic and validation
- `tests/test_verify.py` — Update: keep forge tests, delete template tests
- **Dependencies**: Phase 1 (llm.py, models), Phase 2 (context.py)
- **Risk**: High (PoC compilation iteration + validation logic is the hardest part)

### Phase 5: Report + Orchestrator (report.py + orchestrator.py + scan.py cleanup)
- `pipeline/report.py` — LLM-based, platform-configurable
- `pipeline/orchestrator.py` — New flow with checkpointing + budget tracking + freshness gate
- `pipeline/scan.py` — Remove _acquire_target, fix imports, use models.sev_rank
- `pipeline/scoring.py` — Use models.sev_rank
- Delete: `pipeline/hypothesize.py`, `reports/templates/*.j2`
- Update: `tests/test_report.py`, `tests/test_integration.py`
- **Dependencies**: All previous phases
- **Risk**: Medium (integration of all components)

### Phase 6: Integration Testing
- End-to-end test with sample vulnerable contracts
- Test checkpointing (resume after crash)
- Test budget exhaustion handling
- Test freshness gate (superseded files → abort)
- Fix integration issues

### Development Parallelization

```
Phase 1 ────────────────►
Phase 2 ────────────────► (parallel with 1; only needs CodeContext type definition)
                Phase 3 ─────────► (after 1+2 complete)
                Phase 4 ─────────► (after 1+2 complete; parallel with 3)
                         Phase 5 ► (after 1-4 complete)
                           Phase 6► (after all)
```

- **Phase 1 + 2**: Can be developed in parallel by different subagents. Phase 2 only needs the `CodeContext` model definition from Phase 1, which is a simple type — can be agreed on upfront.
- **Phase 3 + 4**: Can be developed in parallel after 1+2. Both depend on llm.py + context.py but don't depend on each other.
- **Phase 5**: Sequential (integrates everything).
- **Phase 6**: Sequential (tests the whole thing).

## Key Design Decisions

### Why `claude -p` subprocess, not Anthropic API?
- No API key management needed — uses existing Claude Code OAuth
- Already available on the system
- Process isolation (LLM call can't crash the pipeline)
- Trade-off: ~3-5s startup overhead per call, acceptable for pipeline that runs in minutes
- Future: can add `--api-key` flag to switch to direct API calls for performance

### Why LLM-generated PoCs, not templates?
- Templates require perfect variable binding — the orchestrator must know EVERY contract address, function signature, and parameter. This is the exact information that requires code understanding.
- LLM-generated PoCs are self-contained — the LLM reads the code and produces a complete test.
- Templates are kept as examples in the LLM prompt, providing structural guidance without rigidity.

### Why iterative PoC verification + validation?
- First-attempt compilation success rate for LLM-generated Solidity is ~40-60%.
- With error feedback, second attempt succeeds ~70-80% of the time.
- 3 retries is the sweet spot — diminishing returns after that.
- **Validation prevents false positives**: A passing test doesn't prove exploitation. The validation step (cheap LLM call) confirms assertions are meaningful and the exploit logic matches the hypothesis.

### Why separate triage from analysis?
- Triage is batch-efficient (multiple findings per call) and cheap (abbreviated context).
- Analysis is expensive (full context, one per finding).
- Filtering 50 static analysis findings down to 5-10 saves ~80% of analysis cost.
- Adaptive batch sizing prevents context window overflow.

### Why checkpointing?
- LLM calls are expensive (time + cost). Re-running after a crash in Phase 5 shouldn't repeat Phases 1-4.
- Each phase serializes output to JSON. On restart, completed phases are skipped.
- `--no-cache` + deleting checkpoints forces a clean run.

### Why keep Slither/Semgrep?
- LLMs are bad at exhaustive pattern scanning (miss things, hallucinate findings).
- Static analysis is deterministic and fast — catches known patterns reliably.
- LLMs are good at understanding code semantics — filters false positives, identifies exploit paths.
- The combination (static scan → LLM analysis) is strictly better than either alone.
- This is the architecture that kritt.ai uses (confirmed by their public talks).
