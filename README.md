# vuln-research

LLM-integrated smart contract vulnerability research pipeline. Built as an experiment to test whether an autonomous AI agent can find exploitable vulnerabilities in Solidity codebases.

**Status: Archived.** The pipeline works end-to-end but has no competitive edge over existing tools. See [Post-Mortem](#post-mortem) below.

## Architecture

7-phase pipeline: **acquire** -> **scan** -> **context** -> **triage** -> **analyze** -> **poc_gen** -> **report**

```
Target repo
    |
    v
[1. Acquire] -- git clone / local path, solc detection, freshness gate
    |
    v
[2. Scan] -- Semgrep (custom rules) + Slither static analysis
    |
    v
[3. Context] -- Slither API + regex fallback for code extraction
    |           (function bodies, call graphs, state vars, inheritance)
    |
    v
[4. Triage] -- LLM batch-filters findings (FP elimination)
    |           adaptive batch sizing within token budget
    |
    v
[5. Analyze] -- LLM deep analysis per finding
    |            generates exploit hypotheses with root cause + attack vector
    |
    v
[6. PoC Gen] -- LLM generates Foundry .t.sol exploits
    |            iterative: generate -> forge test -> fix errors (3 retries)
    |            LLM validation rejects trivially-passing tests
    |
    v
[7. Report] -- LLM generates platform-specific reports
               (Immunefi / Cantina / generic markdown)
```

### Key Design Decisions

- **LLM transport**: `claude -p` subprocess calls (no API key needed, uses CLI auth)
- **Checkpointing**: JSON serialization after each phase for crash recovery
- **Response caching**: SHA256-keyed file cache to avoid redundant LLM calls
- **Cost tracking**: Hard budget cap on LLM calls (default 50)
- **Freshness gate**: Aborts on superseded/stale code unless `--force`

## Directory Structure

```
pipeline/           # Core 7-phase pipeline
  orchestrator.py   # Main coordinator with checkpointing
  llm.py            # Claude CLI wrapper + cost tracking + caching
  models.py         # Data models (Finding, Hypothesis, PoCResult, etc.)
  acquire.py        # Target acquisition + freshness checks
  scan.py           # Static analysis orchestration
  context.py        # Code context extraction (Slither + regex)
  triage.py         # LLM false-positive filtering
  analyze.py        # LLM deep analysis + hypothesis generation
  poc_gen.py        # LLM PoC generation + forge verification
  verify.py         # ForgeExecutor (forge test runner)
  report.py         # LLM report generation
analyzers/          # Static analysis runners
  slither_runner.py # Slither integration
  semgrep_runner.py # Semgrep integration
  detectors/        # Custom Slither detectors
rules/semgrep/      # Custom Semgrep rules (8 categories)
foundry/templates/  # Jinja2 PoC templates (v1, unused in v2)
tests/              # Unit tests (14 test files)
```

## Usage

```bash
# Install dependencies
pip install -e .

# Run on a target
python -m pipeline.orchestrator <target_dir> [options]

# Options
--min-severity low|medium|high    # Filter threshold (default: medium)
--max-llm-calls 50                # Budget cap
--no-cache                        # Disable response cache
--force                           # Skip freshness gate
--platform immunefi|cantina       # Report format
```

Requires: Python 3.12+, [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code), Foundry (`forge`), Slither, Semgrep.

## Test Results

**mamo-contracts** (real DeFi protocol):
- Scan: 7 findings (Semgrep only; Slither timed out on `forge build`)
- Triage: 0/7 survived -- all correctly identified as false positives
- The stale-price finding was a FP because the code already validates `updatedAt`
- The unsafe-downcast findings were intentional patterns in rate-limiting libraries

**test-vulnerable** (deliberately buggy contract):
- Scan: 8 findings
- Triage: 5/8 survived (correctly kept reentrancy, access control, unchecked calls)
- Analyze: 5 hypotheses generated with root causes and attack vectors
- PoC gen: Not completed (LLM subprocess timeout at 300s)

## Post-Mortem

### Why This Doesn't Work

1. **No detection edge.** Semgrep/Slither rules are public. Every finding this pipeline produces, existing tools (kritt.ai, Olympix, Aderyn) find too. Using public rule sets means zero alpha.

2. **Architecture is inverted.** Uses cheap tools (static analysis) as the primary scanner and expensive tools (LLM) as the filter. Real vulnerabilities -- invariant violations, cross-protocol composability exploits, economic attacks -- aren't pattern-matchable. The LLM should be the primary reasoner, not a post-filter.

3. **Context is fragmented.** The analysis LLM sees isolated function snippets, not full protocol logic. Cross-contract call chains, external protocol dependencies, and economic model assumptions are invisible. This makes it structurally incapable of finding the vulnerabilities that actually pay bounties.

4. **Uneconomical.** Each hypothesis requires multiple `claude -p` calls (PoC gen x3 retries x N hypotheses). For a pipeline that produces mostly false positives, the token cost per valid finding approaches infinity.

5. **No moat.** Anyone can pipe Solidity into Claude/GPT and ask "find vulnerabilities." The pipeline adds orchestration but not intelligence. The competitive landscape (kritt.ai, Olympix, Code4rena AI) has more data, proprietary detectors, and dedicated teams.

### What Would Actually Work

The only viable AI-in-audit approach would need:
- LLM as **primary scanner** (invariant reasoning over full codebase, not pattern matching)
- **Proprietary data** (private audit reports, exploit databases not on rekt.news)
- **On-chain state integration** (real-time reserves, prices, governance state)
- Context windows large enough for entire protocol codebases (current limit: ~200k tokens)

None of these are achievable by a single autonomous agent with public tools.

### Lesson Learned

> Before entering any domain, complete a competitive edge analysis first. "We use LLM so it's smarter" is not an edge. "We have X exclusive data source that increases Y detection rate by Z%" is. No edge, no build.

## License

MIT
