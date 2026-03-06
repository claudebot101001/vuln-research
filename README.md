# vuln-research

LLM-integrated smart contract vulnerability research pipeline. Combines static analysis (Semgrep + Slither) with LLM-powered triage, deep analysis, and automated Foundry PoC generation.

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

## Key Features

- **LLM transport**: `claude -p` subprocess calls (no API key needed, uses CLI auth)
- **Checkpointing**: JSON serialization after each phase for crash recovery
- **Response caching**: SHA256-keyed file cache to avoid redundant LLM calls
- **Cost tracking**: Hard budget cap on LLM calls (configurable, default 50)
- **Freshness gate**: Aborts on superseded/stale code unless `--force`
- **PoC validation**: LLM reviews passing tests to reject trivially-true assertions

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
foundry/templates/  # Jinja2 PoC templates
tests/              # Unit tests (14 test files)
```

## Usage

```bash
pip install -e .

python -m pipeline.orchestrator <target_dir> [options]

# Options
--min-severity low|medium|high    # Filter threshold (default: medium)
--max-llm-calls 50                # Budget cap
--no-cache                        # Disable response cache
--force                           # Skip freshness gate
--platform immunefi|cantina       # Report format
```

## Requirements

- Python 3.12+
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) (`claude auth login`)
- [Foundry](https://book.getfoundry.sh/) (`forge`)
- [Slither](https://github.com/crytic/slither)
- [Semgrep](https://semgrep.dev/)

## License

MIT
