# vuln-research

Smart contract vulnerability research pipeline. Slither + Semgrep for static analysis, Foundry for PoC verification.

## Running

```bash
# Install tools (first time only)
bash setup/install.sh

# Run full pipeline on a target
python -m pipeline.orchestrator --target https://github.com/org/repo

# Run individual phases
python -m pipeline.scan --target ./targets/repo
python -m pipeline.hypothesize --findings output/repo/findings.json
python -m pipeline.verify --hypotheses output/repo/hypotheses.json
python -m pipeline.report --results output/repo/poc_results.json
```

## Structure

- `analyzers/` -- Slither + Semgrep wrappers, custom detectors
- `pipeline/` -- 4-phase pipeline: scan -> hypothesize -> verify -> report
- `foundry/templates/` -- Parameterized PoC Solidity templates
- `rules/semgrep/` -- Custom Semgrep rules for Solidity
- `tests/` -- Unit + integration tests
