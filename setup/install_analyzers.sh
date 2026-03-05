#!/bin/bash
set -euo pipefail
echo "=== Installing Slither + Semgrep ==="
pip install slither-analyzer semgrep crytic-compile 2>/dev/null || pip install --user slither-analyzer semgrep crytic-compile
pip install pydantic pyyaml jinja2 rich click 2>/dev/null || pip install --user pydantic pyyaml jinja2 rich click
echo "Slither: $(slither --version 2>&1 || echo 'check PATH')"
echo "Semgrep: $(semgrep --version 2>&1 || echo 'check PATH')"
