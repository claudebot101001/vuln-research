#!/bin/bash
set -euo pipefail
echo "=== Installing solc-select ==="
pip install solc-select 2>/dev/null || pip install --user solc-select
solc-select install 0.8.28 0.8.20 0.8.17 0.8.13 0.7.6 0.6.12
solc-select use 0.8.28
echo "solc installed: $(solc --version | tail -1)"
