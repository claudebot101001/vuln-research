#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "=== vuln-research tool installation ==="
bash "$SCRIPT_DIR/install_foundry.sh"
bash "$SCRIPT_DIR/install_solc.sh"
bash "$SCRIPT_DIR/install_analyzers.sh"
bash "$SCRIPT_DIR/verify.sh"
echo "=== All tools installed ==="
