#!/bin/bash
set -euo pipefail
echo "=== Installing Foundry ==="
if command -v forge &>/dev/null; then
    echo "Foundry already installed: $(forge --version)"
    exit 0
fi
curl -L https://foundry.paradigm.xyz | bash
export PATH="$HOME/.foundry/bin:$PATH"
foundryup
echo 'export PATH="$HOME/.foundry/bin:$PATH"' >> ~/.bashrc
echo "Foundry installed: $(forge --version)"
