#!/bin/bash
set -euo pipefail
echo "=== Verifying tool installation ==="
FAIL=0
for cmd in forge cast anvil solc slither semgrep; do
    if command -v "$cmd" &>/dev/null; then
        echo "  OK: $cmd"
    else
        echo "  MISSING: $cmd"
        FAIL=1
    fi
done
if [ "$FAIL" -eq 1 ]; then
    echo "Some tools are missing. Check PATH."
    exit 1
fi
echo "=== All tools verified ==="
