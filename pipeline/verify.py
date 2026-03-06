"""Forge test executor and output parser."""

import re
import shutil
import subprocess
from pathlib import Path

from .models import PoCResult


class ForgeExecutor:
    """Runs forge test on .t.sol files and parses results."""

    def run(
        self,
        test_file: Path,
        match_test: str | None = None,
        cwd: Path | None = None,
    ) -> PoCResult:
        """Run forge test on a .t.sol file and parse results."""
        if not shutil.which("forge"):
            return PoCResult(
                hypothesis_id=test_file.stem.replace(".t", ""),
                test_name=match_test or "unknown",
                test_file=str(test_file),
                compiled=False,
                passed=False,
                error="forge not found in PATH",
            )

        cmd = ["forge", "test", "--match-path", str(test_file), "-vvv"]
        if match_test:
            cmd.extend(["--match-test", match_test])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=cwd or test_file.parent,
            )
        except subprocess.TimeoutExpired:
            return PoCResult(
                hypothesis_id=test_file.stem.replace(".t", ""),
                test_name=match_test or "unknown",
                test_file=str(test_file),
                compiled=False,
                passed=False,
                error="forge test timed out (300s)",
            )

        stdout = result.stdout + result.stderr
        return self._parse_forge_output(
            stdout=stdout,
            test_file=test_file,
            match_test=match_test,
        )

    def _parse_forge_output(
        self,
        stdout: str,
        test_file: Path,
        match_test: str | None,
    ) -> PoCResult:
        """Parse forge test stdout into a PoCResult."""
        hypothesis_id = test_file.stem.replace(".t", "")

        # Check compilation
        compiled = (
            "Compiler run successful" in stdout
            or "[PASS]" in stdout
            or "[FAIL]" in stdout
        )

        # Check pass/fail
        passed = "[PASS]" in stdout and "[FAIL]" not in stdout

        # Extract gas
        gas_used = None
        gas_match = re.search(r"\(gas:\s*(\d+)\)", stdout)
        if gas_match:
            gas_used = int(gas_match.group(1))

        # Extract error if failed
        error = None
        if not passed:
            error_match = re.search(r"(?:Error|Reason|revert):\s*(.+)", stdout)
            if error_match:
                error = error_match.group(1).strip()
            elif not compiled:
                error = "Compilation failed"

        return PoCResult(
            hypothesis_id=hypothesis_id,
            test_name=match_test or "unknown",
            test_file=str(test_file),
            compiled=compiled,
            passed=passed,
            gas_used=gas_used,
            logs=stdout,
            error=error,
        )
