"""Phase 6: PoC verification via Foundry."""

import re
import shutil
import subprocess
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from .models import Hypothesis, PoCResult

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "foundry" / "templates"

# Map attack vector keywords to template files
TEMPLATE_MAP: dict[str, str] = {
    "reentrancy": "reentrancy_poc.sol.j2",
    "re-enter": "reentrancy_poc.sol.j2",
    "reentrant": "reentrancy_poc.sol.j2",
    "flash_loan": "flash_loan_poc.sol.j2",
    "flash-loan": "flash_loan_poc.sol.j2",
    "flash loan": "flash_loan_poc.sol.j2",
    "flashloan": "flash_loan_poc.sol.j2",
    "access_control": "access_control_poc.sol.j2",
    "access-control": "access_control_poc.sol.j2",
    "authorization": "access_control_poc.sol.j2",
    "unprotected": "access_control_poc.sol.j2",
    "oracle": "oracle_manipulation_poc.sol.j2",
    "oracle_manipulation": "oracle_manipulation_poc.sol.j2",
    "oracle-manipulation": "oracle_manipulation_poc.sol.j2",
    "integer_overflow": "integer_overflow_poc.sol.j2",
    "integer-overflow": "integer_overflow_poc.sol.j2",
    "overflow": "integer_overflow_poc.sol.j2",
    "underflow": "integer_overflow_poc.sol.j2",
}


class Verifier:
    def __init__(self, output_dir: Path | None = None):
        self.output_dir = output_dir or Path("output") / "poc"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            keep_trailing_newline=True,
        )

    def select_template(self, hypothesis: Hypothesis) -> str | None:
        """Select the best template based on hypothesis attack_vector keywords."""
        vector = hypothesis.attack_vector.lower()
        for keyword, template_name in TEMPLATE_MAP.items():
            if keyword in vector:
                return template_name
        return None

    def render_poc(self, hypothesis: Hypothesis, params: dict | None = None) -> Path | None:
        """Render a PoC .t.sol file from hypothesis and optional extra params."""
        template_name = self.select_template(hypothesis)
        if not template_name:
            return None

        template = self.env.get_template(template_name)

        # Build template variables from hypothesis + params
        variables = {
            "target_function": hypothesis.target_functions[0] if hypothesis.target_functions else "exploit",
            "fork_url": None,
            "fork_block": hypothesis.fork_block,
        }
        if params:
            variables.update(params)

        rendered = template.render(**variables)

        test_file = self.output_dir / f"{hypothesis.id}.t.sol"
        test_file.write_text(rendered)
        return test_file

    def run_forge(self, test_file: Path, match_test: str | None = None) -> PoCResult:
        """Run forge test on a rendered .t.sol file and parse results."""
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
                cwd=test_file.parent,
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

    def verify(self, hypothesis: Hypothesis, params: dict | None = None) -> PoCResult:
        """End-to-end: select template, render, run forge, return result."""
        template_name = self.select_template(hypothesis)
        if not template_name:
            return PoCResult(
                hypothesis_id=hypothesis.id,
                test_name="unknown",
                test_file="",
                compiled=False,
                passed=False,
                error=f"No template found for attack vector: {hypothesis.attack_vector}",
            )

        test_file = self.render_poc(hypothesis, params)
        if not test_file:
            return PoCResult(
                hypothesis_id=hypothesis.id,
                test_name="unknown",
                test_file="",
                compiled=False,
                passed=False,
                error="Failed to render PoC template",
            )

        # Derive test function name from template
        match_test = _test_name_from_template(template_name)
        return self.run_forge(test_file, match_test=match_test)

    def _parse_forge_output(
        self,
        stdout: str,
        test_file: Path,
        match_test: str | None,
    ) -> PoCResult:
        """Parse forge test stdout into a PoCResult."""
        hypothesis_id = test_file.stem.replace(".t", "")

        # Check compilation
        compiled = "Compiler run successful" in stdout or "[PASS]" in stdout or "[FAIL]" in stdout

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


def _test_name_from_template(template_name: str) -> str:
    """Derive the forge test function name from template filename."""
    name_map = {
        "reentrancy_poc.sol.j2": "test_reentrancy_exploit",
        "flash_loan_poc.sol.j2": "test_flash_loan_exploit",
        "access_control_poc.sol.j2": "test_access_control_bypass",
        "oracle_manipulation_poc.sol.j2": "test_oracle_manipulation",
        "integer_overflow_poc.sol.j2": "test_integer_overflow",
    }
    return name_map.get(template_name, "test_")
