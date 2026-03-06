"""Code context extraction for vulnerability findings.

Two extraction modes:
1. Slither API mode (preferred): Uses slither.core.declarations for AST-level
   extraction — accurate call graphs, state variable mapping, inheritance.
2. Regex fallback mode: Best-effort extraction with known limitations:
   - May miss multi-contract files (extracts first matching contract)
   - Assembly blocks can confuse function boundary detection
   - NatSpec comments may contain code-like patterns
   - 'using X for Y' directives not tracked
   Returns partial CodeContext with empty fields where extraction failed.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from .models import CodeContext, Finding

logger = logging.getLogger(__name__)

# Lines of context to extract around a finding
SNIPPET_CONTEXT_LINES = 25  # 25 before + 25 after = ~50 lines


class ContextExtractor:
    """Extracts rich code context for vulnerability findings."""

    def __init__(self, target_dir: Path | str) -> None:
        self.target_dir = Path(target_dir)
        self._slither = self._try_load_slither(self.target_dir)

    def extract(self, finding: Finding) -> CodeContext:
        """Extract rich code context for a finding.

        Dispatches to Slither API mode if available, otherwise falls back
        to regex-based extraction.
        """
        if self._slither:
            try:
                return self._extract_via_slither(finding)
            except Exception as e:
                logger.warning(
                    "Slither extraction failed for %s, falling back to regex: %s",
                    finding.id,
                    e,
                )
        return self._extract_via_regex(finding)

    def estimate_token_count(self, context: CodeContext) -> int:
        """Rough token estimate for context (chars / 4)."""
        total_chars = sum(
            len(getattr(context, f)) for f in ["source_snippet", "full_function", "contract_source"]
        )
        total_chars += sum(len(s) for s in context.call_graph)
        total_chars += sum(len(s) for s in context.state_variables)
        total_chars += sum(len(s) for s in context.inheritance_chain)
        total_chars += sum(len(s) for s in context.related_functions)
        return total_chars // 4

    # ------------------------------------------------------------------
    # Slither mode
    # ------------------------------------------------------------------

    @staticmethod
    def _try_load_slither(target_dir: Path):
        """Try to load Slither on the target directory.

        Returns the Slither object if successful, None otherwise.
        Slither may fail due to: not installed, solc version mismatch,
        compilation errors, etc.
        """
        try:
            from slither.slither import Slither  # type: ignore[import-untyped]

            sl = Slither(str(target_dir))
            logger.info("Slither loaded successfully for %s", target_dir)
            return sl
        except ImportError:
            logger.info("Slither not installed, using regex fallback")
            return None
        except Exception as e:
            logger.warning("Slither failed to load %s: %s", target_dir, e)
            return None

    def _extract_via_slither(self, finding: Finding) -> CodeContext:
        """Use Slither's Python API for AST-level extraction.

        Uses slither.core.declarations (Contract, Function, StateVariable)
        for accurate call graphs, state variable mapping, and inheritance.
        """
        sl = self._slither
        contract_name = finding.contract
        function_name = finding.function

        # Find the contract
        target_contract = None
        for contract in sl.contracts:
            if contract.name == contract_name:
                target_contract = contract
                break

        if target_contract is None:
            logger.warning(
                "Contract %s not found in Slither, falling back to regex",
                contract_name,
            )
            return self._extract_via_regex(finding)

        # Inheritance chain
        inheritance_chain = [c.name for c in target_contract.inheritance]

        # State variables
        state_variables = []
        for sv in target_contract.state_variables:
            visibility = sv.visibility if hasattr(sv, "visibility") else ""
            state_variables.append(f"{sv.type} {visibility} {sv.name}".strip())

        # Find target function
        target_function = None
        if function_name:
            for fn in target_contract.functions + target_contract.modifiers:
                if fn.name == function_name:
                    target_function = fn
                    break

        # Full function body
        full_function = ""
        if target_function and target_function.source_mapping:
            full_function = _read_source_mapping(target_function.source_mapping, self.target_dir)

        # Source snippet (~50 lines around finding)
        source_snippet = self._extract_snippet_from_file(finding)

        # Contract source
        contract_source = ""
        if target_contract.source_mapping:
            raw = _read_source_mapping(target_contract.source_mapping, self.target_dir)
            # Truncate if >500 lines
            lines = raw.split("\n")
            if len(lines) > 500:
                contract_source = "\n".join(lines[:500]) + "\n// ... truncated ..."
            else:
                contract_source = raw

        # Call graph
        call_graph: list[str] = []
        if target_function:
            # Functions called by the target function
            for called in target_function.internal_calls:
                if hasattr(called, "name"):
                    call_graph.append(f"{contract_name}.{function_name} -> {called.name}")
            for called in target_function.external_calls_as_expressions:
                call_graph.append(f"{contract_name}.{function_name} -> {called}")
            # Functions that call the target function
            for fn in target_contract.functions:
                if target_function in fn.internal_calls:
                    call_graph.append(
                        f"{contract_name}.{fn.name} -> {contract_name}.{function_name}"
                    )

        # Related functions (functions that access the same state variables)
        related_functions: list[str] = []
        if target_function:
            target_vars = set()
            for var in target_function.state_variables_read:
                target_vars.add(var.name)
            for var in target_function.state_variables_written:
                target_vars.add(var.name)

            for fn in target_contract.functions:
                if fn == target_function:
                    continue
                fn_vars = set()
                for var in fn.state_variables_read:
                    fn_vars.add(var.name)
                for var in fn.state_variables_written:
                    fn_vars.add(var.name)
                if fn_vars & target_vars:
                    related_functions.append(fn.name)

        return CodeContext(
            finding_id=finding.id,
            source_snippet=source_snippet,
            full_function=full_function,
            contract_source=contract_source,
            call_graph=call_graph,
            state_variables=state_variables,
            inheritance_chain=inheritance_chain,
            related_functions=related_functions,
        )

    # ------------------------------------------------------------------
    # Regex fallback mode
    # ------------------------------------------------------------------

    def _extract_via_regex(self, finding: Finding) -> CodeContext:
        """Best-effort regex extraction.

        Known limitations:
        - May miss multi-contract files (extracts first matching contract)
        - Assembly blocks can confuse function boundary detection
        - NatSpec comments may contain code-like patterns
        - 'using X for Y' directives not tracked
        Returns partial CodeContext with empty fields where extraction failed.
        """
        source_snippet = self._extract_snippet_from_file(finding)

        # Read the full source file
        source_text = self._read_finding_file(finding)

        # Extract function body
        full_function = ""
        if finding.function and source_text:
            full_function = _regex_extract_function(source_text, finding.function)

        # Extract contract source and inheritance
        contract_source = ""
        inheritance_chain: list[str] = []
        if finding.contract and source_text:
            contract_source, inheritance_chain = _regex_extract_contract(
                source_text, finding.contract
            )
            # Truncate if >500 lines
            lines = contract_source.split("\n")
            if len(lines) > 500:
                contract_source = "\n".join(lines[:500]) + "\n// ... truncated ..."

        # Extract state variables
        state_variables: list[str] = []
        if contract_source:
            state_variables = _regex_extract_state_variables(contract_source)

        return CodeContext(
            finding_id=finding.id,
            source_snippet=source_snippet,
            full_function=full_function,
            contract_source=contract_source,
            call_graph=[],  # Cannot determine via regex
            state_variables=state_variables,
            inheritance_chain=inheritance_chain,
            related_functions=[],  # Cannot determine via regex
        )

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _extract_snippet_from_file(self, finding: Finding) -> str:
        """Extract ~50 lines of source around the finding location."""
        source_text = self._read_finding_file(finding)
        if not source_text:
            return finding.code_snippet or ""

        lines = source_text.split("\n")
        line_num = finding.line_start or 1
        start = max(0, line_num - 1 - SNIPPET_CONTEXT_LINES)
        end = min(len(lines), line_num + SNIPPET_CONTEXT_LINES)
        return "\n".join(lines[start:end])

    def _read_finding_file(self, finding: Finding) -> str:
        """Read the source file referenced by a finding."""
        file_path = Path(finding.file_path)
        if not file_path.is_absolute():
            # Avoid doubling: if file_path already starts with target_dir, use as-is
            if not file_path.exists():
                candidate = self.target_dir / file_path
                if candidate.exists():
                    file_path = candidate
        try:
            return file_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, FileNotFoundError):
            logger.warning("Cannot read source file: %s", file_path)
            return ""


# ------------------------------------------------------------------
# Regex extraction helpers (module-level, stateless)
# ------------------------------------------------------------------

# Matches: function name(...) ... {
_FUNCTION_PATTERN = re.compile(
    r"function\s+(\w+)\s*\([^)]*\)"  # function name(params)
    r"[^{]*"  # visibility, modifiers, returns
    r"\{",  # opening brace
    re.DOTALL,
)

# Matches: contract Name is Base1, Base2 {
_CONTRACT_PATTERN = re.compile(
    r"(contract|library|interface)\s+(\w+)"
    r"(?:\s+is\s+([^{]+))?"  # optional inheritance
    r"\s*\{",
    re.DOTALL,
)

# Matches state variable declarations (simplified)
_STATE_VAR_PATTERN = re.compile(
    r"^\s+"  # indented (inside contract)
    r"("
    r"(?:mapping\s*\([^)]+\)|[\w\[\]]+)"  # type (including mapping)
    r"(?:\s+(?:public|private|internal|external|constant|immutable|override))+"  # modifiers
    r"\s+\w+"  # name
    r"[^;]*;"  # rest until semicolon
    r")",
    re.MULTILINE,
)

# Broader state var pattern for lines that look like declarations
_STATE_VAR_BROAD = re.compile(
    r"^\s+"
    r"((?:mapping|uint\d*|int\d*|address|bool|bytes\d*|string|"
    r"I\w+|IERC\w+|\w+(?:\[\])?)"  # common Solidity types
    r"(?:\s*\([^)]*\))?"  # mapping args
    r"(?:\s+(?:public|private|internal|external|constant|immutable|override))*"
    r"\s+\w+"
    r"\s*(?:=[^;]*)?"  # optional initializer
    r"\s*;)",
    re.MULTILINE,
)


def _regex_extract_function(source: str, function_name: str) -> str:
    """Extract a function body from Solidity source by name.

    Finds the function declaration and matches braces to find the closing }.
    """
    # Find the function declaration
    pattern = re.compile(
        r"function\s+" + re.escape(function_name) + r"\s*\([^)]*\)[^{]*\{",
        re.DOTALL,
    )
    match = pattern.search(source)
    if not match:
        return ""

    # Find matching closing brace
    start = match.start()
    brace_start = match.end() - 1  # Position of opening {
    body_end = _find_matching_brace(source, brace_start)
    if body_end == -1:
        # Fallback: take next 50 lines from function start
        lines = source[start:].split("\n")
        return "\n".join(lines[:50])

    return source[start : body_end + 1]


def _find_matching_brace(source: str, open_pos: int) -> int:
    """Find the position of the matching closing brace.

    Handles nested braces. Ignores braces inside string literals and comments.
    Returns -1 if no match found.
    """
    depth = 0
    i = open_pos
    in_line_comment = False
    in_block_comment = False
    in_string = False
    string_char = ""

    while i < len(source):
        ch = source[i]
        next_ch = source[i + 1] if i + 1 < len(source) else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
        elif in_block_comment:
            if ch == "*" and next_ch == "/":
                in_block_comment = False
                i += 1
        elif in_string:
            if ch == "\\" and next_ch:
                i += 1  # skip escaped char
            elif ch == string_char:
                in_string = False
        else:
            if ch == "/" and next_ch == "/":
                in_line_comment = True
                i += 1
            elif ch == "/" and next_ch == "*":
                in_block_comment = True
                i += 1
            elif ch in ('"', "'"):
                in_string = True
                string_char = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i

        i += 1

    return -1


def _regex_extract_contract(source: str, contract_name: str) -> tuple[str, list[str]]:
    """Extract a contract body and its inheritance chain from source.

    Returns (contract_source, inheritance_chain).
    For multi-contract files, extracts the first contract matching the name.
    """
    pattern = re.compile(
        r"(contract|library|interface)\s+" + re.escape(contract_name) + r"(?:\s+is\s+([^{]+))?"
        r"\s*\{",
        re.DOTALL,
    )
    match = pattern.search(source)
    if not match:
        return "", []

    # Parse inheritance
    inheritance_chain = [contract_name]
    if match.group(2):
        bases = match.group(2).strip()
        for base in bases.split(","):
            base = base.strip()
            if base:
                # Remove any generic params like Ownable(msg.sender)
                base_name = re.match(r"(\w+)", base)
                if base_name:
                    inheritance_chain.append(base_name.group(1))

    # Find matching closing brace for the contract
    start = match.start()
    brace_start = match.end() - 1
    body_end = _find_matching_brace(source, brace_start)
    if body_end == -1:
        # Take everything from contract start to end of file
        return source[start:], inheritance_chain

    return source[start : body_end + 1], inheritance_chain


def _regex_extract_state_variables(contract_source: str) -> list[str]:
    """Extract state variable declarations from a contract body.

    Looks for lines between the contract opening brace and the first
    function/modifier/event/constructor declaration. Also picks up
    variable-like declarations throughout the contract.
    """
    variables: list[str] = []
    seen: set[str] = set()

    # Try the broad pattern across the entire contract
    for match in _STATE_VAR_BROAD.finditer(contract_source):
        var_text = match.group(1).strip()
        # Skip if it looks like a function call or control structure
        if any(
            kw in var_text for kw in ["function ", "modifier ", "event ", "constructor", "return "]
        ):
            continue
        if var_text not in seen:
            variables.append(var_text)
            seen.add(var_text)

    # Also try the stricter pattern for anything we missed
    for match in _STATE_VAR_PATTERN.finditer(contract_source):
        var_text = match.group(1).strip()
        if var_text not in seen:
            variables.append(var_text)
            seen.add(var_text)

    return variables


def _read_source_mapping(source_mapping, target_dir: Path) -> str:
    """Read source code from a Slither source mapping object."""
    try:
        filename = source_mapping.filename.absolute
        if not filename:
            filename = source_mapping.filename.relative
            if filename:
                filename = str(target_dir / filename)
        if not filename:
            return ""
        start = source_mapping.start
        length = source_mapping.length
        content = Path(filename).read_text(encoding="utf-8", errors="replace")
        return content[start : start + length]
    except Exception as e:
        logger.warning("Failed to read source mapping: %s", e)
        return ""
