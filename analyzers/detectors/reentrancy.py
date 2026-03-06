"""Detect cross-function reentrancy patterns.

Identifies external calls followed by state writes where other functions
read the same state variables, enabling cross-function reentrancy attacks.
"""


# Patterns indicating external calls
EXTERNAL_CALL_PATTERNS = [
    ".call{",
    ".call(",
    ".transfer(",
    ".send(",
    ".delegatecall(",
    ".staticcall(",
]

# Patterns indicating state writes
STATE_WRITE_PATTERNS = [
    "=",  # assignment (filtered further by context)
    "delete ",
    "push(",
    "pop(",
]

# Known reentrancy guard patterns
GUARD_PATTERNS = [
    "nonReentrant",
    "ReentrancyGuard",
    "_locked",
    "require(!locked)",
    "_status",
]


def detect(contract_data: dict) -> list[dict]:
    """Detect cross-function reentrancy vulnerabilities.

    Args:
        contract_data: Parsed Slither JSON contract information containing
            'functions' list with 'external_calls', 'state_variables_written',
            'state_variables_read', and 'modifiers' fields.

    Returns:
        List of finding dicts with keys: type, severity, confidence,
        description, function, contract, details.
    """
    findings = []
    functions = contract_data.get("functions", [])
    contract_name = contract_data.get("name", "Unknown")

    # Build a map of state variables read by each function
    state_reads: dict[str, set[str]] = {}
    for func in functions:
        func_name = func.get("name", "")
        reads = set(func.get("state_variables_read", []))
        state_reads[func_name] = reads

    for func in functions:
        func_name = func.get("name", "")
        modifiers = func.get("modifiers", [])

        # Skip if function has reentrancy guard
        if _has_reentrancy_guard(modifiers):
            continue

        external_calls = func.get("external_calls", [])
        state_writes = func.get("state_variables_written", [])

        if not external_calls or not state_writes:
            continue

        # Check: external call happens before state write
        for call in external_calls:
            call_line = call.get("line", 0)
            for write_var in state_writes:
                write_line = write_var.get("line", 0) if isinstance(write_var, dict) else 0
                var_name = write_var.get("name", write_var) if isinstance(write_var, dict) else write_var

                # External call before state write is the classic pattern
                if call_line > 0 and write_line > 0 and call_line < write_line:
                    # Check for cross-function: does another function read this state?
                    cross_functions = _find_cross_function_reads(
                        var_name, func_name, state_reads
                    )

                    finding = {
                        "type": "cross-function-reentrancy",
                        "severity": "high",
                        "confidence": "high" if cross_functions else "medium",
                        "description": (
                            f"External call at line {call_line} in {func_name}() "
                            f"precedes state write to '{var_name}' at line {write_line}."
                        ),
                        "function": func_name,
                        "contract": contract_name,
                        "details": {
                            "external_call": call,
                            "state_variable": var_name,
                            "call_line": call_line,
                            "write_line": write_line,
                            "cross_function_reads": cross_functions,
                            "has_guard": False,
                        },
                    }
                    findings.append(finding)

                elif call_line == 0 or write_line == 0:
                    # Line info unavailable; flag based on pattern alone
                    cross_functions = _find_cross_function_reads(
                        var_name, func_name, state_reads
                    )
                    if cross_functions:
                        finding = {
                            "type": "cross-function-reentrancy",
                            "severity": "high",
                            "confidence": "low",
                            "description": (
                                f"Function {func_name}() has external calls and writes "
                                f"to '{var_name}' which is read by: "
                                f"{', '.join(cross_functions)}. "
                                f"Line ordering could not be verified."
                            ),
                            "function": func_name,
                            "contract": contract_name,
                            "details": {
                                "external_call": call,
                                "state_variable": var_name,
                                "cross_function_reads": cross_functions,
                                "has_guard": False,
                            },
                        }
                        findings.append(finding)

    return findings


def _has_reentrancy_guard(modifiers: list[str]) -> bool:
    """Check if any modifier is a known reentrancy guard."""
    for mod in modifiers:
        mod_lower = mod.lower()
        for pattern in GUARD_PATTERNS:
            if pattern.lower() in mod_lower:
                return True
    return False


def _find_cross_function_reads(
    variable: str, source_func: str, state_reads: dict[str, set[str]]
) -> list[str]:
    """Find functions that read a given state variable (excluding the source)."""
    readers = []
    for func_name, reads in state_reads.items():
        if func_name != source_func and variable in reads:
            readers.append(func_name)
    return readers
