"""Detect unchecked low-level call return values.

Identifies .call(), .send(), and .delegatecall() whose boolean return
value is not checked, which can silently fail and leave the contract
in an inconsistent state.
"""

# Low-level call patterns that return (bool, bytes)
LOW_LEVEL_CALL_PATTERNS = [
    ".call(",
    ".call{",
    ".delegatecall(",
    ".staticcall(",
    ".send(",
]


def detect(contract_data: dict) -> list[dict]:
    """Detect unchecked low-level call return values.

    Args:
        contract_data: Parsed Slither JSON contract information containing
            'functions' list with 'name', 'low_level_calls', 'content',
            and 'unchecked_calls' fields.

    Returns:
        List of finding dicts with keys: type, severity, confidence,
        description, function, contract, details.
    """
    findings = []
    functions = contract_data.get("functions", [])
    contract_name = contract_data.get("name", "Unknown")

    for func in functions:
        func_name = func.get("name", "")
        content = func.get("content", "")
        unchecked_calls = func.get("unchecked_calls", [])

        # Path 1: Explicit unchecked_calls field from Slither
        for call in unchecked_calls:
            call_type = call.get("type", "call")
            target = call.get("target", "unknown")
            line = call.get("line", None)

            findings.append({
                "type": "unchecked-low-level-call",
                "severity": "medium",
                "confidence": "high",
                "description": (
                    f"Unchecked {call_type} return value in {func_name}() "
                    f"targeting {target}."
                ),
                "function": func_name,
                "contract": contract_name,
                "details": {
                    "call_type": call_type,
                    "target": target,
                    "line": line,
                },
            })

        # Path 2: Heuristic analysis of function content
        if content and not unchecked_calls:
            unchecked = _find_unchecked_calls_in_source(content)
            for call_info in unchecked:
                findings.append({
                    "type": "unchecked-low-level-call",
                    "severity": "medium",
                    "confidence": "medium",
                    "description": (
                        f"Possible unchecked {call_info['pattern']} return value "
                        f"in {func_name}()."
                    ),
                    "function": func_name,
                    "contract": contract_name,
                    "details": {
                        "call_type": call_info["pattern"],
                        "source_analysis": True,
                    },
                })

    return findings


def _find_unchecked_calls_in_source(content: str) -> list[dict]:
    """Heuristic: find low-level calls whose return is likely unchecked.

    Looks for call patterns that are not preceded by (bool success, ) or
    require/if statements.
    """
    unchecked = []
    lines = content.split("\n")

    for i, line in enumerate(lines):
        stripped = line.strip()
        for pattern in LOW_LEVEL_CALL_PATTERNS:
            if pattern not in stripped:
                continue

            # Check if the return value is captured
            if _return_value_checked(stripped, lines, i):
                continue

            unchecked.append({
                "pattern": pattern.strip("({"),
                "line_offset": i,
                "code": stripped,
            })

    return unchecked


def _return_value_checked(line: str, all_lines: list[str], line_idx: int) -> bool:
    """Heuristic check if a low-level call's return value is used.

    Looks for patterns like:
    - (bool success, ) = addr.call(...)
    - require(addr.send(...))
    - if (!addr.send(...))
    - bool ok = addr.call(...)
    """
    # Pattern: (bool ...) = ...call
    if "(bool" in line and "=" in line:
        return True

    # Pattern: require(...call...)
    if "require(" in line:
        return True

    # Pattern: if (... call ...)
    if line.startswith("if") or line.startswith("if("):
        return True

    # Pattern: assert(... call ...)
    if "assert(" in line:
        return True

    # Check previous line for assignment pattern (multi-line)
    if line_idx > 0:
        prev = all_lines[line_idx - 1].strip()
        if prev.endswith("=") or "(bool" in prev:
            return True

    return False
