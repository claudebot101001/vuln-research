"""Detect arithmetic in unchecked blocks and unsafe downcasts.

Identifies unchecked { } blocks containing arithmetic, unsafe type
narrowing (e.g., uint256 to uint128), and divide-before-multiply patterns.
"""


def detect(contract_data: dict) -> list[dict]:
    """Detect integer overflow/underflow vulnerabilities.

    Args:
        contract_data: Parsed Slither JSON contract information containing
            'functions' list with 'name', 'content', 'unchecked_blocks',
            and 'type_conversions' fields.

    Returns:
        List of finding dicts with keys: type, severity, confidence,
        description, function, contract, details.
    """
    findings = []
    functions = contract_data.get("functions", [])
    contract_name = contract_data.get("name", "Unknown")
    solc_version = contract_data.get("solc_version", "0.8.0")

    # Pre-0.8.0 contracts have no built-in overflow protection
    is_pre_080 = _is_pre_080(solc_version)

    for func in functions:
        func_name = func.get("name", "")
        content = func.get("content", "")
        unchecked_blocks = func.get("unchecked_blocks", [])
        type_conversions = func.get("type_conversions", [])

        # Check 1: Arithmetic in unchecked blocks
        for block in unchecked_blocks:
            block_content = block.get("content", "")
            arithmetic_ops = _find_arithmetic(block_content)
            if arithmetic_ops:
                findings.append({
                    "type": "unchecked-arithmetic",
                    "severity": "high",
                    "confidence": "high",
                    "description": (
                        f"Unchecked arithmetic in {func_name}(): "
                        f"operations {', '.join(arithmetic_ops)} inside "
                        f"unchecked block. Overflow/underflow is possible."
                    ),
                    "function": func_name,
                    "contract": contract_name,
                    "details": {
                        "operations": arithmetic_ops,
                        "block_content": block_content[:200],
                    },
                })

        # Check 2: Source-level unchecked block detection
        if content and not unchecked_blocks:
            unchecked_findings = _find_unchecked_in_source(content)
            for uf in unchecked_findings:
                findings.append({
                    "type": "unchecked-arithmetic",
                    "severity": "high",
                    "confidence": "medium",
                    "description": (
                        f"Unchecked arithmetic in {func_name}(): "
                        f"found unchecked block with arithmetic operations."
                    ),
                    "function": func_name,
                    "contract": contract_name,
                    "details": uf,
                })

        # Check 3: Unsafe downcasts
        for conversion in type_conversions:
            from_type = conversion.get("from", "")
            to_type = conversion.get("to", "")
            if _is_unsafe_downcast(from_type, to_type):
                findings.append({
                    "type": "unsafe-downcast",
                    "severity": "medium",
                    "confidence": "high",
                    "description": (
                        f"Unsafe downcast from {from_type} to {to_type} "
                        f"in {func_name}(). Value truncation may occur."
                    ),
                    "function": func_name,
                    "contract": contract_name,
                    "details": {
                        "from_type": from_type,
                        "to_type": to_type,
                    },
                })

        # Check 4: Source-level downcast detection
        if content:
            downcasts = _find_downcasts_in_source(content)
            for dc in downcasts:
                findings.append({
                    "type": "unsafe-downcast",
                    "severity": "medium",
                    "confidence": "medium",
                    "description": (
                        f"Possible unsafe downcast to {dc['to_type']} "
                        f"in {func_name}(). Value truncation may occur."
                    ),
                    "function": func_name,
                    "contract": contract_name,
                    "details": dc,
                })

        # Check 5: Divide-before-multiply
        if content and _has_divide_before_multiply(content):
            findings.append({
                "type": "divide-before-multiply",
                "severity": "medium",
                "confidence": "medium",
                "description": (
                    f"Possible divide-before-multiply in {func_name}(). "
                    f"Integer division truncates, which loses precision "
                    f"when followed by multiplication."
                ),
                "function": func_name,
                "contract": contract_name,
                "details": {
                    "pattern": "divide-before-multiply",
                },
            })

        # Check 6: Pre-0.8.0 arithmetic without SafeMath
        if is_pre_080 and content:
            arithmetic = _find_arithmetic(content)
            if arithmetic and "SafeMath" not in content:
                findings.append({
                    "type": "pre-080-no-safemath",
                    "severity": "high",
                    "confidence": "high",
                    "description": (
                        f"Pre-0.8.0 contract uses arithmetic in {func_name}() "
                        f"without SafeMath library."
                    ),
                    "function": func_name,
                    "contract": contract_name,
                    "details": {
                        "solc_version": solc_version,
                        "operations": arithmetic,
                    },
                })

    return findings


def _is_pre_080(version: str) -> bool:
    """Check if solc version is before 0.8.0."""
    try:
        parts = version.split(".")
        major, minor = int(parts[0]), int(parts[1])
        return major == 0 and minor < 8
    except (ValueError, IndexError):
        return False


def _find_arithmetic(content: str) -> list[str]:
    """Find arithmetic operations in content."""
    ops = []
    # Simple heuristic: look for operators with operands
    if "+" in content and "++" not in content.replace("++", ""):
        ops.append("+")
    if "-" in content and "--" not in content.replace("--", "") and "->" not in content:
        ops.append("-")
    if "*" in content and "**" not in content:
        ops.append("*")
    if "/" in content and "//" not in content and "/*" not in content:
        ops.append("/")
    return ops


def _find_unchecked_in_source(content: str) -> list[dict]:
    """Find unchecked blocks with arithmetic in source code."""
    findings = []
    idx = 0
    while True:
        pos = content.find("unchecked", idx)
        if pos == -1:
            break
        # Find the matching block
        brace_start = content.find("{", pos)
        if brace_start == -1:
            break
        brace_end = _find_matching_brace(content, brace_start)
        if brace_end == -1:
            break
        block = content[brace_start:brace_end + 1]
        arithmetic = _find_arithmetic(block)
        if arithmetic:
            findings.append({
                "operations": arithmetic,
                "block_preview": block[:200],
            })
        idx = brace_end + 1
    return findings


def _find_matching_brace(content: str, start: int) -> int:
    """Find the matching closing brace."""
    depth = 0
    for i in range(start, len(content)):
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _is_unsafe_downcast(from_type: str, to_type: str) -> bool:
    """Check if a type conversion is an unsafe narrowing cast."""
    from_bits = _extract_bits(from_type)
    to_bits = _extract_bits(to_type)
    if from_bits is not None and to_bits is not None:
        return to_bits < from_bits
    return False


def _extract_bits(type_name: str) -> int | None:
    """Extract bit width from Solidity integer type."""
    import re

    match = re.match(r"u?int(\d+)", type_name)
    if match:
        return int(match.group(1))
    if type_name in ("uint", "int"):
        return 256
    return None


def _find_downcasts_in_source(content: str) -> list[dict]:
    """Find potential unsafe downcasts in source code."""
    import re

    findings = []
    # Pattern: uint128(someUint256Var) or int64(someValue)
    cast_pattern = re.compile(r"(u?int\d+)\s*\(")
    for match in cast_pattern.finditer(content):
        to_type = match.group(1)
        to_bits = _extract_bits(to_type)
        # If casting to a smaller type, flag it
        if to_bits is not None and to_bits < 256:
            findings.append({
                "to_type": to_type,
                "to_bits": to_bits,
                "position": match.start(),
            })
    return findings


def _has_divide_before_multiply(content: str) -> bool:
    """Heuristic: check for divide-before-multiply patterns."""
    import re

    # Look for pattern: expr / expr * expr
    # Simplified: look for / followed by * on same or next expression
    lines = content.split("\n")
    for line in lines:
        stripped = line.strip()
        # Simple pattern: a / b * c
        if re.search(r"\w+\s*/\s*\w+\s*\*\s*\w+", stripped):
            return True
    return False
