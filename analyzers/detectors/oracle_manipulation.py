"""Detect price oracle usage without staleness checks or TWAP.

Identifies contracts that consume oracle price data (Chainlink, Uniswap
TWAP, custom oracles) without validating freshness, zero-price, or
round completeness.
"""

# Oracle interaction patterns
ORACLE_CALL_PATTERNS = [
    "latestRoundData",
    "latestAnswer",
    "getPrice",
    "getUnderlyingPrice",
    "consult",
    "observe",
    "slot0",
    "getAmountsOut",
    "getReserves",
]

# Staleness check patterns (what we expect to see)
STALENESS_CHECK_PATTERNS = [
    "updatedAt",
    "block.timestamp",
    "answeredInRound",
    "roundId",
    "heartbeat",
    "staleness",
    "maxDelay",
    "MAX_DELAY",
    "PRICE_STALE",
    "stalePrice",
]

# Zero/negative price check patterns
PRICE_VALIDATION_PATTERNS = [
    "price > 0",
    "price != 0",
    "answer > 0",
    "answer != 0",
    "require(price",
    "require(answer",
    "if (price <= 0",
    "if (answer <= 0",
]


def detect(contract_data: dict) -> list[dict]:
    """Detect oracle usage without proper validation.

    Args:
        contract_data: Parsed Slither JSON contract information containing
            'functions' list with 'name', 'content', 'external_calls',
            and 'state_variables_read' fields.

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
        external_calls = func.get("external_calls", [])

        # Detect oracle calls from external_calls metadata
        oracle_calls = _find_oracle_calls(external_calls)

        # Also detect from source content
        if content:
            oracle_calls.extend(_find_oracle_patterns_in_source(content))

        if not oracle_calls:
            continue

        # Check for missing staleness validation
        has_staleness = _has_staleness_check(content, func)
        has_price_validation = _has_price_validation(content)

        if not has_staleness:
            findings.append({
                "type": "oracle-no-staleness-check",
                "severity": "high",
                "confidence": "high" if content else "medium",
                "description": (
                    f"Function {func_name}() uses oracle data "
                    f"({', '.join(c['type'] for c in oracle_calls)}) "
                    f"without checking data freshness/staleness."
                ),
                "function": func_name,
                "contract": contract_name,
                "details": {
                    "oracle_calls": oracle_calls,
                    "missing_check": "staleness",
                    "has_price_validation": has_price_validation,
                },
            })

        if not has_price_validation:
            findings.append({
                "type": "oracle-no-price-validation",
                "severity": "high",
                "confidence": "high" if content else "medium",
                "description": (
                    f"Function {func_name}() uses oracle price data "
                    f"without validating price > 0."
                ),
                "function": func_name,
                "contract": contract_name,
                "details": {
                    "oracle_calls": oracle_calls,
                    "missing_check": "price_validation",
                    "has_staleness": has_staleness,
                },
            })

        # Check for Uniswap spot price usage (vulnerable to manipulation)
        spot_price_calls = [
            c for c in oracle_calls if c["type"] in ("slot0", "getReserves")
        ]
        if spot_price_calls:
            findings.append({
                "type": "oracle-spot-price-manipulation",
                "severity": "high",
                "confidence": "high",
                "description": (
                    f"Function {func_name}() uses spot price "
                    f"({', '.join(c['type'] for c in spot_price_calls)}) "
                    f"which is vulnerable to flash loan manipulation. "
                    f"Use TWAP instead."
                ),
                "function": func_name,
                "contract": contract_name,
                "details": {
                    "oracle_calls": spot_price_calls,
                    "recommendation": "Use TWAP or time-weighted oracle",
                },
            })

    return findings


def _find_oracle_calls(external_calls: list[dict]) -> list[dict]:
    """Extract oracle-related calls from external calls metadata."""
    oracle_calls = []
    for call in external_calls:
        call_name = call.get("name", call.get("function", ""))
        for pattern in ORACLE_CALL_PATTERNS:
            if pattern in call_name:
                oracle_calls.append({
                    "type": pattern,
                    "call": call,
                })
                break
    return oracle_calls


def _find_oracle_patterns_in_source(content: str) -> list[dict]:
    """Find oracle call patterns in function source code."""
    oracle_calls = []
    for pattern in ORACLE_CALL_PATTERNS:
        if pattern in content:
            oracle_calls.append({
                "type": pattern,
                "source": True,
            })
    return oracle_calls


def _has_staleness_check(content: str, func: dict) -> bool:
    """Check if function validates oracle data freshness."""
    if not content:
        return False
    for pattern in STALENESS_CHECK_PATTERNS:
        if pattern in content:
            return True
    return False


def _has_price_validation(content: str) -> bool:
    """Check if function validates oracle price is positive."""
    if not content:
        return False
    for pattern in PRICE_VALIDATION_PATTERNS:
        if pattern in content:
            return True
    return False
