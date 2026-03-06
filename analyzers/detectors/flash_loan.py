"""Detect balanceOf-dependent logic vulnerable to flash loans.

Identifies contracts that use token balance checks (balanceOf, address.balance)
as authorization or pricing inputs, which can be manipulated via flash loans.
"""

# Balance query patterns
BALANCE_PATTERNS = [
    "balanceOf(",
    ".balance",
    "getBalance(",
    "totalSupply()",
]

# Sensitive contexts where balance-dependent logic is dangerous
SENSITIVE_CONTEXTS = [
    # Price calculation from reserves
    "getAmountsOut",
    "getReserves",
    "getPrice",
    "calcPrice",
    # Proportion/share calculations
    "totalSupply",
    "share",
    "ratio",
    # Access control based on balance
    "require(balanceOf",
    "require(token.balanceOf",
    # Swap/exchange functions
    "swap",
    "exchange",
]

# Flash loan callback signatures
FLASH_LOAN_CALLBACKS = [
    "executeOperation",
    "onFlashLoan",
    "flashLoanCallback",
    "uniswapV2Call",
    "uniswapV3FlashCallback",
    "pancakeCall",
]


def detect(contract_data: dict) -> list[dict]:
    """Detect balance-dependent logic vulnerable to flash loans.

    Args:
        contract_data: Parsed Slither JSON contract information containing
            'functions' list with 'name', 'content', 'state_variables_read',
            and 'external_calls' fields.

    Returns:
        List of finding dicts with keys: type, severity, confidence,
        description, function, contract, details.
    """
    findings = []
    functions = contract_data.get("functions", [])
    contract_name = contract_data.get("name", "Unknown")

    # Check if contract implements flash loan callbacks (might be intended)
    has_flash_loan_support = any(
        func.get("name", "") in FLASH_LOAN_CALLBACKS for func in functions
    )

    for func in functions:
        func_name = func.get("name", "")
        content = func.get("content", "")
        external_calls = func.get("external_calls", [])

        if not content:
            continue

        # Skip flash loan callback implementations themselves
        if func_name in FLASH_LOAN_CALLBACKS:
            continue

        balance_uses = _find_balance_queries(content, external_calls)
        if not balance_uses:
            continue

        # Check if balance is used in sensitive context
        sensitive_uses = _find_sensitive_balance_usage(content, balance_uses)

        if sensitive_uses:
            findings.append({
                "type": "flash-loan-balance-dependency",
                "severity": "high",
                "confidence": "high",
                "description": (
                    f"Function {func_name}() relies on balance checks "
                    f"({', '.join(u['pattern'] for u in balance_uses)}) "
                    f"in a sensitive context ({', '.join(sensitive_uses)}). "
                    f"This can be manipulated via flash loans."
                ),
                "function": func_name,
                "contract": contract_name,
                "details": {
                    "balance_queries": balance_uses,
                    "sensitive_contexts": sensitive_uses,
                    "has_flash_loan_support": has_flash_loan_support,
                },
            })
        else:
            # Balance query exists but context is unclear
            findings.append({
                "type": "flash-loan-balance-dependency",
                "severity": "medium",
                "confidence": "low",
                "description": (
                    f"Function {func_name}() uses balance queries "
                    f"({', '.join(u['pattern'] for u in balance_uses)}). "
                    f"Verify these cannot be manipulated via flash loans."
                ),
                "function": func_name,
                "contract": contract_name,
                "details": {
                    "balance_queries": balance_uses,
                    "sensitive_contexts": [],
                    "has_flash_loan_support": has_flash_loan_support,
                },
            })

    return findings


def _find_balance_queries(content: str, external_calls: list[dict]) -> list[dict]:
    """Find balance query patterns in function content and calls."""
    found = []
    seen = set()

    for pattern in BALANCE_PATTERNS:
        if pattern in content and pattern not in seen:
            seen.add(pattern)
            found.append({"pattern": pattern, "source": "content"})

    for call in external_calls:
        call_name = call.get("name", call.get("function", ""))
        for pattern in BALANCE_PATTERNS:
            clean = pattern.rstrip("()")
            if clean in call_name and pattern not in seen:
                seen.add(pattern)
                found.append({"pattern": pattern, "source": "external_call"})

    return found


def _find_sensitive_balance_usage(
    content: str, balance_uses: list[dict]
) -> list[str]:
    """Identify sensitive contexts where balance is used."""
    found = []
    for ctx in SENSITIVE_CONTEXTS:
        if ctx in content:
            found.append(ctx)
    return found
