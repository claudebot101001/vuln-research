"""Detect missing access control on sensitive functions.

Identifies functions performing privileged operations (withdraw, pause,
upgrade, selfdestruct, etc.) that lack owner/role-based access modifiers.
"""

# Functions that are considered sensitive and should have access control
SENSITIVE_FUNCTION_NAMES = [
    "withdraw",
    "withdrawAll",
    "emergencyWithdraw",
    "pause",
    "unpause",
    "setPaused",
    "upgrade",
    "upgradeTo",
    "upgradeToAndCall",
    "setImplementation",
    "selfdestruct",
    "destroy",
    "kill",
    "setOwner",
    "transferOwnership",
    "renounceOwnership",
    "setAdmin",
    "grantRole",
    "revokeRole",
    "setFee",
    "setFeeRecipient",
    "sweep",
    "rescue",
    "rescueTokens",
    "mint",
    "burn",
    "setOracle",
    "setPriceFeed",
    "setRouter",
    "initialize",
]

# Sensitive operations within function bodies
SENSITIVE_OPERATIONS = [
    "selfdestruct(",
    "delegatecall(",
    ".transfer(",
    ".call{value:",
    "SELFDESTRUCT",
]

# Known access control modifiers
ACCESS_CONTROL_MODIFIERS = [
    "onlyOwner",
    "onlyAdmin",
    "onlyRole",
    "onlyGovernance",
    "onlyAuthorized",
    "onlyOperator",
    "onlyGuardian",
    "onlyKeeper",
    "onlyMinter",
    "onlyPauser",
    "whenNotPaused",
    "initializer",
    "onlyProxy",
    "requiresAuth",
    "auth",
]


def detect(contract_data: dict) -> list[dict]:
    """Detect functions missing access control.

    Args:
        contract_data: Parsed Slither JSON contract information containing
            'functions' list with 'name', 'visibility', 'modifiers',
            'content', and optional 'is_constructor' fields.

    Returns:
        List of finding dicts with keys: type, severity, confidence,
        description, function, contract, details.
    """
    findings = []
    functions = contract_data.get("functions", [])
    contract_name = contract_data.get("name", "Unknown")

    for func in functions:
        func_name = func.get("name", "")
        visibility = func.get("visibility", "public")
        modifiers = func.get("modifiers", [])
        content = func.get("content", "")
        is_constructor = func.get("is_constructor", False)

        # Skip non-external/public functions and constructors
        if visibility not in ("public", "external"):
            continue
        if is_constructor or func_name == "constructor":
            continue

        has_access_control = _has_access_control(modifiers)

        # Check 1: Sensitive function name without access control
        if _is_sensitive_name(func_name) and not has_access_control:
            findings.append({
                "type": "missing-access-control",
                "severity": "high",
                "confidence": "high",
                "description": (
                    f"Function {func_name}() is {visibility} and performs "
                    f"a sensitive operation but has no access control modifier."
                ),
                "function": func_name,
                "contract": contract_name,
                "details": {
                    "visibility": visibility,
                    "modifiers": modifiers,
                    "reason": "sensitive_function_name",
                },
            })

        # Check 2: Contains sensitive operations without access control
        if content and not has_access_control:
            sensitive_ops = _find_sensitive_operations(content)
            if sensitive_ops:
                findings.append({
                    "type": "missing-access-control",
                    "severity": "high",
                    "confidence": "medium",
                    "description": (
                        f"Function {func_name}() contains sensitive operations "
                        f"({', '.join(sensitive_ops)}) without access control."
                    ),
                    "function": func_name,
                    "contract": contract_name,
                    "details": {
                        "visibility": visibility,
                        "modifiers": modifiers,
                        "sensitive_operations": sensitive_ops,
                        "reason": "sensitive_operation_in_body",
                    },
                })

        # Check 3: Sends ETH without access control
        if content and not has_access_control and _sends_eth(content):
            findings.append({
                "type": "unprotected-eth-transfer",
                "severity": "high",
                "confidence": "medium",
                "description": (
                    f"Function {func_name}() can send ETH but has "
                    f"no access control."
                ),
                "function": func_name,
                "contract": contract_name,
                "details": {
                    "visibility": visibility,
                    "modifiers": modifiers,
                    "reason": "unprotected_eth_send",
                },
            })

    return findings


def _is_sensitive_name(func_name: str) -> bool:
    """Check if function name matches a known sensitive pattern."""
    name_lower = func_name.lower()
    for sensitive in SENSITIVE_FUNCTION_NAMES:
        if sensitive.lower() == name_lower:
            return True
    # Also check prefix patterns
    sensitive_prefixes = ["set", "update", "change", "remove", "delete", "add"]
    for prefix in sensitive_prefixes:
        if name_lower.startswith(prefix) and len(name_lower) > len(prefix):
            # Only flag if the rest looks like a config parameter
            remainder = name_lower[len(prefix):]
            config_words = [
                "owner", "admin", "fee", "oracle", "price", "limit",
                "threshold", "implementation", "proxy", "router",
            ]
            if any(word in remainder for word in config_words):
                return True
    return False


def _has_access_control(modifiers: list[str]) -> bool:
    """Check if modifiers include access control."""
    for mod in modifiers:
        mod_lower = mod.lower()
        for ac_mod in ACCESS_CONTROL_MODIFIERS:
            if ac_mod.lower() in mod_lower:
                return True
        # Also check for require(msg.sender == ...) patterns
        if "only" in mod_lower:
            return True
    return False


def _find_sensitive_operations(content: str) -> list[str]:
    """Find sensitive operations in function body."""
    found = []
    for op in SENSITIVE_OPERATIONS:
        if op in content:
            found.append(op.rstrip("("))
    return found


def _sends_eth(content: str) -> bool:
    """Check if function body contains ETH transfer patterns."""
    eth_patterns = [".transfer(", ".send(", ".call{value:", "call{value:"]
    return any(p in content for p in eth_patterns)
