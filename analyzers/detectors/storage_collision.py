"""Detect proxy storage layout issues and delegatecall to variable addresses.

Identifies storage slot collisions in upgradeable proxy patterns,
uninitialized storage pointers, delegatecall to user-controlled or
variable addresses, and missing storage gap declarations.
"""

# EIP-1967 standard storage slots
EIP1967_SLOTS = {
    "implementation": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "admin": "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    "beacon": "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
}

# Proxy-related patterns
PROXY_PATTERNS = [
    "delegatecall",
    "Proxy",
    "Upgradeable",
    "ERC1967",
    "TransparentProxy",
    "UUPSUpgradeable",
    "BeaconProxy",
]

# Storage gap pattern
STORAGE_GAP_PATTERN = "__gap"


def detect(contract_data: dict) -> list[dict]:
    """Detect storage collision and proxy-related vulnerabilities.

    Args:
        contract_data: Parsed Slither JSON contract information containing
            'name', 'functions', 'state_variables', 'is_proxy',
            'inherited_contracts', and 'content' fields.

    Returns:
        List of finding dicts with keys: type, severity, confidence,
        description, function, contract, details.
    """
    findings = []
    contract_name = contract_data.get("name", "Unknown")
    functions = contract_data.get("functions", [])
    state_variables = contract_data.get("state_variables", [])
    is_proxy = contract_data.get("is_proxy", False)
    inherited = contract_data.get("inherited_contracts", [])
    content = contract_data.get("content", "")

    # Detect if this is a proxy/upgradeable contract
    if not is_proxy:
        is_proxy = _detect_proxy_pattern(contract_name, inherited, content)

    # Check 1: Delegatecall to variable address
    for func in functions:
        func_name = func.get("name", "")
        func_content = func.get("content", "")
        parameters = func.get("parameters", [])

        if "delegatecall" in func_content:
            # Check if delegatecall target is a variable (not hardcoded)
            if _delegatecall_to_variable(func_content, parameters):
                findings.append({
                    "type": "delegatecall-variable-target",
                    "severity": "critical",
                    "confidence": "high",
                    "description": (
                        f"Function {func_name}() uses delegatecall with a "
                        f"variable target address. An attacker who controls "
                        f"this address can execute arbitrary code."
                    ),
                    "function": func_name,
                    "contract": contract_name,
                    "details": {
                        "pattern": "delegatecall-to-variable",
                    },
                })

    # Check 2: Missing storage gap in upgradeable base contract
    if is_proxy and not _has_storage_gap(state_variables, content):
        findings.append({
            "type": "missing-storage-gap",
            "severity": "high",
            "confidence": "medium",
            "description": (
                f"Upgradeable contract {contract_name} does not declare a "
                f"storage gap (__gap). Adding new state variables in future "
                f"upgrades may collide with derived contract storage."
            ),
            "function": None,
            "contract": contract_name,
            "details": {
                "is_proxy": True,
                "state_variable_count": len(state_variables),
            },
        })

    # Check 3: Storage slot collision between proxy and implementation
    if is_proxy and state_variables:
        collisions = _check_slot_collisions(state_variables)
        for collision in collisions:
            findings.append({
                "type": "storage-slot-collision",
                "severity": "critical",
                "confidence": "high",
                "description": (
                    f"Storage slot collision in {contract_name}: "
                    f"{collision['description']}"
                ),
                "function": None,
                "contract": contract_name,
                "details": collision,
            })

    # Check 4: Uninitialized storage pointer
    for func in functions:
        func_name = func.get("name", "")
        func_content = func.get("content", "")

        if _has_uninitialized_storage(func_content):
            findings.append({
                "type": "uninitialized-storage-pointer",
                "severity": "high",
                "confidence": "medium",
                "description": (
                    f"Possible uninitialized storage pointer in "
                    f"{func_name}(). Local storage variables that are not "
                    f"explicitly initialized point to slot 0 and can "
                    f"overwrite critical state."
                ),
                "function": func_name,
                "contract": contract_name,
                "details": {
                    "pattern": "uninitialized-storage-pointer",
                },
            })

    # Check 5: Missing initializer in upgradeable contract
    if is_proxy:
        has_initializer = any(
            "initialize" in func.get("name", "").lower()
            or "initializer" in " ".join(func.get("modifiers", []))
            for func in functions
        )
        has_constructor = any(
            func.get("is_constructor", False) or func.get("name") == "constructor"
            for func in functions
        )
        if has_constructor and not has_initializer:
            findings.append({
                "type": "upgradeable-uses-constructor",
                "severity": "high",
                "confidence": "high",
                "description": (
                    f"Upgradeable contract {contract_name} uses a constructor "
                    f"instead of an initializer. Constructors are not called "
                    f"in proxy contexts; use an initializer function instead."
                ),
                "function": "constructor",
                "contract": contract_name,
                "details": {
                    "has_constructor": True,
                    "has_initializer": has_initializer,
                },
            })

    return findings


def _detect_proxy_pattern(
    name: str, inherited: list[str], content: str
) -> bool:
    """Detect if contract is a proxy/upgradeable contract."""
    # Check contract name
    name_lower = name.lower()
    if any(p.lower() in name_lower for p in ["proxy", "upgradeable", "upgrade"]):
        return True

    # Check inherited contracts
    for parent in inherited:
        if any(p.lower() in parent.lower() for p in PROXY_PATTERNS):
            return True

    # Check content for proxy patterns
    if content:
        for slot in EIP1967_SLOTS.values():
            if slot in content:
                return True
        if "delegatecall" in content and "fallback" in content:
            return True

    return False


def _delegatecall_to_variable(content: str, parameters: list) -> bool:
    """Check if delegatecall target comes from a variable/parameter."""
    # If delegatecall uses a parameter or state variable rather than
    # a hardcoded address, it's potentially dangerous
    param_names = []
    for p in parameters:
        if isinstance(p, dict):
            name = p.get("name", "")
            if name:
                param_names.append(name)
        elif isinstance(p, str):
            parts = p.strip().split()
            if len(parts) >= 2:
                param_names.append(parts[-1])

    lines = content.split("\n")
    for line in lines:
        if "delegatecall" not in line:
            continue
        # Check if any parameter appears in the delegatecall line
        for param in param_names:
            if param in line:
                return True
        # Check for non-constant address patterns
        # A hardcoded address would be 0x... directly in the call
        if "delegatecall" in line and "0x" not in line:
            return True
    return False


def _has_storage_gap(state_variables: list, content: str) -> bool:
    """Check if contract declares a storage gap."""
    for var in state_variables:
        var_name = var.get("name", "") if isinstance(var, dict) else str(var)
        if STORAGE_GAP_PATTERN in var_name:
            return True
    if content and STORAGE_GAP_PATTERN in content:
        return True
    return False


def _check_slot_collisions(state_variables: list) -> list[dict]:
    """Check for obvious storage slot collisions.

    In a real implementation, this would compute actual storage slots
    based on variable ordering and sizes. For now, it checks for
    obvious patterns like multiple variables claiming the same slot.
    """
    collisions = []
    slots_seen: dict[int, str] = {}

    for var in state_variables:
        if not isinstance(var, dict):
            continue
        slot = var.get("slot")
        name = var.get("name", "unknown")
        if slot is not None and slot in slots_seen:
            collisions.append({
                "description": (
                    f"Variable '{name}' and '{slots_seen[slot]}' "
                    f"both occupy storage slot {slot}."
                ),
                "slot": slot,
                "variables": [slots_seen[slot], name],
            })
        elif slot is not None:
            slots_seen[slot] = name

    return collisions


def _has_uninitialized_storage(content: str) -> bool:
    """Detect uninitialized local storage variable patterns."""
    if not content:
        return False
    import re

    # Pattern: Type storage varName; (without = initialization)
    # e.g., "Struct storage s;" without "= someMapping[key]"
    pattern = re.compile(
        r"\b\w+\s+storage\s+\w+\s*;",
        re.MULTILINE,
    )
    for match in pattern.finditer(content):
        matched = match.group()
        # Check it's not an assignment (= on same line before ;)
        if "=" not in matched:
            return True
    return False
