"""Detect user-controlled input flowing to sensitive operations.

Identifies function parameters and msg.sender/msg.value/calldata flowing
into sensitive sinks like delegatecall targets, selfdestruct arguments,
storage slot calculations, and ETH transfer recipients.
"""

# User-controlled input sources
TAINT_SOURCES = [
    "msg.sender",
    "msg.value",
    "msg.data",
    "tx.origin",
    "block.timestamp",
    "block.number",
    "calldata",
]

# Sensitive sinks where tainted data is dangerous
SENSITIVE_SINKS = {
    "delegatecall": {
        "severity": "critical",
        "description": "User input flows to delegatecall target",
    },
    "selfdestruct": {
        "severity": "critical",
        "description": "User input flows to selfdestruct beneficiary",
    },
    "sstore": {
        "severity": "high",
        "description": "User input flows to arbitrary storage write",
    },
    "sload": {
        "severity": "medium",
        "description": "User input flows to arbitrary storage read",
    },
    "call{value:": {
        "severity": "high",
        "description": "User input controls ETH transfer destination or amount",
    },
    ".transfer(": {
        "severity": "high",
        "description": "User input controls transfer recipient",
    },
    ".send(": {
        "severity": "high",
        "description": "User input controls send recipient",
    },
    "create(": {
        "severity": "high",
        "description": "User input flows to contract creation",
    },
    "create2(": {
        "severity": "high",
        "description": "User input flows to create2 salt or code",
    },
}


def detect(contract_data: dict) -> list[dict]:
    """Detect tainted input flowing to sensitive operations.

    Args:
        contract_data: Parsed Slither JSON contract information containing
            'functions' list with 'name', 'parameters', 'content',
            'taint_flows', and 'visibility' fields.

    Returns:
        List of finding dicts with keys: type, severity, confidence,
        description, function, contract, details.
    """
    findings = []
    functions = contract_data.get("functions", [])
    contract_name = contract_data.get("name", "Unknown")

    for func in functions:
        func_name = func.get("name", "")
        parameters = func.get("parameters", [])
        content = func.get("content", "")
        visibility = func.get("visibility", "public")
        taint_flows = func.get("taint_flows", [])

        # Only analyze externally callable functions
        if visibility not in ("public", "external"):
            continue

        # Path 1: Explicit taint flow data from Slither
        for flow in taint_flows:
            source = flow.get("source", "")
            sink = flow.get("sink", "")
            sink_info = _match_sink(sink)
            if sink_info:
                findings.append({
                    "type": "tainted-input-to-sink",
                    "severity": sink_info["severity"],
                    "confidence": "high",
                    "description": (
                        f"In {func_name}(): {sink_info['description']}. "
                        f"Source: {source}, Sink: {sink}."
                    ),
                    "function": func_name,
                    "contract": contract_name,
                    "details": {
                        "source": source,
                        "sink": sink,
                        "flow": flow,
                    },
                })

        # Path 2: Heuristic source analysis
        if content and not taint_flows:
            param_names = _extract_param_names(parameters)
            all_sources = param_names + [
                s for s in TAINT_SOURCES if s in content
            ]

            if not all_sources:
                continue

            for sink_pattern, sink_info in SENSITIVE_SINKS.items():
                if sink_pattern not in content:
                    continue

                # Check if any source variable appears near the sink
                tainted_sources = _find_tainted_flow(
                    content, all_sources, sink_pattern
                )
                if tainted_sources:
                    findings.append({
                        "type": "tainted-input-to-sink",
                        "severity": sink_info["severity"],
                        "confidence": "medium",
                        "description": (
                            f"In {func_name}(): {sink_info['description']}. "
                            f"Possible tainted sources: "
                            f"{', '.join(tainted_sources)}."
                        ),
                        "function": func_name,
                        "contract": contract_name,
                        "details": {
                            "sources": tainted_sources,
                            "sink": sink_pattern,
                            "heuristic": True,
                        },
                    })

    return findings


def _match_sink(sink_name: str) -> dict | None:
    """Match a sink name against known sensitive sinks."""
    for pattern, info in SENSITIVE_SINKS.items():
        if pattern in sink_name:
            return info
    return None


def _extract_param_names(parameters: list) -> list[str]:
    """Extract parameter names from function parameter list."""
    names = []
    for param in parameters:
        if isinstance(param, dict):
            name = param.get("name", "")
            if name:
                names.append(name)
        elif isinstance(param, str):
            # Simple "type name" format
            parts = param.strip().split()
            if len(parts) >= 2:
                names.append(parts[-1])
    return names


def _find_tainted_flow(
    content: str, sources: list[str], sink_pattern: str
) -> list[str]:
    """Heuristic: find source variables that appear near a sink pattern.

    This is a simplified approach - real taint analysis requires data flow
    tracking. Here we check if source variables appear in the same
    statement or nearby lines as the sink.
    """
    tainted = []
    lines = content.split("\n")

    for i, line in enumerate(lines):
        if sink_pattern not in line:
            continue

        # Check current line and surrounding lines (context window of 3)
        context_start = max(0, i - 2)
        context_end = min(len(lines), i + 3)
        context = "\n".join(lines[context_start:context_end])

        for source in sources:
            if source in context:
                tainted.append(source)

    return list(set(tainted))
