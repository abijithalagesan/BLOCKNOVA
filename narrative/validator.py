from typing import Any, Dict


def validate_evidence(evidence: list[Dict[str, Any]]) -> None:
    required = {"path", "sourceNode", "targetNode", "hops", "contribution", "reason"}
    for item in evidence:
        missing = required - item.keys()
        if missing:
            raise ValueError(f"evidence is missing fields: {sorted(missing)}")
        if not 0.0 <= item["contribution"] <= 1.0:
            raise ValueError("evidence contribution must be bounded")
