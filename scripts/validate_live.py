import argparse
from pathlib import Path
import sys
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyzer import analyze_address, load_live_data
from graph.builder import build_graph


def check(name: str, condition: bool, detail: str = "") -> bool:
    status = "PASS" if condition else "FAIL"
    suffix = f": {detail}" if detail else ""
    print(f"{status} {name}{suffix}")
    return condition


def validate(address: str) -> int:
    failures = 0
    try:
        result = analyze_address(address, live=True, debug=True)
    except Exception as error:
        print(f"FAIL live analysis: {error}")
        return 1
    data, collection_limitations = load_live_data(address.lower())
    graph = build_graph(data)
    failures += not check("risk score bounded", 0.0 <= result["riskScore"] <= 1.0)
    failures += not check("risk vector bounded", all(0.0 <= value <= 1.0 for value in result["riskVector"].values()))
    failures += not check("data quality bounded", 0.0 <= result["dataQuality"] <= 1.0)
    for index, signal in enumerate(result.get("signals", [])):
        valid = bool(signal.get("address")) and bool(signal.get("type") or signal.get("signal_type")) and bool(signal.get("source")) and bool(signal.get("evidence")) and 0.0 <= signal.get("severity", -1.0) <= 1.0
        failures += not check(f"signal {index} schema", valid)
    for index, evidence in enumerate(result.get("topEvidence", [])):
        path = evidence.get("path", [])
        valid_edges = all(graph.has_edge(source, target) for source, target in zip(path, path[1:]))
        valid = len(path) >= 2 and valid_edges and evidence.get("hops") == len(path) - 1 and 0.0 <= evidence.get("exposure", -1.0) <= 1.0 and 0.0 <= evidence.get("recency", -1.0) <= 1.0 and 0.0 <= evidence.get("contribution", -1.0) <= 1.0 and bool(evidence.get("edgeTypes")) and bool(evidence.get("intrinsicRiskSource"))
        failures += not check(f"evidence path {index} valid", valid)
    explanation = result.get("explanation", "")
    if result.get("topEvidence"):
        lead = result["topEvidence"][0]
        explanation_valid = str(lead["sourceNode"]) in explanation and str(lead["targetNode"]) in explanation and str(lead["hops"]) in explanation
    else:
        explanation_valid = "No supported risky exposure" in explanation
    failures += not check("explanation references available evidence", explanation_valid)
    failures += not check("debug counters present", all(key in result.get("debug", {}) for key in ("transactionsCollected", "tokenTransfersCollected", "approvalsCollected", "contractsDiscovered", "securityFlagsReceived", "signalsGenerated", "graphNodeCount", "graphEdgeCount", "pathsFound", "finalDataQuality")))
    if collection_limitations:
        print("LIMITATIONS")
        for limitation in collection_limitations:
            print(f"- {limitation}")
    print(f"RESULT {'PASS' if failures == 0 else 'FAIL'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate a live BlockNova analysis")
    parser.add_argument("address")
    args = parser.parse_args()
    sys.exit(validate(args.address))