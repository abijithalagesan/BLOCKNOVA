import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from analyzer import load_live_data
from collectors.goplus import GoPlusCollector, GoPlusUnavailableError
from graph.builder import build_graph
from signals.aggregation import intrinsic_label
from signals.direct_flags import detect_direct_flags


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a live GoPlus security result")
    parser.add_argument("--address", required=True, help="public Ethereum address")
    args = parser.parse_args()
    load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")
    api_url = os.getenv("GOPLUS_API_URL")
    if not api_url:
        print("GO_PLUS_NOT_CONFIGURED")
        print("Set GOPLUS_API_URL in .env; no provider result was fabricated.")
        return 2
    try:
        provider_signal = GoPlusCollector(api_url, api_key=os.getenv("GOPLUS_API_KEY")).get_signal(args.address)
    except (GoPlusUnavailableError, ValueError) as error:
        print(f"GO_PLUS_UNAVAILABLE: {error}")
        return 2
    if provider_signal is None:
        print(json.dumps({"address": args.address.lower(), "providerResult": "no security flags returned", "signals": [], "intrinsicRisk": "unknown", "evidence": {}}, indent=2))
        return 0
    signals = detect_direct_flags(args.address, provider_signal)
    graph_data, limitations = load_live_data(args.address.lower())
    graph = build_graph(graph_data)
    node = graph.nodes[args.address.lower()]
    print(json.dumps({
        "address": args.address.lower(),
        "providerResult": {"source": provider_signal.source, "classification": provider_signal.risk_label, "flags": provider_signal.flags, "observedAt": provider_signal.observed_at.isoformat() if provider_signal.observed_at else None},
        "signals": [signal.model_dump(mode="json") for signal in signals],
        "intrinsicRisk": node.get("intrinsic_risk_label", intrinsic_label(signals)),
        "evidence": [signal.evidence for signal in signals],
        "limitations": limitations,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
