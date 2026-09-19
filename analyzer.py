import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict
from dotenv import load_dotenv
from collectors.explorer import ExplorerCollector, ExplorerUnavailableError
from collectors.goplus import GoPlusCollector, GoPlusUnavailableError
from collectors.rpc import AlchemyTransferError, RpcCollector, RpcUnavailableError
from graph.builder import build_collected_graph, build_graph
from graph.models import GraphData
from graph.traversal import find_paths
from narrative.renderer import render
from config.constants import DEFAULT_CONFIG
from risk.scoring import score_paths
from signals.anomaly import detect_behavioral_anomalies
from signals.allowance import detect_allowance_risk
from signals.direct_flags import detect_direct_flags
from proof.merkle import build_merkle_tree, get_root
from signals.aggregation import aggregate_signals

DATA_PATH = Path(__file__).parent / "data" / "sample_graph.json"
load_dotenv()


def load_sample_data() -> GraphData:
    return GraphData.model_validate_json(DATA_PATH.read_text())


def risk_level(score: float) -> str:
    thresholds = DEFAULT_CONFIG.risk_level_thresholds
    if score >= thresholds["CRITICAL"]:
        return "CRITICAL"
    if score >= thresholds["HIGH"]:
        return "HIGH"
    if score >= thresholds["ELEVATED"]:
        return "ELEVATED"
    return "LOW"


def _empty_live_data(address: str) -> GraphData:
    return build_collected_graph(address, [], [], observed_through=datetime.now(timezone.utc), coverage=0.0)


def _merge_edges(existing: list[dict[str, Any]], additions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for edge in existing + additions:
        metadata = edge.get("metadata") or {}
        identity = str(metadata.get("transactionHash") or metadata.get("txHash") or f"{edge.get('source')}:{edge.get('target')}:{edge.get('timestamp')}:{edge.get('edge_type')}")
        current = merged.get(identity)
        if current is None or edge.get("evidence_source") == "alchemy_seed_enrichment":
            merged[identity] = edge
    return list(merged.values())


def load_live_data(address: str) -> tuple[GraphData, list[str]]:
    limitations: list[str] = []
    transactions: list[dict[str, Any]] = []
    approvals: list[dict[str, Any]] = []
    signals = []
    coverage_details = {"transactionHistory": 0.0, "tokenTransfers": 0.0, "approvals": 0.0, "contractIdentification": 0.0, "securitySignals": 0.0}
    node_kinds: dict[str, str] = {}
    history = None
    alchemy_success = False
    rpc_url = os.getenv("ETHEREUM_RPC_URL")
    if rpc_url:
        try:
            rpc_collector = RpcCollector(rpc_url)
            transactions, transfer_limitations = rpc_collector.collect_alchemy_transfers(address, max_pages=int(os.getenv("ALCHEMY_MAX_PAGES", "10")), page_size=int(os.getenv("ALCHEMY_PAGE_SIZE", "100")))
            approvals = rpc_collector.collect_approval_events(address, lookback_blocks=int(os.getenv("RPC_APPROVAL_LOOKBACK_BLOCKS", "100")))
            limitations.extend(transfer_limitations)
            coverage_details["transactionHistory"] = 1.0
            coverage_details["tokenTransfers"] = 1.0
            coverage_details["approvals"] = 1.0
            if rpc_collector.approval_history_limited:
                coverage_details["approvals"] = 0.5
                limitations.append("Approval history was bounded to the configured recent RPC block window.")
            alchemy_success = True
            signals.extend(detect_behavioral_anomalies(address, transactions))
            for approval in approvals:
                approval_data = dict(approval.get("metadata", {}))
                approval_data.update({"allowance": approval_data.get("allowance", approval.get("value", 0)), "source": approval.get("evidence_source", "alchemy_rpc")})
                signals.extend(detect_allowance_risk(address, approval_data, observed_at=approval.get("timestamp")))
        except (AlchemyTransferError, RpcUnavailableError, ValueError) as error:
            limitations.append(f"Alchemy transfer collection unavailable: {error}")
            try:
                approvals = RpcCollector(rpc_url).collect_approval_events(address, lookback_blocks=int(os.getenv("RPC_APPROVAL_LOOKBACK_BLOCKS", "100")))
                coverage_details["approvals"] = 0.5
                limitations.append("Approval history was collected separately after transfer collection failed.")
            except (RpcUnavailableError, ValueError) as approval_error:
                limitations.append(f"Alchemy approval collection unavailable: {approval_error}")
    explorer_url = os.getenv("ETHERSCAN_API_URL")
    if explorer_url and not alchemy_success:
        try:
            history = ExplorerCollector(explorer_url, api_key=os.getenv("ETHERSCAN_API_KEY"), chain_id=os.getenv("ETHERSCAN_CHAIN_ID", "1"), cache_path=os.getenv("BLOCKNOVA_CACHE_PATH", ".blocknova_cache.json")).collect_history(address)
            transactions = history.transactions
            approvals = history.approvals
            coverage_details.update(history.coverage)
            limitations.extend(history.limitations)
            signals.extend(detect_behavioral_anomalies(address, transactions))
            for approval in approvals:
                approval_data = dict(approval.get("metadata", {}))
                approval_data.update({"allowance": approval_data.get("allowance", approval.get("value", 0)), "source": approval.get("evidence_source", "etherscan")})
                signals.extend(detect_allowance_risk(address, approval_data, observed_at=approval.get("timestamp")))
        except (ExplorerUnavailableError, ValueError) as error:
            limitations.append(f"explorer history unavailable: {error}")
    else:
        limitations.append("LIVE DATA NOT CONFIGURED: ETHERSCAN_API_URL is not configured; full wallet history was not collected.")
    if rpc_url:
        try:
            rpc_collector = RpcCollector(rpc_url)
            addresses = {address}
            for record in transactions + approvals:
                addresses.update({record["source"], record["target"]})
            node_kinds = rpc_collector.identify_addresses(list(addresses))
            coverage_details["contractIdentification"] = 1.0
        except (RpcUnavailableError, ValueError) as error:
            limitations.append(f"Ethereum contract identification unavailable: {error}")
    else:
        limitations.append("LIVE DATA NOT CONFIGURED: ETHEREUM_RPC_URL is not configured; contract identification was not collected.")
    goplus_url = os.getenv("GOPLUS_API_URL")
    if goplus_url:
        try:
            goplus = GoPlusCollector(goplus_url, api_key=os.getenv("GOPLUS_API_KEY"))
            max_addresses = max(1, int(os.getenv("GOPLUS_MAX_ADDRESSES", "25")))
            related_addresses = sorted({record["source"] for record in transactions} | {record["target"] for record in transactions} | {record["source"] for record in approvals} | {record["target"] for record in approvals})
            addresses_to_check = [address] + [candidate for candidate in related_addresses if candidate != address][: max_addresses - 1]
            successful_checks = 0
            for candidate in addresses_to_check:
                try:
                    signal = goplus.get_signal(candidate)
                    successful_checks += 1
                    if signal:
                        signals.extend(detect_direct_flags(candidate, signal))
                except GoPlusUnavailableError as error:
                    limitations.append(f"GoPlus security data unavailable for {candidate}: {error}")
            coverage_details["securitySignals"] = successful_checks / len(addresses_to_check) if addresses_to_check else 0.0
            if len(addresses_to_check) < len({address, *related_addresses}):
                coverage_details["securitySignals"] *= 0.5
                limitations.append(f"GoPlus security checks were bounded to {max_addresses} addresses.")
            seed_values = [value.strip().lower() for value in os.getenv("GOPLUS_SEED_ADDRESSES", "").split(",") if value.strip()]
            for seed in seed_values:
                seed_signal = goplus.get_signal(seed)
                if seed_signal is None or seed_signal.risk_label not in {"confirmed_malicious", "high_risk", "suspicious"}:
                    continue
                signals.extend(detect_direct_flags(seed, seed_signal))
                if rpc_url:
                    try:
                        seed_edges, seed_limitations = RpcCollector(rpc_url).collect_seed_relationships(seed, address, max_pages=int(os.getenv("ALCHEMY_MAX_PAGES", "10")), page_size=int(os.getenv("ALCHEMY_PAGE_SIZE", "100")))
                        transactions = _merge_edges(transactions, seed_edges)
                        limitations.extend(seed_limitations)
                        if seed_edges:
                            limitations.append(f"Seed enrichment found {len(seed_edges)} target-to-seed relationship(s) for {seed}.")
                    except (AlchemyTransferError, RpcUnavailableError, ValueError) as error:
                        limitations.append(f"Seed relationship enrichment unavailable for {seed}: {error}")
        except (GoPlusUnavailableError, ValueError) as error:
            limitations.append(f"GoPlus security data unavailable: {error}")
    else:
        limitations.append("LIVE DATA NOT CONFIGURED: GOPLUS_API_URL is not configured; external security signals were not collected.")
    coverage = sum(coverage_details.values()) / len(coverage_details)
    return build_collected_graph(address, transactions + approvals, signals, observed_through=datetime.now(timezone.utc), coverage=coverage, coverage_details=coverage_details, node_kinds=node_kinds), limitations


def analyze_address(address: str, live: bool = False, debug: bool = False) -> Dict[str, Any]:
    normalized = address.strip().lower()
    if not normalized.startswith("0x") or len(normalized) != 42:
        raise ValueError("address must be a 42-character EVM address")
    int(normalized[2:], 16)
    collection_limitations: list[str] = []
    if live:
        data, collection_limitations = load_live_data(normalized)
    else:
        data = load_sample_data()
    graph = build_graph(data)
    address_found = normalized in graph
    paths = find_paths(graph, normalized, max_hops=3) if address_found else []
    signal_addresses = {normalized}
    for path in paths:
        signal_addresses.update(path["nodes"])
    target_signals = [signal for signal in data.signals if signal.address == normalized]
    result = score_paths(paths, data.observed_through, data.coverage, requested_address_found=address_found, signals=target_signals)
    relevant_addresses = {normalized}
    for evidence in result["evidence"]:
        relevant_addresses.update(evidence["path"])
    output_signals = []
    signal_evidence = []
    for signal in data.signals:
        if signal.address not in relevant_addresses:
            continue
        serialized = signal.model_dump(mode="json")
        serialized["type"] = signal.signal_type
        output_signals.append(serialized)
        provider_evidence = json.loads(json.dumps(signal.evidence, default=str))
        signal_evidence.append({"address": signal.address, "signal_type": signal.signal_type, "severity": signal.severity, "source": signal.source, "providerEvidence": provider_evidence, "observedAt": signal.observed_at.isoformat() if signal.observed_at else None, "confidence": signal.confidence})
    result["signalEvidence"] = signal_evidence
    narrative = render(result)
    canonical_evidence = signal_evidence + result["evidence"]
    evidence_root = get_root(build_merkle_tree(canonical_evidence))
    expires_at = data.observed_through + timedelta(days=DEFAULT_CONFIG.attestation_validity_days)
    limitations = collection_limitations + narrative.limitations
    response = {"address": normalized, "riskScore": result["riskScore"], "riskLevel": risk_level(result["riskScore"]), "riskVector": result["riskVector"], "dataQuality": result["riskVector"]["dataQuality"], "coverage": data.coverage_details, "signals": output_signals, "signalEvidence": signal_evidence, "evidenceCount": len(canonical_evidence), "topEvidence": result["evidence"][:5], "explanation": narrative.explanation, "limitations": limitations, "evidenceRoot": evidence_root, "evidenceVersion": DEFAULT_CONFIG.evidence_version, "observedThrough": data.observed_through.isoformat(), "expiresAt": expires_at.isoformat(), "attestation": {"uid": "", "status": "NOT_ISSUED"}}
    if debug:
        response["debug"] = {
            "transactionsCollected": sum(1 for edge in data.edges if edge.edge_type.value in {"transfer", "contract_interaction"}),
            "tokenTransfersCollected": sum(1 for edge in data.edges if edge.edge_type.value == "token_transfer"),
            "approvalsCollected": sum(1 for edge in data.edges if edge.edge_type.value == "approval"),
            "contractsDiscovered": sum(1 for node in data.nodes if node.kind == "contract"),
            "securityFlagsReceived": sum(1 for signal in data.signals if signal.signal_type in {"confirmed_malicious", "high_risk", "suspicious"}),
            "signalsGenerated": len(data.signals),
            "graphNodeCount": graph.number_of_nodes(),
            "graphEdgeCount": graph.number_of_edges(),
            "pathsFound": len(paths),
            "finalDataQuality": data.coverage,
        }
    return response


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Analyze an Ethereum address with BlockNova")
    parser.add_argument("address")
    parser.add_argument("--live", action="store_true", help="use configured Ethereum and GoPlus collectors")
    parser.add_argument("--debug", action="store_true", help="include collection and graph pipeline counters")
    args = parser.parse_args()
    print(json.dumps(analyze_address(args.address, live=args.live, debug=args.debug), indent=2))
