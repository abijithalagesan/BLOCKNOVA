import networkx as nx
from datetime import datetime, timezone
from typing import Any, Iterable, List, Optional
from graph.models import GraphData
from signals.aggregation import aggregate_signals, intrinsic_label
from signals.models import RiskSignal


def build_graph(data: GraphData) -> nx.MultiDiGraph:
    graph = nx.MultiDiGraph()
    signals_by_address: dict[str, list[RiskSignal]] = {}
    for signal in aggregate_signals(data.signals):
        signals_by_address.setdefault(signal.address, []).append(signal)
    for node in data.nodes:
        attributes = node.model_dump()
        node_signals = signals_by_address.get(node.address, [])
        if node_signals:
            attributes["intrinsic_risk_label"] = intrinsic_label(node_signals)
            attributes["risk_source"] = ",".join(sorted({signal.source for signal in node_signals}))
            attributes["risk_signals"] = [signal.model_dump(mode="json") for signal in node_signals]
        graph.add_node(node.address, **attributes)
    for edge in data.edges:
        graph.add_edge(edge.source, edge.target, **edge.model_dump())
    return graph


def build_collected_graph(address: str, transactions: Iterable[dict[str, Any]], signals: Iterable[RiskSignal], observed_through: Optional[datetime] = None, coverage: float = 0.0, coverage_details: Optional[dict[str, float]] = None, node_kinds: Optional[dict[str, str]] = None) -> GraphData:
    normalized = address.strip().lower()
    aggregated_signals = aggregate_signals(signals)
    signal_by_address: dict[str, list[RiskSignal]] = {}
    for signal in aggregated_signals:
        signal_by_address.setdefault(signal.address, []).append(signal)
    nodes = [{"address": normalized, "kind": "wallet", "intrinsic_risk_label": "unknown", "risk_source": None, "metadata": {}}]
    edges: List[dict[str, Any]] = []
    node_addresses = {normalized}
    for transaction in transactions:
        source = transaction["source"].lower()
        target = transaction["target"].lower()
        node_addresses.update({source, target})
        edges.append(transaction)
    for node_address in sorted(node_addresses - {normalized}):
        default_kind = "contract" if any(edge["target"].lower() == node_address and edge["edge_type"] == "contract_interaction" for edge in edges) else "wallet"
        nodes.append({"address": node_address, "kind": (node_kinds or {}).get(node_address, default_kind), "intrinsic_risk_label": "unknown", "risk_source": None, "metadata": {}})
    if node_kinds:
        nodes[0]["kind"] = node_kinds.get(normalized, nodes[0]["kind"])
    return GraphData(nodes=nodes, edges=edges, observed_through=observed_through or datetime.now(timezone.utc), coverage=max(0.0, min(1.0, coverage)), coverage_details=coverage_details or {}, signals=aggregated_signals)
