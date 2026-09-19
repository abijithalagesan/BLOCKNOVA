from typing import Any, Dict, List
import networkx as nx


def find_paths(graph: nx.MultiDiGraph, target: str, max_hops: int) -> List[Dict[str, Any]]:
    paths: List[Dict[str, Any]] = []
    for node_path in nx.single_source_shortest_path(graph, target, cutoff=max_hops).values():
        if len(node_path) < 2:
            continue
        terminal = graph.nodes[node_path[-1]]
        if terminal.get("intrinsic_risk_label", "unknown") in {"confirmed_malicious", "high_risk", "suspicious"}:
            edges = []
            for source, destination in zip(node_path, node_path[1:]):
                edge_data = graph.get_edge_data(source, destination)
                edge = min(edge_data.values(), key=lambda item: item.get("value", 0.0))
                edges.append(edge)
            paths.append({"nodes": node_path, "edges": edges, "source": node_path[-1], "terminal_label": terminal.get("intrinsic_risk_label", "unknown")})
    return paths
