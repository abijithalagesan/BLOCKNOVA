from analyzer import load_sample_data
from graph.builder import build_graph
from graph.traversal import find_paths


def test_bounded_path_reaches_malicious_seed():
    data = load_sample_data()
    graph = build_graph(data)
    paths = find_paths(graph, "0x1111111111111111111111111111111111111111", 3)
    assert len(paths) == 1
    assert paths[0]["nodes"][-1] == "0x3333333333333333333333333333333333333333"
    assert len(paths[0]["edges"]) == 2


def test_traversal_respects_hop_bound():
    data = load_sample_data()
    graph = build_graph(data)
    assert find_paths(graph, "0x1111111111111111111111111111111111111111", 1) == []
