from analyzer import analyze_address


def test_debug_output_contains_pipeline_counters():
    result = analyze_address("0x1111111111111111111111111111111111111111", debug=True)
    assert result["debug"]["graphNodeCount"] >= 1
    assert result["debug"]["graphEdgeCount"] >= 1
    assert result["debug"]["pathsFound"] == len(result["topEvidence"])


def test_unconfigured_live_mode_is_explicit(monkeypatch):
    for name in ("ETHERSCAN_API_URL", "ETHEREUM_RPC_URL", "GOPLUS_API_URL"):
        monkeypatch.delenv(name, raising=False)
    result = analyze_address("0x9999999999999999999999999999999999999999", live=True)
    assert any("LIVE DATA NOT CONFIGURED" in limitation for limitation in result["limitations"])
    assert result["riskScore"] == 0.0