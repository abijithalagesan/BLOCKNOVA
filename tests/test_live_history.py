from analyzer import analyze_address


def test_live_mode_without_explorer_has_explicit_history_limitation(monkeypatch):
    for name in ("ETHERSCAN_API_URL", "ETHERSCAN_API_KEY", "ETHEREUM_RPC_URL", "GOPLUS_API_URL"):
        monkeypatch.delenv(name, raising=False)
    result = analyze_address("0x9999999999999999999999999999999999999999", live=True)
    assert result["coverage"]["transactionHistory"] == 0.0
    assert result["dataQuality"] == 0.0
    assert any("ETHERSCAN_API_URL" in item for item in result["limitations"])
