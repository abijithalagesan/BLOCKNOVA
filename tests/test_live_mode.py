from analyzer import analyze_address


def test_live_mode_without_configuration_reports_partial_data(monkeypatch):
    monkeypatch.delenv("ETHEREUM_RPC_URL", raising=False)
    monkeypatch.delenv("GOPLUS_API_URL", raising=False)
    result = analyze_address("0x9999999999999999999999999999999999999999", live=True)
    assert result["riskScore"] == 0.0
    assert result["dataQuality"] == 0.0
    assert any("ETHEREUM_RPC_URL" in limitation for limitation in result["limitations"])
    assert any("GOPLUS_API_URL" in limitation for limitation in result["limitations"])


def test_invalid_live_address_is_rejected():
    try:
        analyze_address("not-an-address", live=True)
    except ValueError as error:
        assert "42-character" in str(error)
    else:
        raise AssertionError("invalid address was accepted")
