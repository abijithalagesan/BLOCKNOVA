from analyzer import analyze_address


def test_malicious_sample_has_explainable_evidence():
    result = analyze_address("0x1111111111111111111111111111111111111111")
    assert result["riskScore"] > 0.0
    assert result["topEvidence"]
    assert result["topEvidence"][0]["path"] == [
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333",
    ]
    assert "2-hop path" in result["explanation"]
