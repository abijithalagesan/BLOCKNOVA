from analyzer import analyze_address


def test_clean_sample_has_no_supported_malicious_path():
    result = analyze_address("0x4444444444444444444444444444444444444444")
    assert result["riskScore"] < 0.25
    assert result["topEvidence"] == []
    assert "No supported risky exposure" in result["explanation"]
    assert result["riskVector"]["dataQuality"] < 1.0
