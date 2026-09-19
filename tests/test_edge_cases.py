import pytest
from fastapi.testclient import TestClient
from app import app
from analyzer import analyze_address


def test_unknown_address_is_not_called_safe():
    result = analyze_address("0x9999999999999999999999999999999999999999")
    assert result["riskScore"] == 0.0
    assert result["riskVector"]["dataQuality"] <= 0.5
    assert result["limitations"]


def test_api_rejects_invalid_address():
    client = TestClient(app)
    response = client.post("/analyze", json={"address": "not-an-address"})
    assert response.status_code == 422


def test_invalid_direct_analysis_address_raises():
    with pytest.raises(Exception):
        analyze_address("invalid")
