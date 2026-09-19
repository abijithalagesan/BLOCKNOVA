from fastapi.testclient import TestClient
from app import app


def test_health_and_analysis_contract():
    client = TestClient(app)
    assert client.get("/health").json()["status"] == "ok"
    response = client.post("/analyze", json={"address": "0x1111111111111111111111111111111111111111", "chain": "ethereum"})
    assert response.status_code == 200
    body = response.json()
    assert {"riskScore", "riskLevel", "riskVector", "topEvidence", "explanation", "limitations"} <= body.keys()
