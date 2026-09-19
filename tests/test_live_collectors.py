from datetime import datetime, timezone
import requests
import pytest
from collectors.goplus import GoPlusCollector, GoPlusUnavailableError, SecuritySignal
from collectors.rpc import RpcCollector, RpcUnavailableError
from graph.builder import build_collected_graph

TARGET = "0x1111111111111111111111111111111111111111"
COUNTERPARTY = "0x2222222222222222222222222222222222222222"


class FakeRpcSession:
    def post(self, *args, **kwargs):
        return self

    def raise_for_status(self):
        return None

    def json(self):
        return {"result": "0x1"}


class FailingSession:
    def post(self, *args, **kwargs):
        raise requests.ConnectionError("offline")


class FailingGetSession:
    def get(self, *args, **kwargs):
        raise requests.ConnectionError("offline")


def test_rpc_unavailable_is_explicit():
    collector = RpcCollector("https://rpc.invalid", session=FailingSession())
    with pytest.raises(RpcUnavailableError):
        collector.validate_connection()


def test_goplus_unavailable_is_explicit():
    collector = GoPlusCollector("https://goplus.invalid", session=FailingGetSession())
    with pytest.raises(GoPlusUnavailableError):
        collector.get_signal(TARGET)


def test_rpc_response_is_converted_to_transaction_edge(monkeypatch):
    collector = RpcCollector("https://rpc.example", lookback_blocks=1, session=FakeRpcSession())
    responses = {
        "eth_chainId": "0x1",
        "eth_blockNumber": "0x10",
        "eth_getBlockByNumber": {"timestamp": "0x65b2a000", "transactions": [{"from": TARGET, "to": COUNTERPARTY, "value": "0xde0b6b3a7640000", "hash": "0xabc"}]},
    }
    monkeypatch.setattr(collector, "_request", lambda method, params: responses[method])
    transactions = collector.collect_transactions(TARGET)
    assert transactions[0]["edge_type"] == "transfer"
    assert transactions[0]["value"] == 1.0
    graph_data = build_collected_graph(TARGET, transactions, [], observed_through=datetime.now(timezone.utc), coverage=0.7)
    assert graph_data.edges[0].source == TARGET
    assert graph_data.edges[0].target == COUNTERPARTY
    assert graph_data.edges[0].evidence_source == "ethereum_rpc"


def test_goplus_flag_is_preserved_as_security_signal():
    class Session:
        def get(self, *args, **kwargs):
            return self

        def raise_for_status(self):
            return None

        def json(self):
            return {"result": {"is_phishing": "1", "source": "provider"}}

    signal = GoPlusCollector("https://goplus.example", session=Session()).get_signal(TARGET)
    assert signal == SecuritySignal(TARGET, "confirmed_malicious", "goplus", {"is_phishing": "1", "source": "provider"})


def test_goplus_clean_response_returns_no_risk_signal():
    class Session:
        def get(self, *args, **kwargs):
            return self

        def raise_for_status(self):
            return None

        def json(self):
            return {"code": 1, "message": "OK", "result": {"is_phishing": "0", "is_blacklisted": "0"}}

    assert GoPlusCollector("https://goplus.example", session=Session()).get_signal(TARGET) is None


def test_goplus_malformed_response_is_rejected():
    class Session:
        def get(self, *args, **kwargs):
            return self

        def raise_for_status(self):
            return None

        def json(self):
            return {"code": 1, "message": "OK", "result": ["invalid"]}

    with pytest.raises(GoPlusUnavailableError):
        GoPlusCollector("https://goplus.example", session=Session()).get_signal(TARGET)


def test_goplus_timestamp_is_preserved():
    class Session:
        def get(self, *args, **kwargs):
            return self

        def raise_for_status(self):
            return None

        def json(self):
            return {"result": {"is_phishing": "1", "updated_at": "2024-01-01T00:00:00Z"}}

    signal = GoPlusCollector("https://goplus.example", session=Session()).get_signal(TARGET)
    assert signal.observed_at.isoformat() == "2024-01-01T00:00:00+00:00"
