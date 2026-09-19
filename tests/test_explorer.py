from datetime import datetime, timezone
import json
import requests
import pytest
from collectors.explorer import ExplorerCollector, ExplorerHistory, ExplorerUnavailableError
from collectors.rpc import RpcCollector

TARGET = "0x1111111111111111111111111111111111111111"
COUNTERPARTY = "0x2222222222222222222222222222222222222222"
TOKEN = "0x3333333333333333333333333333333333333333"
SPENDER = "0x4444444444444444444444444444444444444444"


def etherscan_response(result, status="1"):
    return {"status": status, "message": "OK", "result": result}


class ExplorerSession:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, url, params, timeout):
        self.calls.append(params)
        class Response:
            def __init__(self, payload):
                self.payload = payload

            def raise_for_status(self):
                return None

            def json(self):
                return self.payload
        action = params["action"]
        return Response(self.responses[action])


def test_normal_transaction_and_erc20_transfer_are_normalized(tmp_path):
    session = ExplorerSession({
        "txlist": etherscan_response([{"from": TARGET, "to": COUNTERPARTY, "value": "1000000000000000000", "timeStamp": "1700000000", "blockNumber": "10", "hash": "0xnormal"}]),
        "tokentx": etherscan_response([{"from": COUNTERPARTY, "to": TARGET, "value": "1000000", "tokenDecimal": "6", "tokenSymbol": "USDC", "contractAddress": TOKEN, "timeStamp": "1700000001", "blockNumber": "11", "hash": "0xtoken"}]),
        "getLogs": etherscan_response([]),
    })
    history = ExplorerCollector("https://api.example", session=session, cache_path=str(tmp_path / "cache.json")).collect_history(TARGET)
    assert history.coverage == {"transactionHistory": 1.0, "tokenTransfers": 1.0, "approvals": 1.0}
    assert [call["chainid"] for call in session.calls] == ["1", "1", "1"]
    assert {edge["edge_type"] for edge in history.transactions} == {"transfer", "token_transfer"}
    token_edge = next(edge for edge in history.transactions if edge["edge_type"] == "token_transfer")
    assert token_edge["value"] == 1.0
    assert token_edge["metadata"]["tokenSymbol"] == "USDC"
    assert token_edge["metadata"]["transactionHash"] == "0xtoken"


def test_custom_chain_id_is_included_in_every_request(tmp_path):
    session = ExplorerSession({"txlist": etherscan_response([]), "tokentx": etherscan_response([]), "getLogs": etherscan_response([])})
    ExplorerCollector("https://api.example", chain_id="1", session=session, cache_path=str(tmp_path / "cache.json")).collect_history(TARGET)
    assert all(call["chainid"] == "1" for call in session.calls)


def test_unlimited_approval_is_normalized(tmp_path):
    allowance = 2**256 - 1
    session = ExplorerSession({
        "txlist": etherscan_response([]),
        "tokentx": etherscan_response([]),
        "getLogs": etherscan_response([{"address": TOKEN, "topics": [ExplorerCollector.approval_topic, "0x" + TARGET[2:].rjust(64, "0"), "0x" + SPENDER[2:].rjust(64, "0")], "data": hex(allowance), "timeStamp": "1700000000", "blockNumber": "10", "transactionHash": "0xapproval"}]),
    })
    history = ExplorerCollector("https://api.example", session=session, cache_path=str(tmp_path / "cache.json")).collect_history(TARGET)
    assert len(history.approvals) == 1
    approval = history.approvals[0]
    assert approval["edge_type"] == "approval"
    assert approval["metadata"]["allowance"] == str(allowance)
    assert approval["metadata"]["spender"] == SPENDER
    assert approval["metadata"]["token"] == TOKEN


def test_empty_history_is_not_an_error_but_reports_limitation(tmp_path):
    empty = {"txlist": etherscan_response("No transactions found", status="0"), "tokentx": etherscan_response("No transactions found", status="0"), "getLogs": etherscan_response([])}
    history = ExplorerCollector("https://api.example", session=ExplorerSession(empty), cache_path=str(tmp_path / "cache.json")).collect_history(TARGET)
    assert history.transactions == []
    assert any("no transaction history" in item for item in history.limitations)


def test_api_failure_reports_each_failed_source(tmp_path):
    class FailingSession:
        def get(self, *args, **kwargs):
            raise requests.ConnectionError("offline")
    history = ExplorerCollector("https://api.example", session=FailingSession(), cache_path=str(tmp_path / "cache.json")).collect_history(TARGET)
    assert len(history.limitations) >= 3
    assert history.coverage == {"transactionHistory": 0.0, "tokenTransfers": 0.0, "approvals": 0.0}


def test_invalid_response_is_reported(tmp_path):
    session = ExplorerSession({"txlist": {"status": "1", "result": {"not": "a-list"}}, "tokentx": etherscan_response([]), "getLogs": etherscan_response([])})
    history = ExplorerCollector("https://api.example", session=session, cache_path=str(tmp_path / "cache.json")).collect_history(TARGET)
    assert history.coverage["transactionHistory"] == 0.0
    assert any("invalid response" in item for item in history.limitations)


def test_file_cache_avoids_repeated_fetch(tmp_path):
    session = ExplorerSession({"txlist": etherscan_response([]), "tokentx": etherscan_response([]), "getLogs": etherscan_response([])})
    collector = ExplorerCollector("https://api.example", session=session, cache_path=str(tmp_path / "cache.json"))
    collector.normal_transactions(TARGET)
    collector.normal_transactions(TARGET)
    assert len(session.calls) == 1


def test_contract_identification_uses_eth_get_code(monkeypatch):
    collector = RpcCollector("https://rpc.example")
    monkeypatch.setattr(collector, "validate_connection", lambda: "0x1")
    monkeypatch.setattr(collector, "get_code", lambda address: "0x6000" if address == TOKEN else "0x")
    result = collector.identify_addresses([TOKEN, COUNTERPARTY])
    assert result == {TOKEN: "contract", COUNTERPARTY: "wallet"}


def test_zero_value_transfer_becomes_contract_interaction(tmp_path):
    session = ExplorerSession({
        "txlist": etherscan_response([{"from": TARGET, "to": COUNTERPARTY, "value": "0", "timeStamp": "1700000000", "hash": "0xzero"}]),
        "tokentx": etherscan_response([]),
        "getLogs": etherscan_response([]),
    })
    history = ExplorerCollector("https://api.example", session=session, cache_path=str(tmp_path / "cache.json")).collect_history(TARGET)
    assert history.transactions[0]["edge_type"] == "contract_interaction"
    assert history.transactions[0]["value"] == 0.0


def test_missing_timestamp_and_malformed_rows_are_skipped(tmp_path):
    session = ExplorerSession({
        "txlist": etherscan_response([
            {"from": TARGET, "to": COUNTERPARTY, "value": "1", "hash": "0xmissing-time"},
            {"from": "bad", "to": COUNTERPARTY, "value": "not-a-number", "timeStamp": "bad"},
        ]),
        "tokentx": etherscan_response([]),
        "getLogs": etherscan_response([]),
    })
    history = ExplorerCollector("https://api.example", session=session, cache_path=str(tmp_path / "cache.json")).collect_history(TARGET)
    assert history.transactions == []
    assert any("no transaction history" in item for item in history.limitations)


def test_extremely_large_values_remain_finite(tmp_path):
    session = ExplorerSession({
        "txlist": etherscan_response([{"from": TARGET, "to": COUNTERPARTY, "value": str(10**1000), "timeStamp": "1700000000", "hash": "0xhuge"}]),
        "tokentx": etherscan_response([]),
        "getLogs": etherscan_response([]),
    })
    history = ExplorerCollector("https://api.example", session=session, cache_path=str(tmp_path / "cache.json")).collect_history(TARGET)
    assert history.transactions[0]["value"] == 1e308
