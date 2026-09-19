from datetime import datetime, timezone
import pytest
from collectors.rpc import AlchemyTransferError, RpcCollector, RpcUnavailableError

TARGET = "0x1111111111111111111111111111111111111111"
OTHER = "0x2222222222222222222222222222222222222222"
TOKEN = "0x3333333333333333333333333333333333333333"
SPENDER = "0x4444444444444444444444444444444444444444"


def transfer(source, target, category="external", value=1.0, unique_id=None):
    return {
        "from": source,
        "to": target,
        "category": category,
        "value": value,
        "asset": "ETH" if category != "erc20" else "USDC",
        "hash": "0xhash",
        "uniqueId": unique_id,
        "blockNum": "0x10",
        "metadata": {"blockTimestamp": "2024-01-01T00:00:00Z"},
        "rawContract": {"address": TOKEN if category == "erc20" else None},
    }


def make_collector(monkeypatch, responses):
    collector = RpcCollector("https://alchemy.example")
    monkeypatch.setattr(collector, "validate_connection", lambda: "0x1")
    monkeypatch.setattr(collector, "_request", lambda method, params: responses[method].pop(0) if isinstance(responses[method], list) else responses[method])
    return collector


def test_eth_transfer_from_address_is_normalized(monkeypatch):
    collector = make_collector(monkeypatch, {"alchemy_getAssetTransfers": [{"transfers": [transfer(TARGET, OTHER)]}, {"transfers": []}], "eth_getBlockByNumber": {}})
    records, limitations = collector.collect_alchemy_transfers(TARGET)
    assert records[0]["edge_type"] == "transfer"
    assert records[0]["source"] == TARGET
    assert records[0]["target"] == OTHER
    assert limitations == []


def test_erc20_transfer_to_address_preserves_token(monkeypatch):
    collector = make_collector(monkeypatch, {"alchemy_getAssetTransfers": [{"transfers": []}, {"transfers": [transfer(OTHER, TARGET, "erc20", 2.5)]}], "eth_getBlockByNumber": {}})
    records, _ = collector.collect_alchemy_transfers(TARGET)
    assert records[0]["edge_type"] == "token_transfer"
    assert records[0]["metadata"]["token"] == TOKEN
    assert records[0]["metadata"]["asset"] == "USDC"


def test_pagination_and_duplicate_removal(monkeypatch):
    duplicate = transfer(TARGET, OTHER, unique_id="same")
    second = transfer(TARGET, OTHER, value=3.0, unique_id="second")
    collector = make_collector(monkeypatch, {"alchemy_getAssetTransfers": [{"transfers": [duplicate], "pageKey": "next"}, {"transfers": [duplicate, second]}, {"transfers": []}], "eth_getBlockByNumber": {}})
    records, _ = collector.collect_alchemy_transfers(TARGET, max_pages=3)
    assert len(records) == 2
    assert {record["metadata"]["transactionHash"] for record in records} == {"0xhash"}


def test_page_limit_is_reported(monkeypatch):
    page = {"transfers": [transfer(TARGET, OTHER)], "pageKey": "always"}
    collector = make_collector(monkeypatch, {"alchemy_getAssetTransfers": [page, page], "eth_getBlockByNumber": {}})
    records, limitations = collector.collect_alchemy_transfers(TARGET, max_pages=1)
    assert records
    assert any("page limit" in item for item in limitations)


def test_zero_value_transfer_is_retained(monkeypatch):
    collector = make_collector(monkeypatch, {"alchemy_getAssetTransfers": [{"transfers": [transfer(TARGET, OTHER, value=0.0)]}, {"transfers": []}], "eth_getBlockByNumber": {}})
    records, _ = collector.collect_alchemy_transfers(TARGET)
    assert records[0]["value"] == 0.0


def test_malformed_alchemy_response_is_rejected(monkeypatch):
    collector = make_collector(monkeypatch, {"alchemy_getAssetTransfers": {"bad": True}, "eth_getBlockByNumber": {}})
    with pytest.raises(AlchemyTransferError):
        collector.collect_alchemy_transfers(TARGET)


def test_rpc_failure_is_propagated(monkeypatch):
    collector = RpcCollector("https://alchemy.example")
    monkeypatch.setattr(collector, "validate_connection", lambda: "0x1")
    monkeypatch.setattr(collector, "_request", lambda method, params: (_ for _ in ()).throw(RpcUnavailableError("offline")))
    with pytest.raises(RpcUnavailableError):
        collector.collect_alchemy_transfers(TARGET)


def test_approval_event_is_decoded(monkeypatch):
    owner_topic = "0x" + TARGET[2:].rjust(64, "0")
    spender_topic = "0x" + SPENDER[2:].rjust(64, "0")
    approval_log = {"address": TOKEN, "topics": [collector_topic := RpcCollector("https://alchemy.example").approval_topic, owner_topic, spender_topic], "data": hex(2**256 - 1), "blockNumber": "0x10", "transactionHash": "0xapproval"}
    collector = RpcCollector("https://alchemy.example")
    monkeypatch.setattr(collector, "validate_connection", lambda: "0x1")
    monkeypatch.setattr(collector, "_request", lambda method, params: [approval_log] if method == "eth_getLogs" else "0x10" if method == "eth_blockNumber" else {"timestamp": "0x65b2a000"})
    approvals = collector.collect_approval_events(TARGET)
    assert approvals[0]["metadata"]["owner"] == TARGET
    assert approvals[0]["metadata"]["spender"] == SPENDER
    assert approvals[0]["metadata"]["allowance"] == str(2**256 - 1)


def test_missing_approval_data_returns_empty(monkeypatch):
    collector = RpcCollector("https://alchemy.example")
    monkeypatch.setattr(collector, "validate_connection", lambda: "0x1")
    monkeypatch.setattr(collector, "_request", lambda method, params: [] if method == "eth_getLogs" else "0x10" if method == "eth_blockNumber" else {})
    assert collector.collect_approval_events(TARGET) == []


def test_seed_relationship_enrichment_filters_target_to_seed(monkeypatch):
    seed = OTHER
    collector = make_collector(monkeypatch, {"alchemy_getAssetTransfers": [{"transfers": [transfer(TARGET, seed, unique_id="relationship"), transfer(seed, TARGET, unique_id="reverse")]}, {"transfers": []}], "eth_getBlockByNumber": {}})
    relationships, limitations = collector.collect_seed_relationships(seed, TARGET)
    assert len(relationships) == 1
    assert relationships[0]["source"] == TARGET
    assert relationships[0]["target"] == seed
    assert relationships[0]["evidence_source"] == "alchemy_seed_enrichment"
    assert relationships[0]["metadata"]["source"] == "alchemy_seed_enrichment"
