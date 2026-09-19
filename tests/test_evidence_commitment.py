from analyzer import analyze_address
from proof.merkle import build_merkle_tree, get_root

EMPTY_ROOT = get_root(build_merkle_tree([]))


def test_confirmed_malicious_signal_is_committed():
    result = analyze_address("0x1111111111111111111111111111111111111111")
    assert result["signalEvidence"]
    assert result["evidenceCount"] > 0
    assert result["evidenceRoot"] != EMPTY_ROOT
    assert result["signalEvidence"][0]["signal_type"] == "confirmed_malicious"


def test_provider_flag_changes_evidence_root():
    first = [{"address": "0x1", "signal_type": "confirmed_malicious", "severity": 1.0, "source": "goplus", "providerEvidence": {"flag": "is_phishing"}}]
    second = [{"address": "0x1", "signal_type": "confirmed_malicious", "severity": 1.0, "source": "goplus", "providerEvidence": {"flag": "stealing_attack"}}]
    assert get_root(build_merkle_tree(first)) != get_root(build_merkle_tree(second))


def test_transaction_hash_changes_evidence_root():
    first = [{"path": ["a", "b"], "relationship": {"txHash": "0xone", "value": 1}}]
    second = [{"path": ["a", "b"], "relationship": {"txHash": "0xtwo", "value": 1}}]
    assert get_root(build_merkle_tree(first)) != get_root(build_merkle_tree(second))
