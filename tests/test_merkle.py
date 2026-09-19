from proof.merkle import build_merkle_tree, get_proof, get_root, verify_proof


def test_same_evidence_same_root_and_reordered_fields_same_root():
    first = [{"value": 1, "hash": "0xabc"}, {"path": ["a", "b"], "risk": 0.2}]
    second = [{"hash": "0xabc", "value": 1}, {"risk": 0.2, "path": ["a", "b"]}]
    assert get_root(build_merkle_tree(first)) == get_root(build_merkle_tree(second))


def test_changed_transaction_hash_changes_root():
    assert get_root(build_merkle_tree([{"hash": "0xabc"}])) != get_root(build_merkle_tree([{"hash": "0xdef"}]))


def test_changed_value_changes_root():
    assert get_root(build_merkle_tree([{"value": 1}])) != get_root(build_merkle_tree([{"value": 2}]))


def test_proof_verifies_and_invalid_proof_fails():
    evidence = [{"id": index, "value": index * 10} for index in range(3)]
    tree = build_merkle_tree(evidence)
    proof = get_proof(tree, 1)
    assert verify_proof(evidence[1], proof, get_root(tree))
    assert not verify_proof({"id": 1, "value": 999}, proof, get_root(tree))


def test_empty_evidence_is_safe():
    tree = build_merkle_tree([])
    assert tree["leafCount"] == 0
    assert len(tree["root"]) == 64
    try:
        get_proof(tree, 0)
    except IndexError:
        pass
    else:
        raise AssertionError("empty tree should not produce a proof")
