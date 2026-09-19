import hashlib
import json
from typing import Any, Dict, List, Sequence


def canonical_json(value: Any) -> str:
	return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def hash_leaf(leaf: Any) -> str:
	return hashlib.sha256(canonical_json(leaf).encode("utf-8")).hexdigest()


def _hash_pair(left: str, right: str) -> str:
	return hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def build_merkle_tree(evidence: Sequence[Any]) -> Dict[str, Any]:
	leaves = [hash_leaf(item) for item in evidence]
	if not leaves:
		empty = hashlib.sha256(b"").hexdigest()
		return {"root": empty, "leafCount": 0, "leaves": [], "levels": [[empty]]}
	levels: List[List[str]] = [leaves]
	current = leaves
	while len(current) > 1:
		next_level: List[str] = []
		for index in range(0, len(current), 2):
			left = current[index]
			right = current[index + 1] if index + 1 < len(current) else left
			next_level.append(_hash_pair(left, right))
		levels.append(next_level)
		current = next_level
	return {"root": current[0], "leafCount": len(leaves), "leaves": leaves, "levels": levels}


def get_root(tree: Dict[str, Any]) -> str:
	return str(tree["root"])


def get_proof(tree: Dict[str, Any], index: int) -> List[Dict[str, str]]:
	if tree.get("leafCount", 0) == 0 or index < 0 or index >= tree["leafCount"]:
		raise IndexError("leaf index is outside the Merkle tree")
	proof: List[Dict[str, str]] = []
	current_index = index
	for level in tree["levels"][:-1]:
		sibling_index = current_index - 1 if current_index % 2 else current_index + 1
		if sibling_index >= len(level):
			sibling_index = current_index
		proof.append({"hash": level[sibling_index], "position": "left" if current_index % 2 else "right"})
		current_index //= 2
	return proof


def verify_proof(leaf: Any, proof: Sequence[Dict[str, str]], root: str) -> bool:
	current = hash_leaf(leaf) if not (isinstance(leaf, str) and len(leaf) == 64) else leaf
	try:
		for item in proof:
			sibling = item["hash"]
			if item["position"] == "left":
				current = _hash_pair(sibling, current)
			elif item["position"] == "right":
				current = _hash_pair(current, sibling)
			else:
				return False
		return current == root
	except (KeyError, ValueError):
		return False
