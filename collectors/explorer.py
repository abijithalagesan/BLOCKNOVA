import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import requests
from eth_utils import keccak
from graph.models import Node


class ExplorerUnavailableError(RuntimeError):
	"""Raised when an Etherscan-compatible API cannot provide usable data."""


@dataclass(frozen=True)
class ExplorerHistory:
	transactions: List[Dict[str, Any]]
	approvals: List[Dict[str, Any]]
	coverage: Dict[str, float]
	limitations: List[str]


class ExplorerCollector:
	approval_topic = keccak(text="Approval(address,address,uint256)").hex()

	def __init__(self, api_url: str, api_key: Optional[str] = None, chain_id: str = "1", timeout: float = 15.0, cache_path: str = ".blocknova_cache.json", session: Optional[requests.Session] = None) -> None:
		if not api_url:
			raise ValueError("ETHERSCAN_API_URL is required for real wallet history")
		self.api_url = api_url
		self.api_key = api_key
		self.chain_id = str(chain_id or "1")
		self.timeout = timeout
		self.cache_path = Path(cache_path)
		self.session = session or requests.Session()

	def _cache_key(self, params: Dict[str, Any]) -> str:
		encoded = json.dumps(params, sort_keys=True, separators=(",", ":"))
		return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

	def _cached(self, params: Dict[str, Any]) -> Optional[Any]:
		if not self.cache_path.exists():
			return None
		try:
			cache = json.loads(self.cache_path.read_text())
			return cache.get(self._cache_key(params))
		except (OSError, ValueError):
			return None

	def _store(self, params: Dict[str, Any], value: Any) -> None:
		try:
			cache = json.loads(self.cache_path.read_text()) if self.cache_path.exists() else {}
			cache[self._cache_key(params)] = value
			self.cache_path.write_text(json.dumps(cache))
		except (OSError, TypeError, ValueError):
			return

	def _request(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
		request_params = dict(params)
		request_params["chainid"] = self.chain_id
		cached = self._cached(request_params)
		if cached is not None:
			return cached
		query = dict(request_params)
		if self.api_key:
			query["apikey"] = self.api_key
		try:
			response = self.session.get(self.api_url, params=query, timeout=self.timeout)
			response.raise_for_status()
			payload = response.json()
		except requests.RequestException as error:
			status_code = getattr(getattr(error, "response", None), "status_code", None)
			detail = f"HTTP {status_code}" if status_code else "request failed"
			raise ExplorerUnavailableError(f"explorer request failed: {detail}") from error
		except ValueError as error:
			raise ExplorerUnavailableError("explorer returned invalid JSON") from error
		result = payload.get("result")
		if payload.get("status") == "0" and isinstance(result, str) and "no transactions" in result.lower():
			result = []
		if not isinstance(result, list):
			raise ExplorerUnavailableError(f"explorer returned an invalid response: {payload.get('message', payload)}")
		self._store(request_params, result)
		return result

	@staticmethod
	def _timestamp(record: Dict[str, Any]) -> datetime:
		raw = record.get("timeStamp") or record.get("timestamp")
		if raw in (None, ""):
			raise ValueError("record is missing timestamp")
		return datetime.fromtimestamp(int(raw, 0) if isinstance(raw, str) and raw.startswith("0x") else int(raw), tz=timezone.utc)
	@staticmethod
	def _scaled_value(raw_value: int, decimals: int = 18) -> float:
		# Keep malformed or impractically large provider integers finite for the graph.
		if raw_value.bit_length() > 1023:
			return 1e308
		return min(float(raw_value) / (10**decimals), 1e308)

	def normal_transactions(self, address: str) -> List[Dict[str, Any]]:
		normalized = Node(address=address).address
		records = self._request({"module": "account", "action": "txlist", "address": normalized, "startblock": 0, "endblock": 99999999, "page": 1, "offset": 1000, "sort": "asc"})
		result = []
		for record in records:
			try:
				source = (record.get("from") or "").lower()
				target = (record.get("to") or "").lower()
				if not source or not target:
					continue
				value_wei = int(record.get("value") or 0)
				result.append({"source": source, "target": target, "edge_type": "transfer" if value_wei else "contract_interaction", "value": self._scaled_value(value_wei), "timestamp": self._timestamp(record), "evidence_source": "etherscan", "metadata": {"transactionHash": record.get("hash"), "blockNumber": record.get("blockNumber"), "valueWei": str(value_wei)}})
			except (TypeError, ValueError, OverflowError):
				continue
		return result

	def token_transfers(self, address: str) -> List[Dict[str, Any]]:
		normalized = Node(address=address).address
		records = self._request({"module": "account", "action": "tokentx", "address": normalized, "startblock": 0, "endblock": 99999999, "page": 1, "offset": 1000, "sort": "asc"})
		result = []
		for record in records:
			try:
				source = (record.get("from") or "").lower()
				target = (record.get("to") or "").lower()
				if not source or not target:
					continue
				raw_value = int(record.get("value") or 0)
				decimals = int(record.get("tokenDecimal") or 0)
				result.append({"source": source, "target": target, "edge_type": "token_transfer", "value": self._scaled_value(raw_value, decimals) if decimals else 0.0, "timestamp": self._timestamp(record), "evidence_source": "etherscan", "metadata": {"transactionHash": record.get("hash"), "blockNumber": record.get("blockNumber"), "token": (record.get("contractAddress") or "").lower(), "tokenSymbol": record.get("tokenSymbol"), "tokenValueRaw": str(raw_value), "tokenDecimals": decimals}})
			except (TypeError, ValueError, OverflowError):
				continue
		return result

	def approval_events(self, address: str) -> List[Dict[str, Any]]:
		normalized = Node(address=address).address
		topic_address = normalized[2:].rjust(64, "0")
		records = self._request({"module": "logs", "action": "getLogs", "fromBlock": 0, "toBlock": "latest", "topic0": self.approval_topic, "topic1": f"0x{topic_address}", "topic0_1_opr": "and"})
		result = []
		for record in records:
			try:
				topics = record.get("topics", [])
				if len(topics) < 3:
					continue
				owner = "0x" + topics[1][-40:]
				spender = "0x" + topics[2][-40:]
				allowance_raw = int(record.get("data", "0x0"), 16)
				result.append({"source": owner.lower(), "target": spender.lower(), "edge_type": "approval", "value": self._scaled_value(allowance_raw), "timestamp": self._timestamp(record), "evidence_source": "etherscan", "metadata": {"transactionHash": record.get("transactionHash"), "blockNumber": record.get("blockNumber"), "token": (record.get("address") or "").lower(), "allowance": str(allowance_raw), "spender": spender.lower(), "owner": owner.lower()}})
			except (TypeError, ValueError, OverflowError):
				continue
		return result

	def collect_history(self, address: str) -> ExplorerHistory:
		limitations: List[str] = []
		coverage = {"transactionHistory": 0.0, "tokenTransfers": 0.0, "approvals": 0.0}
		try:
			transactions = self.normal_transactions(address)
			coverage["transactionHistory"] = 1.0
		except ExplorerUnavailableError as error:
			transactions = []
			limitations.append(f"normal transaction history unavailable: {error}")
		try:
			transactions.extend(self.token_transfers(address))
			coverage["tokenTransfers"] = 1.0
		except ExplorerUnavailableError as error:
			limitations.append(f"ERC-20 transfer history unavailable: {error}")
		try:
			approvals = self.approval_events(address)
			coverage["approvals"] = 1.0
		except ExplorerUnavailableError as error:
			approvals = []
			limitations.append(f"approval history unavailable: {error}")
		if not transactions:
			limitations.append("The explorer returned no transaction history for this address.")
		return ExplorerHistory(transactions=transactions, approvals=approvals, coverage=coverage, limitations=limitations)
