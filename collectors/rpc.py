from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import requests
from graph.models import Node
from eth_utils import keccak


class RpcUnavailableError(RuntimeError):
    """Raised when an Ethereum JSON-RPC endpoint cannot provide data."""


class AlchemyTransferError(RpcUnavailableError):
    """Raised when Alchemy's transfer method returns unusable data."""


class RpcCollector:
    def __init__(self, rpc_url: str, timeout: float = 10.0, lookback_blocks: int = 20, session: Optional[requests.Session] = None) -> None:
        if not rpc_url:
            raise ValueError("ETHEREUM_RPC_URL is required for live mode")
        self.rpc_url = rpc_url
        self.timeout = timeout
        self.lookback_blocks = max(1, lookback_blocks)
        self.session = session or requests.Session()
        self._request_id = 0
        self.approval_topic = "0x" + keccak(text="Approval(address,address,uint256)").hex()
        self.approval_history_limited = False

    def _request(self, method: str, params: List[Any]) -> Any:
        self._request_id += 1
        try:
            response = self.session.post(self.rpc_url, json={"jsonrpc": "2.0", "id": self._request_id, "method": method, "params": params}, timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as error:
            status_code = getattr(getattr(error, "response", None), "status_code", None)
            detail = f"HTTP {status_code}" if status_code else "request failed"
            raise RpcUnavailableError(f"Ethereum RPC request failed: {detail}") from error
        except ValueError as error:
            raise RpcUnavailableError("Ethereum RPC returned invalid JSON") from error
        if "error" in payload:
            raise RpcUnavailableError(f"Ethereum RPC returned an error for {method}: {payload['error']}")
        return payload.get("result")

    def validate_connection(self) -> str:
        chain_id = self._request("eth_chainId", [])
        if chain_id != "0x1":
            raise RpcUnavailableError(f"configured RPC is not Ethereum mainnet: {chain_id}")
        return chain_id

    def latest_block_number(self) -> int:
        return int(self._request("eth_blockNumber", []), 16)

    def get_code(self, address: str) -> str:
        normalized = Node(address=address).address
        return str(self._request("eth_getCode", [normalized, "latest"]) or "0x")

    def identify_addresses(self, addresses: List[str]) -> Dict[str, str]:
        self.validate_connection()
        identified: Dict[str, str] = {}
        for address in sorted(set(addresses)):
            identified[Node(address=address).address] = "contract" if self.get_code(address) not in {"0x", "0x0", "0x00"} else "wallet"
        return identified

    def collect_approval_events(self, address: str, lookback_blocks: int = 100) -> List[Dict[str, Any]]:
        normalized = Node(address=address).address
        self.validate_connection()
        padded = "0x" + normalized[2:].rjust(64, "0")
        latest = self.latest_block_number()
        lookback = max(1, lookback_blocks)
        start_block = max(0, latest - lookback + 1)
        self.approval_history_limited = start_block > 0
        logs: List[Dict[str, Any]] = []
        for chunk_start in range(start_block, latest + 1, 10):
            chunk_end = min(latest, chunk_start + 9)
            logs.extend(self._request("eth_getLogs", [{"fromBlock": hex(chunk_start), "toBlock": hex(chunk_end), "topics": [self.approval_topic, padded]}]) or [])
        block_timestamps: Dict[str, datetime] = {}
        approvals: List[Dict[str, Any]] = []
        for log in logs:
            try:
                topics = log.get("topics", [])
                if len(topics) < 3:
                    continue
                owner = "0x" + topics[1][-40:]
                spender = "0x" + topics[2][-40:]
                allowance = int(log.get("data", "0x0"), 16)
                block_number = log.get("blockNumber")
                if block_number not in block_timestamps:
                    block = self._request("eth_getBlockByNumber", [block_number, False]) or {}
                    block_timestamps[block_number] = datetime.fromtimestamp(int(block.get("timestamp", "0x0"), 16), tz=timezone.utc)
                approvals.append({"source": owner.lower(), "target": spender.lower(), "edge_type": "approval", "value": min(float(allowance) / 10**18, 1e308), "timestamp": block_timestamps[block_number], "evidence_source": "alchemy_rpc", "metadata": {"transactionHash": log.get("transactionHash"), "blockNumber": block_number, "token": (log.get("address") or "").lower(), "allowance": str(allowance), "spender": spender.lower(), "owner": owner.lower()}})
            except (TypeError, ValueError, OverflowError, KeyError):
                continue
        return approvals

    def collect_alchemy_transfers(self, address: str, max_pages: int = 10, page_size: int = 100) -> tuple[List[Dict[str, Any]], List[str]]:
        normalized = Node(address=address).address
        self.validate_connection()
        transfers: List[Dict[str, Any]] = []
        limitations: List[str] = []
        seen: set[str] = set()
        categories = ["external", "internal", "erc20"]
        for direction in ("fromAddress", "toAddress"):
            page_key: Optional[str] = None
            for page_number in range(max(1, max_pages)):
                params: Dict[str, Any] = {direction: normalized, "category": categories, "withMetadata": True, "maxCount": hex(max(1, page_size))}
                if page_key:
                    params["pageKey"] = page_key
                try:
                    response = self._request("alchemy_getAssetTransfers", [params]) or {}
                except RpcUnavailableError:
                    raise
                if not isinstance(response, dict) or "transfers" not in response or not isinstance(response["transfers"], list):
                    raise AlchemyTransferError("Alchemy returned an invalid alchemy_getAssetTransfers response")
                for transfer in response.get("transfers", []):
                    try:
                        source = Node(address=transfer["from"]).address
                        target = Node(address=transfer["to"]).address
                        category = str(transfer.get("category", "external"))
                        edge_type = "token_transfer" if category == "erc20" else "transfer" if category in {"external", "internal"} else "contract_interaction"
                        unique_id = str(transfer.get("uniqueId") or f"{transfer.get('hash')}:{source}:{target}:{category}")
                        if unique_id in seen:
                            continue
                        seen.add(unique_id)
                        timestamp = None
                        metadata = transfer.get("metadata") or {}
                        if metadata.get("blockTimestamp"):
                            timestamp = datetime.fromisoformat(str(metadata["blockTimestamp"]).replace("Z", "+00:00"))
                        if timestamp is None:
                            block_number = transfer.get("blockNum")
                            block = self._request("eth_getBlockByNumber", [block_number, False]) or {}
                            timestamp = datetime.fromtimestamp(int(block.get("timestamp", "0x0"), 16), tz=timezone.utc)
                        raw_contract = transfer.get("rawContract") or {}
                        transfers.append({"source": source, "target": target, "edge_type": edge_type, "value": float(transfer.get("value") or 0.0), "timestamp": timestamp, "evidence_source": "alchemy_transfers", "metadata": {"transactionHash": transfer.get("hash"), "blockNumber": transfer.get("blockNum"), "asset": transfer.get("asset"), "token": raw_contract.get("address"), "rawContract": raw_contract, "category": category}})
                    except (KeyError, TypeError, ValueError, OverflowError):
                        limitations.append("Alchemy returned a malformed transfer record; that record was skipped.")
                page_key = response.get("pageKey")
                if not page_key:
                    break
            else:
                limitations.append(f"Alchemy transfer pagination stopped at the configured page limit ({max_pages}) for {direction}.")
        return transfers, limitations

    def collect_seed_relationships(self, seed: str, target: str, max_pages: int = 10, page_size: int = 100) -> tuple[List[Dict[str, Any]], List[str]]:
        normalized_seed = Node(address=seed).address
        normalized_target = Node(address=target).address
        transfers, limitations = self.collect_alchemy_transfers(normalized_seed, max_pages=max_pages, page_size=page_size)
        relationships = []
        for transfer in transfers:
            if transfer["source"] == normalized_target and transfer["target"] == normalized_seed:
                relationship = dict(transfer)
                relationship["evidence_source"] = "alchemy_seed_enrichment"
                metadata = dict(relationship.get("metadata") or {})
                metadata["source"] = "alchemy_seed_enrichment"
                relationship["metadata"] = metadata
                relationships.append(relationship)
        return relationships, limitations

    def collect_transactions(self, address: str) -> List[Dict[str, Any]]:
        normalized = Node(address=address).address
        self.validate_connection()
        latest = self.latest_block_number()
        transactions: List[Dict[str, Any]] = []
        for block_number in range(max(0, latest - self.lookback_blocks + 1), latest + 1):
            block = self._request("eth_getBlockByNumber", [hex(block_number), True]) or {}
            timestamp = datetime.fromtimestamp(int(block.get("timestamp", "0x0"), 16), tz=timezone.utc)
            for transaction in block.get("transactions", []):
                source = (transaction.get("from") or "").lower()
                target = (transaction.get("to") or "").lower()
                if normalized not in {source, target} or not target:
                    continue
                value_wei = int(transaction.get("value", "0x0"), 16)
                transactions.append({
                    "source": source,
                    "target": target,
                    "edge_type": "transfer" if value_wei else "contract_interaction",
                    "value": value_wei / 10**18,
                    "timestamp": timestamp,
                    "evidence_source": "ethereum_rpc",
                    "metadata": {"transactionHash": transaction.get("hash"), "blockNumber": block_number},
                })
        return transactions
