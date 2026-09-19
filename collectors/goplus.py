from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import requests
from graph.models import Node


class GoPlusUnavailableError(RuntimeError):
	"""Raised when GoPlus cannot return a usable response."""


@dataclass(frozen=True)
class SecuritySignal:
	address: str
	risk_label: str
	source: str
	flags: Dict[str, Any] = field(default_factory=dict)
	observed_at: Optional[datetime] = None


class GoPlusCollector:
	def __init__(self, api_url: str, api_key: Optional[str] = None, timeout: float = 10.0, session: Optional[requests.Session] = None) -> None:
		if not api_url:
			raise ValueError("GOPLUS_API_URL is required for live security signals")
		self.api_url = api_url.rstrip("/")
		self.api_key = api_key
		self.timeout = timeout
		self.session = session or requests.Session()

	def get_signal(self, address: str) -> Optional[SecuritySignal]:
		normalized = Node(address=address).address
		headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
		try:
			response = self.session.get(f"{self.api_url}/{normalized}", params={"chain_id": "1"}, headers=headers, timeout=self.timeout)
			response.raise_for_status()
			payload = response.json()
		except (requests.RequestException, ValueError) as error:
			raise GoPlusUnavailableError(f"GoPlus request failed: {error}") from error
		result = payload.get("result")
		if not isinstance(result, dict):
			raise GoPlusUnavailableError("GoPlus response did not contain a result object")
		flags = {key: value for key, value in result.items() if value not in (None, "", 0, "0", False)}
		if not flags:
			return None
		confirmed_flags = {"is_blacklisted", "is_phishing", "cybercrime", "money_laundering", "financial_crime", "stealing_attack", "blackmail"}
		suspicious_flags = {"is_mixer", "blacklist_doubt", "honeypot_related_address"}
		if any(str(flags.get(key)).lower() in {"1", "true", "yes"} for key in confirmed_flags):
			label = "confirmed_malicious"
		elif any(str(flags.get(key)).lower() in {"1", "true", "yes"} for key in suspicious_flags):
			label = "suspicious"
		else:
			label = "unknown"
		observed_at = None
		for timestamp_key in ("observed_at", "timestamp", "updated_at", "last_updated"):
			raw_timestamp = result.get(timestamp_key)
			if raw_timestamp in (None, ""):
				continue
			try:
				observed_at = datetime.fromtimestamp(int(raw_timestamp), tz=timezone.utc) if str(raw_timestamp).isdigit() else datetime.fromisoformat(str(raw_timestamp).replace("Z", "+00:00"))
			except (TypeError, ValueError, OverflowError):
				continue
			break
		return SecuritySignal(address=normalized, risk_label=label, source="goplus", flags=flags, observed_at=observed_at)
