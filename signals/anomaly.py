from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any, Dict, Iterable, List, Optional
from signals.models import RiskSignal


def detect_behavioral_anomalies(address: str, transactions: Iterable[Dict[str, Any]], observed_at: Optional[datetime] = None) -> List[RiskSignal]:
	records = list(transactions)
	if not records:
		return []
	parsed = []
	for record in records:
		timestamp = record.get("timestamp")
		if isinstance(timestamp, str):
			timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
		if timestamp and timestamp.tzinfo is None:
			timestamp = timestamp.replace(tzinfo=timezone.utc)
		try:
			value = float(record.get("value", 0.0))
		except (TypeError, ValueError, OverflowError):
			continue
		parsed.append((value, timestamp, record))
	signals: List[RiskSignal] = []
	histories: Dict[str, List[tuple[float, Optional[datetime], Dict[str, Any]]]] = {}
	for value, timestamp, record in parsed:
		metadata = record.get("metadata") or {}
		asset_key = str(metadata.get("token") or metadata.get("asset") or record.get("asset") or "native").lower()
		histories.setdefault(asset_key, []).append((value, timestamp, record))
	for asset_history in histories.values():
		for value, timestamp, record in asset_history:
			if value <= 0 or timestamp is None:
				continue
			baseline_values = sorted(item[0] for item in asset_history if item[2] is not record and item[0] > 0)
			if len(baseline_values) < 5:
				continue
			baseline = median(baseline_values)
			p99 = baseline_values[min(len(baseline_values) - 1, int((len(baseline_values) - 1) * 0.99))]
			deviation_multiplier = value / baseline if baseline else 0.0
			if baseline > 0 and deviation_multiplier >= 10.0 and value > max(baseline * 10.0, p99 * 4.0):
				signals.append(RiskSignal(address=address, signal_type="large_transfer_anomaly", severity=min(1.0, deviation_multiplier / 100.0), source="behavioral_rules", evidence={"value": value, "asset": str((record.get("metadata") or {}).get("asset") or (record.get("metadata") or {}).get("token") or record.get("asset") or "native"), "baseline_median": baseline, "baseline_p99": p99, "deviation_multiplier": deviation_multiplier, "transaction_hash": (record.get("metadata") or {}).get("transactionHash"), "transaction": record}, observed_at=timestamp, confidence=0.9))
				break
	dated = sorted(timestamp for _, timestamp, _ in parsed if timestamp)
	if len(dated) >= 3 and dated[-1] - dated[-3] <= timedelta(hours=1):
		signals.append(RiskSignal(address=address, signal_type="activity_burst", severity=0.45, source="behavioral_rules", evidence={"events": 3, "window_hours": 1}, observed_at=dated[-1], confidence=0.85))
	contract_events = [(timestamp, record) for _, timestamp, record in parsed if timestamp and record.get("edge_type") == "contract_interaction"]
	if contract_events and dated and dated[-1] - dated[0] >= timedelta(days=30):
		latest_timestamp, latest_record = contract_events[-1]
		signals.append(RiskSignal(address=address, signal_type="new_contract_after_inactivity", severity=0.40, source="behavioral_rules", evidence={"transaction": latest_record, "inactive_days": (latest_timestamp - dated[0]).days}, observed_at=latest_timestamp, confidence=0.75))
	return signals
