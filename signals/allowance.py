from datetime import datetime
from typing import Any, Dict, List, Optional
from signals.models import RiskSignal


def detect_allowance_risk(address: str, approval: Optional[Dict[str, Any]], observed_at: Optional[datetime] = None) -> List[RiskSignal]:
	if not approval:
		return []
	raw_value = approval.get("allowance", approval.get("value", 0))
	try:
		allowance = int(raw_value)
	except (TypeError, ValueError):
		return []
	if allowance <= 0:
		return []
	maximum = int(approval.get("max_uint256", 2**256 - 1))
	if allowance >= int(maximum * 0.99):
		signal_type, severity, description = "unlimited_allowance", 0.8, "effectively unlimited token allowance"
	elif allowance >= int(approval.get("high_threshold", 10**24)):
		signal_type, severity, description = "large_allowance", 0.5, "large token allowance"
	else:
		signal_type, severity, description = "normal_allowance", 0.15, "normal token allowance"
	evidence = {"token": approval.get("token"), "spender": approval.get("spender"), "allowance": str(allowance), "description": description}
	return [RiskSignal(address=address, signal_type=signal_type, severity=severity, source=str(approval.get("source", "allowance")), evidence=evidence, observed_at=observed_at, confidence=float(approval.get("confidence", 1.0)))]
