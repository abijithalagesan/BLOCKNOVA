from datetime import datetime
from typing import Any, Dict, List, Optional
from signals.models import RiskSignal


_CONTROL_RULES = {
	"owner": ("owner_control", 0.35),
	"admin": ("admin_control", 0.45),
	"upgradeable": ("upgradeability", 0.55),
	"proxy": ("upgradeability", 0.55),
	"pause": ("pause_capability", 0.35),
	"mint": ("mint_capability", 0.50),
	"privileged_control": ("privileged_control", 0.60),
	"ownership_changed": ("ownership_change", 0.40),
}


def detect_contract_control(address: str, control_data: Optional[Dict[str, Any]], observed_at: Optional[datetime] = None) -> List[RiskSignal]:
	if not control_data:
		return []
	signals: List[RiskSignal] = []
	for field, (signal_type, severity) in _CONTROL_RULES.items():
		value = control_data.get(field)
		if value in (None, False, 0, "", "0", "false"):
			continue
		signals.append(RiskSignal(address=address, signal_type=signal_type, severity=severity, source=str(control_data.get("source", "contract_control")), evidence={"field": field, "value": value, "contract": address}, observed_at=observed_at, confidence=float(control_data.get("confidence", 1.0))))
	return signals
