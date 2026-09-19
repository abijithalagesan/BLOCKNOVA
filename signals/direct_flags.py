from datetime import datetime
from typing import Any, Dict, List, Optional
from signals.models import RiskSignal


_FLAG_LABELS = {
	"confirmed_malicious": ("confirmed_malicious", 1.0),
	"is_blacklisted": ("confirmed_malicious", 1.0),
	"is_phishing": ("confirmed_malicious", 1.0),
	"cybercrime": ("confirmed_malicious", 1.0),
	"money_laundering": ("confirmed_malicious", 1.0),
	"financial_crime": ("confirmed_malicious", 1.0),
	"stealing_attack": ("confirmed_malicious", 1.0),
	"blackmail": ("confirmed_malicious", 1.0),
	"high_risk": ("high_risk", 0.7),
	"is_mixer": ("suspicious", 0.4),
	"blacklist_doubt": ("suspicious", 0.4),
	"honeypot_related_address": ("suspicious", 0.4),
}


def _enabled(value: Any) -> bool:
	return str(value).lower() in {"1", "true", "yes", "detected"}


def detect_direct_flags(address: str, provider_data: Any, source: str = "provider", observed_at: Optional[datetime] = None) -> List[RiskSignal]:
	flags: Dict[str, Any] = dict(getattr(provider_data, "flags", provider_data or {}))
	source = getattr(provider_data, "source", source)
	observed_at = getattr(provider_data, "observed_at", observed_at)
	signals: List[RiskSignal] = []
	for flag, (signal_type, severity) in _FLAG_LABELS.items():
		if _enabled(flags.get(flag, False)):
			signals.append(RiskSignal(address=address, signal_type=signal_type, severity=severity, source=source, evidence={"flag": flag, "value": flags.get(flag), "provider_flags": flags}, observed_at=observed_at, confidence=1.0))
	return signals
