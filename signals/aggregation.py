from collections import defaultdict
from typing import Iterable, List
from signals.models import RiskSignal


_INTRINSIC_LABELS = ((0.85, "confirmed_malicious"), (0.60, "high_risk"), (0.25, "suspicious"))


def aggregate_signals(signals: Iterable[RiskSignal]) -> List[RiskSignal]:
    grouped: dict[tuple[str, str, str], RiskSignal] = {}
    for signal in signals:
        evidence_id = str(signal.evidence.get("event_id") or signal.evidence.get("flag") or signal.evidence.get("token") or signal.signal_type)
        key = (signal.address, signal.signal_type, evidence_id)
        existing = grouped.get(key)
        if existing is None or (signal.severity, signal.confidence) > (existing.severity, existing.confidence):
            grouped[key] = signal
    return sorted(grouped.values(), key=lambda signal: (signal.address, -signal.severity, signal.signal_type))


def intrinsic_label(signals: Iterable[RiskSignal]) -> str:
    direct = [signal.severity for signal in signals if signal.signal_type in {"confirmed_malicious", "high_risk", "suspicious"}]
    highest = max(direct, default=0.0)
    for threshold, label in _INTRINSIC_LABELS:
        if highest >= threshold:
            return label
    return "unknown"
