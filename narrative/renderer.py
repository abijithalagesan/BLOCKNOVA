from typing import Any, Dict, List
from narrative.schema import Narrative
from narrative.validator import validate_evidence


def render(result: Dict[str, Any]) -> Narrative:
    evidence: List[Dict[str, Any]] = result["evidence"]
    validate_evidence(evidence)
    limitations = []
    quality = result["riskVector"]["dataQuality"]
    if quality < 1.0:
        limitations.append(f"Analysis coverage is incomplete ({quality:.0%}); absence of evidence is not proof of safety.")
    if evidence:
        lead = evidence[0]
        status = lead.get("exposureStatus", "UNKNOWN")
        age_days = lead.get("ageDays")
        if status == "ACTIVE":
            timing = "This is a recent relationship, so the current propagated exposure remains significant."
        elif status in {"HISTORICAL", "DORMANT"} and age_days is not None:
            years = age_days / 365.25
            timing = f"This is a {status.lower()} relationship from approximately {years:.1f} years ago, so the current propagated exposure is strongly reduced by recency; the relationship is not thereby harmless."
        else:
            timing = "The relationship timestamp is unavailable, so its currentness cannot be determined."
        explanation = f"Supported evidence found a {lead['hops']}-hop path from {lead['targetNode']} to {lead['sourceNode']}. {lead['reason']} {timing}"
    elif result.get("signalEvidence"):
        signal = result["signalEvidence"][0]
        flag = signal["providerEvidence"].get("flag", signal["signal_type"])
        explanation = f"Provider evidence for {signal['address']} reports {flag} with severity {signal['severity']:.2f} from {signal['source']}. This signal is included in the evidence commitment; absence of a propagated path does not weaken the direct signal."
    else:
        explanation = "No supported risky exposure was found in the available evidence. This does not prove the address is safe, especially where coverage is incomplete."
    return Narrative(explanation=explanation, limitations=limitations)
