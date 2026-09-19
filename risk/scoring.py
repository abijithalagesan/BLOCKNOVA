from datetime import datetime
from typing import Any, Dict, List, Optional
from config.constants import DEFAULT_CONFIG, EdgeType, RiskConfig
from risk.aggregation import aggregate_correlated
from risk.exposure import exposure_weight
from risk.propagation import hop_weight
from risk.quality import data_quality
from risk.temporal import recency_weight
from risk.temporal import exposure_classification
from signals.models import RiskSignal


def score_paths(paths: List[Dict[str, Any]], observed_through: datetime, coverage: float, requested_address_found: bool = True, config: RiskConfig = DEFAULT_CONFIG, signals: Optional[List[RiskSignal]] = None) -> Dict[str, Any]:
    evidence: List[Dict[str, Any]] = []
    grouped: Dict[str, List[float]] = {}
    dimension_groups: Dict[str, List[float]] = {"directThreat": [], "indirectExposure": [], "permissionExposure": [], "controlRisk": [], "behavioralAnomaly": []}
    for path in paths:
        terminal = path["source"]
        label = path["terminal_label"]
        intrinsic = config.intrinsic_risk.get(label, 0.0)
        edge_types = [edge["edge_type"] for edge in path["edges"]]
        values = [float(edge.get("value", 0.0)) for edge in path["edges"]]
        value = max(values, default=0.0)
        exposure = exposure_weight(value, config)
        timestamps = [edge.get("timestamp") for edge in path["edges"]]
        valid_timestamps = [timestamp for timestamp in timestamps if timestamp is not None]
        recency = min((recency_weight(timestamp, observed_through, config) for timestamp in valid_timestamps), default=0.0)
        edge_weight = sum(config.edge_weights.get(EdgeType(edge["edge_type"]), 0.0) for edge in path["edges"]) / len(edge_types)
        contribution = max(0.0, min(1.0, intrinsic * exposure * hop_weight(len(edge_types), config) * recency * edge_weight))
        reason = f"{label.replace('_', ' ')} source {terminal} is reachable in {len(edge_types)} hop(s) through {', '.join(edge_types)} with normalized exposure {exposure:.2f}."
        relationship = None
        if path["edges"]:
            first_edge = path["edges"][0]
            metadata = first_edge.get("metadata") or {}
            timestamp = first_edge.get("timestamp")
            relationship = {"txHash": metadata.get("transactionHash") or metadata.get("txHash"), "asset": metadata.get("asset") or metadata.get("token"), "value": first_edge.get("value", 0.0), "timestamp": timestamp.isoformat() if hasattr(timestamp, "isoformat") else timestamp, "source": first_edge.get("evidence_source")}
        ages = [exposure_classification(timestamp, observed_through, config) for timestamp in valid_timestamps]
        exposure_status = "UNKNOWN" if not ages else max(ages, key=lambda item: item[1] or 0.0)[0]
        age_days = max((age for _, age in ages if age is not None), default=None)
        item = {"path": path["nodes"], "sourceNode": terminal, "targetNode": path["nodes"][0], "hops": len(edge_types), "hopCount": len(edge_types), "edgeTypes": edge_types, "transferredValue": value, "exposure": exposure, "recency": recency, "recencyWeight": recency, "exposureStatus": exposure_status, "ageDays": age_days, "intrinsicRiskSource": label, "contribution": contribution, "relationship": relationship, "reason": reason}
        evidence.append(item)
        grouped.setdefault(terminal, []).append(contribution)
        dimension = "indirectExposure"
        if EdgeType.APPROVAL.value in edge_types:
            dimension = "permissionExposure"
        if EdgeType.OWNERSHIP_ADMIN.value in edge_types:
            dimension = "controlRisk"
        dimension_groups[dimension].append(contribution)
    signal_dimensions = {
        "confirmed_malicious": "directThreat",
        "high_risk": "directThreat",
        "suspicious": "directThreat",
        "normal_allowance": "permissionExposure",
        "large_allowance": "permissionExposure",
        "unlimited_allowance": "permissionExposure",
        "owner_control": "controlRisk",
        "admin_control": "controlRisk",
        "upgradeability": "controlRisk",
        "pause_capability": "controlRisk",
        "mint_capability": "controlRisk",
        "privileged_control": "controlRisk",
        "ownership_change": "controlRisk",
        "large_transfer_anomaly": "behavioralAnomaly",
        "activity_burst": "behavioralAnomaly",
        "new_contract_after_inactivity": "behavioralAnomaly",
    }
    for signal in signals or []:
        dimension = signal_dimensions.get(signal.signal_type)
        if dimension:
            dimension_groups[dimension].append(max(0.0, min(1.0, signal.severity)))
    dimensions = {name: aggregate_correlated(values, config) for name, values in dimension_groups.items()}
    quality = data_quality(coverage, requested_address_found, len(paths))
    dimensions["dataQuality"] = quality
    risk_component = sum(dimensions[name] * weight for name, weight in config.dimension_weights.items() if name != "dataQuality")
    weighted_score = risk_component * quality
    direct_threat_floor = dimensions["directThreat"] * quality
    overall = max(weighted_score, direct_threat_floor)
    return {"riskScore": max(0.0, min(1.0, overall)), "riskVector": dimensions, "evidence": sorted(evidence, key=lambda item: item["contribution"], reverse=True)}
