from dataclasses import dataclass, field
from enum import Enum
from typing import Dict


class EdgeType(str, Enum):
    TRANSFER = "transfer"
    TOKEN_TRANSFER = "token_transfer"
    APPROVAL = "approval"
    CONTRACT_INTERACTION = "contract_interaction"
    OWNERSHIP_ADMIN = "ownership_admin"


@dataclass(frozen=True)
class RiskConfig:
    intrinsic_risk: Dict[str, float] = field(default_factory=lambda: {
        "confirmed_malicious": 1.0,
        "high_risk": 0.7,
        "suspicious": 0.4,
        "clean": 0.0,
        "unknown": 0.0,
    })
    exposure_reference_value: float = 10.0
    hop_decay: float = 0.72
    recency_half_life_days: float = 180.0
    active_exposure_max_days: float = 30.0
    historical_exposure_max_days: float = 365.0
    edge_weights: Dict[EdgeType, float] = field(default_factory=lambda: {
        EdgeType.TRANSFER: 1.0,
        EdgeType.TOKEN_TRANSFER: 0.9,
        EdgeType.APPROVAL: 0.8,
        EdgeType.CONTRACT_INTERACTION: 0.7,
        EdgeType.OWNERSHIP_ADMIN: 1.1,
    })
    dimension_weights: Dict[str, float] = field(default_factory=lambda: {
        "directThreat": 0.25,
        "indirectExposure": 0.30,
        "permissionExposure": 0.15,
        "controlRisk": 0.15,
        "behavioralAnomaly": 0.10,
        "dataQuality": 0.05,
    })
    risk_level_thresholds: Dict[str, float] = field(default_factory=lambda: {
        "CRITICAL": 0.75,
        "HIGH": 0.50,
        "ELEVATED": 0.10,
    })
    max_hops: int = 3
    correlation_decay: float = 0.55
    evidence_version: str = "1.0"
    attestation_validity_days: int = 30


DEFAULT_CONFIG = RiskConfig()
