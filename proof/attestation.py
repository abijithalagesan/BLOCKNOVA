from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional


class RejectReason(str, Enum):
    NO_ATTESTATION = "NO_ATTESTATION"
    WRONG_SCHEMA = "WRONG_SCHEMA"
    WRONG_ISSUER = "WRONG_ISSUER"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    STALE = "STALE"
    RISK_TOO_HIGH = "RISK_TOO_HIGH"
    DATA_QUALITY_TOO_LOW = "DATA_QUALITY_TOO_LOW"
    ALLOWED = "ALLOWED"


class AttestationStatus(str, Enum):
    CURRENT = "CURRENT"
    STALE = "STALE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


@dataclass(frozen=True)
class AttestationPayload:
    subject: str
    version: str
    risk_score: float
    direct_threat_score: float
    exposure_score: float
    permission_exposure_score: float
    data_quality: float
    evidence_root: str
    observed_through: datetime
    expires_at: datetime
    schema_uid: str


def payload_from_result(result: Dict[str, object], version: str, schema_uid: str, observed_through: datetime, expires_at: datetime) -> AttestationPayload:
    vector = result["riskVector"]
    return AttestationPayload(
        subject=str(result["address"]).lower(),
        version=version,
        risk_score=float(result["riskScore"]),
        direct_threat_score=float(vector["directThreat"]),
        exposure_score=float(vector["indirectExposure"]),
        permission_exposure_score=float(vector["permissionExposure"]),
        data_quality=float(result["dataQuality"]),
        evidence_root=str(result["evidenceRoot"]),
        observed_through=observed_through,
        expires_at=expires_at,
        schema_uid=schema_uid,
    )


@dataclass
class LocalAttestation:
    uid: str
    issuer: str
    payload: AttestationPayload
    revoked: bool = False


class LocalRegistry:
    def __init__(self, trusted_issuer: str) -> None:
        self.trusted_issuer = trusted_issuer
        self.latest_by_subject: Dict[str, str] = {}
        self.attestations: Dict[str, LocalAttestation] = {}

    def register(self, attestation: LocalAttestation, issuer: str) -> None:
        if issuer != self.trusted_issuer:
            raise PermissionError("only trusted issuer can register attestations")
        self.attestations[attestation.uid] = attestation
        self.latest_by_subject[attestation.payload.subject.lower()] = attestation.uid

    def rotate_issuer(self, new_issuer: str, caller: str) -> None:
        if caller != self.trusted_issuer:
            raise PermissionError("only current issuer can rotate issuer")
        self.trusted_issuer = new_issuer

    def latest(self, subject: str) -> Optional[LocalAttestation]:
        uid = self.latest_by_subject.get(subject.lower())
        return self.attestations.get(uid) if uid else None


class LocalVault:
    def __init__(self, registry: LocalRegistry, schema_uid: str, trusted_issuer: str, max_risk: float = 0.5, min_data_quality: float = 0.5, max_age_days: int = 30) -> None:
        self.registry = registry
        self.schema_uid = schema_uid
        self.trusted_issuer = trusted_issuer
        self.max_risk = max_risk
        self.min_data_quality = min_data_quality
        self.max_age_days = max_age_days

    def can_interact(self, subject: str, now: Optional[datetime] = None) -> RejectReason:
        attestation = self.registry.latest(subject)
        if attestation is None:
            return RejectReason.NO_ATTESTATION
        if attestation.payload.schema_uid != self.schema_uid:
            return RejectReason.WRONG_SCHEMA
        if attestation.issuer != self.trusted_issuer:
            return RejectReason.WRONG_ISSUER
        if attestation.revoked:
            return RejectReason.REVOKED
        current = now or datetime.now(timezone.utc)
        if current >= attestation.payload.expires_at:
            return RejectReason.EXPIRED
        if (current - attestation.payload.observed_through).total_seconds() > self.max_age_days * 86400:
            return RejectReason.STALE
        if attestation.payload.risk_score > self.max_risk:
            return RejectReason.RISK_TOO_HIGH
        if attestation.payload.data_quality < self.min_data_quality:
            return RejectReason.DATA_QUALITY_TOO_LOW
        return RejectReason.ALLOWED


def attestation_status(attestation: LocalAttestation, now: Optional[datetime] = None, max_age_days: int = 30) -> AttestationStatus:
    if attestation.revoked:
        return AttestationStatus.REVOKED
    current = now or datetime.now(timezone.utc)
    if current >= attestation.payload.expires_at:
        return AttestationStatus.EXPIRED
    if (current - attestation.payload.observed_through).total_seconds() > max_age_days * 86400:
        return AttestationStatus.STALE
    return AttestationStatus.CURRENT
