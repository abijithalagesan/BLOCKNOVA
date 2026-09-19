from datetime import datetime, timedelta, timezone
from proof.attestation import AttestationPayload, AttestationStatus, LocalAttestation, LocalRegistry, LocalVault, RejectReason, attestation_status


SUBJECT = "0x1111111111111111111111111111111111111111"


def payload(risk=0.1, quality=0.9, observed=None, expires=None, schema="schema-v1"):
    observed = observed or datetime(2026, 9, 20, tzinfo=timezone.utc)
    expires = expires or observed + timedelta(days=30)
    return AttestationPayload(SUBJECT, "1.0", risk, 0.0, 0.0, 0.0, quality, "a" * 64, observed, expires, schema)


def test_high_risk_rejects_and_low_risk_allows():
    registry = LocalRegistry("issuer")
    vault = LocalVault(registry, "schema-v1", "issuer", max_risk=0.5)
    registry.register(LocalAttestation("high", "issuer", payload(risk=0.8)), "issuer")
    assert vault.can_interact(SUBJECT, datetime(2026, 9, 21, tzinfo=timezone.utc)) == RejectReason.RISK_TOO_HIGH
    registry.register(LocalAttestation("low", "issuer", payload(risk=0.1)), "issuer")
    assert vault.can_interact(SUBJECT, datetime(2026, 9, 21, tzinfo=timezone.utc)) == RejectReason.ALLOWED


def test_registry_trust_rotation_and_validation_reasons():
    registry = LocalRegistry("issuer")
    vault = LocalVault(registry, "schema-v1", "issuer")
    assert vault.can_interact(SUBJECT) == RejectReason.NO_ATTESTATION
    registry.register(LocalAttestation("uid", "issuer", payload()), "issuer")
    assert vault.can_interact(SUBJECT, datetime(2026, 9, 21, tzinfo=timezone.utc)) == RejectReason.ALLOWED
    registry.attestations["uid"].payload = payload(schema="wrong")
    assert vault.can_interact(SUBJECT) == RejectReason.WRONG_SCHEMA


def test_revoked_expired_stale_and_low_quality():
    now = datetime(2026, 9, 20, tzinfo=timezone.utc)
    registry = LocalRegistry("issuer")
    vault = LocalVault(registry, "schema-v1", "issuer", max_age_days=30)
    attestation = LocalAttestation("uid", "issuer", payload(observed=now - timedelta(days=31), expires=now + timedelta(days=30)), False)
    registry.register(attestation, "issuer")
    assert vault.can_interact(SUBJECT, now) == RejectReason.STALE
    attestation.payload = payload(expires=now - timedelta(days=1))
    assert vault.can_interact(SUBJECT, now) == RejectReason.EXPIRED
    attestation.payload = payload()
    attestation.revoked = True
    assert vault.can_interact(SUBJECT, now) == RejectReason.REVOKED
    attestation.revoked = False
    attestation.payload = payload(quality=0.1)
    assert vault.can_interact(SUBJECT, now) == RejectReason.DATA_QUALITY_TOO_LOW


def test_attestation_statuses():
    now = datetime(2026, 9, 20, tzinfo=timezone.utc)
    current = LocalAttestation("current", "issuer", payload())
    stale = LocalAttestation("stale", "issuer", payload(observed=now - timedelta(days=31), expires=now + timedelta(days=30)))
    expired = LocalAttestation("expired", "issuer", payload(expires=now - timedelta(seconds=1)))
    revoked = LocalAttestation("revoked", "issuer", payload(), True)
    assert attestation_status(current, now) == AttestationStatus.CURRENT
    assert attestation_status(stale, now) == AttestationStatus.STALE
    assert attestation_status(expired, now) == AttestationStatus.EXPIRED
    assert attestation_status(revoked, now) == AttestationStatus.REVOKED
