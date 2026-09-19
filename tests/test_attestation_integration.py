from datetime import datetime, timedelta, timezone
from analyzer import analyze_address
from proof.attestation import LocalAttestation, LocalRegistry, LocalVault, RejectReason, payload_from_result


def test_analysis_merkle_registry_vault_flow_high_and_low():
    now = datetime.now(timezone.utc)
    registry = LocalRegistry("blocknova-issuer")
    vault = LocalVault(registry, "blocknova-schema-v1", "blocknova-issuer", max_risk=0.5)
    high_result = analyze_address("0x1111111111111111111111111111111111111111")
    high_result = dict(high_result)
    high_result["riskScore"] = 0.8
    high_payload = payload_from_result(high_result, "1.0", "blocknova-schema-v1", now, now + timedelta(days=30))
    registry.register(LocalAttestation("high-uid", "blocknova-issuer", high_payload), "blocknova-issuer")
    assert len(high_result["evidenceRoot"]) == 64
    assert vault.can_interact(high_payload.subject, now) == RejectReason.RISK_TOO_HIGH
    low_result = analyze_address("0x4444444444444444444444444444444444444444")
    low_payload = payload_from_result(low_result, "1.0", "blocknova-schema-v1", now, now + timedelta(days=30))
    registry.register(LocalAttestation("low-uid", "blocknova-issuer", low_payload), "blocknova-issuer")
    assert vault.can_interact(low_payload.subject, now) == RejectReason.ALLOWED
