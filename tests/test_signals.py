from datetime import datetime, timedelta, timezone
from analyzer import analyze_address
from signals.aggregation import aggregate_signals, intrinsic_label
from signals.allowance import detect_allowance_risk
from signals.anomaly import detect_behavioral_anomalies
from signals.contract_control import detect_contract_control
from signals.direct_flags import detect_direct_flags
from signals.models import RiskSignal
from risk.scoring import score_paths
from collectors.goplus import SecuritySignal
from graph.builder import build_collected_graph, build_graph
from config.constants import DEFAULT_CONFIG
from risk.temporal import exposure_classification

ADDRESS = "0x1111111111111111111111111111111111111111"


def test_confirmed_malicious_direct_flag():
    signals = detect_direct_flags(ADDRESS, {"is_phishing": "1"}, source="goplus")
    assert signals[0].signal_type == "confirmed_malicious"
    assert signals[0].severity == 1.0
    assert signals[0].evidence["flag"] == "is_phishing"


def test_goplus_signal_is_attached_to_graph_node_with_provider_evidence():
    provider = SecuritySignal(ADDRESS, "confirmed_malicious", "goplus", {"is_phishing": "1", "provider_case": "case-7"})
    signals = detect_direct_flags(ADDRESS, provider)
    graph_data = build_collected_graph(ADDRESS, [], signals, coverage=1.0)
    graph = build_graph(graph_data)
    node = graph.nodes[ADDRESS]
    assert node["intrinsic_risk_label"] == "confirmed_malicious"
    assert node["risk_signals"][0]["source"] == "goplus"
    assert node["risk_signals"][0]["evidence"]["provider_flags"]["provider_case"] == "case-7"


def test_duplicate_goplus_flags_preserve_strongest_evidence():
    first = detect_direct_flags(ADDRESS, SecuritySignal(ADDRESS, "confirmed_malicious", "goplus", {"is_phishing": "1", "case": "same"}))
    second = detect_direct_flags(ADDRESS, SecuritySignal(ADDRESS, "confirmed_malicious", "goplus", {"is_phishing": "1", "case": "same"}))
    result = aggregate_signals(first + second)
    assert len(result) == 1
    assert result[0].source == "goplus"
    assert result[0].evidence["provider_flags"]["case"] == "same"


def test_allowance_distinguishes_normal_large_unlimited_and_none():
    assert detect_allowance_risk(ADDRESS, None) == []
    assert detect_allowance_risk(ADDRESS, {"allowance": 0}) == []
    assert detect_allowance_risk(ADDRESS, {"allowance": 100})[0].signal_type == "normal_allowance"
    assert detect_allowance_risk(ADDRESS, {"allowance": 10**25})[0].signal_type == "large_allowance"
    unlimited = detect_allowance_risk(ADDRESS, {"allowance": 2**256 - 1})[0]
    assert unlimited.signal_type == "unlimited_allowance"
    assert unlimited.signal_type != "confirmed_malicious"


def test_privileged_contract_produces_evidence_signal():
    signals = detect_contract_control(ADDRESS, {"admin": ADDRESS, "upgradeable": True, "source": "bytecode_analysis"})
    assert {signal.signal_type for signal in signals} == {"admin_control", "upgradeability"}
    assert all(signal.evidence["contract"] == ADDRESS for signal in signals)


def test_large_transfer_anomaly_is_deterministic():
    now = datetime.now(timezone.utc)
    records = [
        {"value": 1.0, "timestamp": now - timedelta(days=5), "metadata": {"asset": "ETH"}},
        {"value": 1.0, "timestamp": now - timedelta(days=4), "metadata": {"asset": "ETH"}},
        {"value": 1.0, "timestamp": now - timedelta(days=3), "metadata": {"asset": "ETH"}},
        {"value": 1.0, "timestamp": now - timedelta(days=2), "metadata": {"asset": "ETH"}},
        {"value": 1.0, "timestamp": now - timedelta(days=1), "metadata": {"asset": "ETH"}},
        {"value": 100.0, "timestamp": now, "metadata": {"transactionHash": "0xoutlier", "asset": "ETH"}},
    ]
    signals = detect_behavioral_anomalies(ADDRESS, records)
    assert signals[0].signal_type == "large_transfer_anomaly"
    assert signals[0].evidence["baseline_median"] == 1.0
    assert signals[0].evidence["deviation_multiplier"] == 100.0
    assert signals[0].evidence["transaction_hash"] == "0xoutlier"


def test_normal_historical_variation_is_not_anomalous():
    now = datetime.now(timezone.utc)
    records = [{"value": value, "timestamp": now - timedelta(days=offset)} for offset, value in enumerate((1.0, 1.1, 0.9, 1.2, 1.4, 2.0), start=1)]
    assert detect_behavioral_anomalies(ADDRESS, records) == []


def test_insufficient_history_is_not_anomalous():
    now = datetime.now(timezone.utc)
    records = [{"value": 1.0, "timestamp": now - timedelta(days=1)}, {"value": 100.0, "timestamp": now}]
    assert detect_behavioral_anomalies(ADDRESS, records) == []


def test_missing_data_is_not_anomalous():
    assert detect_behavioral_anomalies(ADDRESS, [{"value": 100.0}, {"value": 1.0}]) == []


def test_clean_address_has_no_signals():
    assert detect_direct_flags(ADDRESS, {}) == []
    assert detect_allowance_risk(ADDRESS, {}) == []
    assert detect_contract_control(ADDRESS, {}) == []
    assert detect_behavioral_anomalies(ADDRESS, []) == []


def test_missing_provider_data_is_not_a_risk_signal():
    assert detect_direct_flags(ADDRESS, None, source="missing_provider") == []


def test_duplicate_signals_are_deduplicated():
    signal = RiskSignal(address=ADDRESS, signal_type="confirmed_malicious", severity=1.0, source="goplus", evidence={"flag": "is_phishing", "event_id": "same"})
    duplicate = signal.model_copy(update={"severity": 0.4, "source": "forta"})
    result = aggregate_signals([signal, duplicate])
    assert len(result) == 1
    assert result[0].severity == 1.0


def test_multiple_signals_preserve_evidence_and_intrinsic_label():
    direct = RiskSignal(address=ADDRESS, signal_type="confirmed_malicious", severity=1.0, source="goplus", evidence={"flag": "is_phishing"})
    allowance = RiskSignal(address=ADDRESS, signal_type="unlimited_allowance", severity=0.8, source="allowance", evidence={"token": "token"})
    result = aggregate_signals([direct, allowance])
    assert len(result) == 2
    assert intrinsic_label(result) == "confirmed_malicious"
    assert {signal.evidence.keys().__contains__("flag") for signal in result} == {True, False}


def test_sample_result_identifies_the_signal_causing_intrinsic_risk():
    result = analyze_address(ADDRESS)
    assert result["signals"][0]["signal_type"] == "confirmed_malicious"
    assert result["topEvidence"][0]["intrinsicRiskSource"] == "confirmed_malicious"


def test_anomaly_signal_contributes_to_behavioral_dimension():
    signal = RiskSignal(address=ADDRESS, signal_type="large_transfer_anomaly", severity=0.965, source="behavioral_rules", evidence={"value": 19.3})
    result = score_paths([], datetime.now(timezone.utc), 1.0, signals=[signal])
    assert result["riskVector"]["behavioralAnomaly"] > 0.0


def test_unlimited_allowance_contributes_to_permission_dimension():
    signal = RiskSignal(address=ADDRESS, signal_type="unlimited_allowance", severity=0.8, source="alchemy_rpc", evidence={"allowance": "max"})
    result = score_paths([], datetime.now(timezone.utc), 1.0, signals=[signal])
    assert result["riskVector"]["permissionExposure"] > 0.0


def test_privileged_control_contributes_to_control_dimension():
    signal = RiskSignal(address=ADDRESS, signal_type="privileged_control", severity=0.6, source="contract_control", evidence={"field": "admin"})
    result = score_paths([], datetime.now(timezone.utc), 1.0, signals=[signal])
    assert result["riskVector"]["controlRisk"] > 0.0


def test_confirmed_malicious_target_is_not_diluted():
    signal = RiskSignal(address=ADDRESS, signal_type="confirmed_malicious", severity=1.0, source="goplus", evidence={"flag": "stealing_attack"})
    result = score_paths([], datetime.now(timezone.utc), 1.0, signals=[signal])
    assert result["riskVector"]["directThreat"] == 1.0
    assert result["riskScore"] == 1.0


def test_clean_target_has_zero_score():
    result = score_paths([], datetime.now(timezone.utc), 1.0, signals=[])
    assert result["riskScore"] == 0.0


def test_anomaly_only_target_stays_below_direct_threat():
    signal = RiskSignal(address=ADDRESS, signal_type="large_transfer_anomaly", severity=1.0, source="behavioral_rules", evidence={"value": 100.0})
    result = score_paths([], datetime.now(timezone.utc), 1.0, signals=[signal])
    assert result["riskVector"]["behavioralAnomaly"] == 1.0
    assert result["riskScore"] == 0.1


def test_indirect_exposure_target_uses_path_contribution():
    now = datetime.now(timezone.utc)
    path = [{"nodes": [ADDRESS, "0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333"], "edges": [{"edge_type": "transfer", "value": 10.0, "timestamp": now}, {"edge_type": "token_transfer", "value": 10.0, "timestamp": now}], "source": "0x3333333333333333333333333333333333333333", "terminal_label": "confirmed_malicious"}]
    result = score_paths(path, now, 1.0)
    assert result["riskVector"]["indirectExposure"] > 0.0
    assert result["riskVector"]["directThreat"] == 0.0


def test_malicious_and_anomaly_keeps_direct_evidence_dominant():
    signals = [
        RiskSignal(address=ADDRESS, signal_type="confirmed_malicious", severity=1.0, source="goplus", evidence={"flag": "stealing_attack"}),
        RiskSignal(address=ADDRESS, signal_type="large_transfer_anomaly", severity=1.0, source="behavioral_rules", evidence={"value": 100.0}),
    ]
    result = score_paths([], datetime.now(timezone.utc), 1.0, signals=signals)
    assert result["riskScore"] == 1.0
    assert result["riskVector"]["directThreat"] > result["riskVector"]["behavioralAnomaly"] - 0.01


def test_relationship_evidence_is_preserved_in_propagated_path():
    now = datetime.now(timezone.utc)
    seed = "0x3333333333333333333333333333333333333333"
    signal = RiskSignal(address=seed, signal_type="confirmed_malicious", severity=1.0, source="goplus", evidence={"flag": "stealing_attack"})
    path = [{"nodes": [ADDRESS, seed], "edges": [{"edge_type": "transfer", "value": 2.0, "timestamp": now, "evidence_source": "alchemy_seed_enrichment", "metadata": {"transactionHash": "0xrelationship", "asset": "ETH"}}], "source": seed, "terminal_label": "confirmed_malicious"}]
    result = score_paths(path, now, 1.0, signals=[signal])
    evidence = result["evidence"][0]
    assert result["riskVector"]["indirectExposure"] > 0.0
    assert evidence["relationship"]["txHash"] == "0xrelationship"
    assert evidence["relationship"]["source"] == "alchemy_seed_enrichment"


def test_exposure_status_active_at_ten_days():
    observed = datetime(2026, 9, 20, tzinfo=timezone.utc)
    status, age = exposure_classification(observed - timedelta(days=10), observed, DEFAULT_CONFIG)
    assert status == "ACTIVE"
    assert age == 10.0


def test_exposure_status_historical_at_one_hundred_days():
    observed = datetime(2026, 9, 20, tzinfo=timezone.utc)
    status, age = exposure_classification(observed - timedelta(days=100), observed, DEFAULT_CONFIG)
    assert status == "HISTORICAL"
    assert age == 100.0


def test_exposure_status_dormant_at_two_years():
    observed = datetime(2026, 9, 20, tzinfo=timezone.utc)
    status, age = exposure_classification(observed - timedelta(days=730), observed, DEFAULT_CONFIG)
    assert status == "DORMANT"
    assert age == 730.0


def test_exposure_status_boundaries():
    observed = datetime(2026, 9, 20, tzinfo=timezone.utc)
    assert exposure_classification(observed - timedelta(days=30), observed, DEFAULT_CONFIG)[0] == "ACTIVE"
    assert exposure_classification(observed - timedelta(days=31), observed, DEFAULT_CONFIG)[0] == "HISTORICAL"
    assert exposure_classification(observed - timedelta(days=365), observed, DEFAULT_CONFIG)[0] == "HISTORICAL"
    assert exposure_classification(observed - timedelta(days=366), observed, DEFAULT_CONFIG)[0] == "DORMANT"


def test_missing_timestamp_is_unknown():
    observed = datetime(2026, 9, 20, tzinfo=timezone.utc)
    assert exposure_classification(None, observed, DEFAULT_CONFIG) == ("UNKNOWN", None)
