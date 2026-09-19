from config.constants import DEFAULT_CONFIG
from risk.aggregation import aggregate_correlated
from risk.exposure import exposure_weight
from risk.propagation import hop_weight


def test_risk_weights_are_bounded_and_decay():
    assert exposure_weight(100000, DEFAULT_CONFIG) == 1.0
    assert hop_weight(2, DEFAULT_CONFIG) < hop_weight(1, DEFAULT_CONFIG)
    assert 0.0 <= aggregate_correlated([1.0, 1.0, 1.0], DEFAULT_CONFIG) <= 1.0
