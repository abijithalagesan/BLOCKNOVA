from config.constants import RiskConfig


def exposure_weight(value: float, config: RiskConfig) -> float:
    if value <= 0:
        return 0.0
    return min(1.0, value / config.exposure_reference_value)
