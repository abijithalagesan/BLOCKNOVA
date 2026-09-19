from config.constants import RiskConfig


def hop_weight(hops: int, config: RiskConfig) -> float:
    return config.hop_decay ** max(0, hops - 1)
