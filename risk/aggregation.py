from typing import Dict, Iterable
from config.constants import RiskConfig


def aggregate_correlated(scores: Iterable[float], config: RiskConfig) -> float:
    ordered = sorted((max(0.0, min(1.0, score)) for score in scores), reverse=True)
    total = 0.0
    for index, score in enumerate(ordered):
        total += score * (config.correlation_decay ** index)
    return min(1.0, total)
