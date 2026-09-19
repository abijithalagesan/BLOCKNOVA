from datetime import datetime, timezone
from math import exp, log
from typing import Optional, Tuple
from config.constants import RiskConfig


def recency_weight(timestamp: datetime, observed_through: datetime, config: RiskConfig) -> float:
    age_days = max(0.0, (observed_through - timestamp).total_seconds() / 86400)
    return exp(-log(2) * age_days / config.recency_half_life_days)

def exposure_classification(timestamp: Optional[datetime], observed_through: datetime, config: RiskConfig) -> Tuple[str, Optional[float]]:
    if timestamp is None or observed_through is None:
        return "UNKNOWN", None
    age_days = max(0.0, (observed_through - timestamp).total_seconds() / 86400)
    if age_days <= config.active_exposure_max_days:
        return "ACTIVE", age_days
    if age_days <= config.historical_exposure_max_days:
        return "HISTORICAL", age_days
    return "DORMANT", age_days
