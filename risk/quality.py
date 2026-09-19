from typing import Optional


def data_quality(coverage: float, requested_address_found: bool, path_count: int) -> float:
    quality = coverage
    if not requested_address_found:
        quality *= 0.5
    if path_count == 0 and coverage < 1.0:
        quality *= 0.95
    return max(0.0, min(1.0, quality))
