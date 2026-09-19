from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, field_validator


class RiskSignal(BaseModel):
    address: str
    signal_type: str
    severity: float = Field(ge=0.0, le=1.0)
    source: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    observed_at: Optional[datetime] = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    @field_validator("address")
    @classmethod
    def normalize_address(cls, value: str) -> str:
        value = value.strip().lower()
        if not value.startswith("0x") or len(value) != 42:
            raise ValueError("signal address must be a 42-character EVM address")
        int(value[2:], 16)
        return value

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: Optional[datetime]) -> Optional[datetime]:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
