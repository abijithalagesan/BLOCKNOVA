from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
from config.constants import EdgeType
from signals.models import RiskSignal


class Node(BaseModel):
    address: str
    kind: str = "wallet"
    intrinsic_risk_label: str = "unknown"
    risk_source: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("address")
    @classmethod
    def normalize_address(cls, value: str) -> str:
        value = value.strip().lower()
        if not value.startswith("0x") or len(value) != 42:
            raise ValueError("address must be a 42-character EVM address")
        int(value[2:], 16)
        return value


class Edge(BaseModel):
    source: str
    target: str
    edge_type: EdgeType
    value: float = 0.0
    timestamp: datetime
    evidence_source: str = "local_sample"
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("source", "target")
    @classmethod
    def normalize_address(cls, value: str) -> str:
        value = value.strip().lower()
        if not value.startswith("0x") or len(value) != 42:
            raise ValueError("edge endpoint must be a 42-character EVM address")
        int(value[2:], 16)
        return value

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class GraphData(BaseModel):
    nodes: List[Node]
    edges: List[Edge]
    observed_through: datetime
    coverage: float = Field(ge=0.0, le=1.0)
    coverage_details: Dict[str, float] = Field(default_factory=dict)
    signals: List[RiskSignal] = Field(default_factory=list)
