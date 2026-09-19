from typing import Any, Dict
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
from analyzer import analyze_address

router = APIRouter()


class AnalyzeRequest(BaseModel):
    address: str
    chain: str = "ethereum"
    live: bool = False

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized.startswith("0x") or len(normalized) != 42:
            raise ValueError("address must be a 42-character EVM address")
        int(normalized[2:], 16)
        return normalized

    @field_validator("chain")
    @classmethod
    def validate_chain(cls, value: str) -> str:
        if value.lower() != "ethereum":
            raise ValueError("Phase 1 local data supports ethereum only")
        return value.lower()


@router.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "phase": "1-local-deterministic"}


@router.post("/analyze")
def analyze(request: AnalyzeRequest) -> Dict[str, Any]:
    try:
        return analyze_address(request.address, live=request.live)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
