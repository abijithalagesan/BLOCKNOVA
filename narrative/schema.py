from typing import List
from pydantic import BaseModel


class Narrative(BaseModel):
    explanation: str
    limitations: List[str]
