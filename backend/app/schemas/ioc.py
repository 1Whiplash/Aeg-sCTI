"""IOC (Indicator of Compromise) analiz istek/yanıt şemaları."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class IOCAnalysisRequest(BaseModel):
    value: str = Field(..., description="Analiz edilecek gösterge (IP, domain, hash, url)")
    ioc_type: IOCType


class IOCVerdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class IOCAnalysisResponse(BaseModel):
    value: str
    ioc_type: IOCType
    verdict: IOCVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    sources: list[str] = Field(default_factory=list)
    summary: str | None = None
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
