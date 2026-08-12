"""IOC (Indicator of Compromise) analiz istek/yanıt şemaları."""

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from app.core.enums import IOCType, Severity
from app.schemas.geo import GeoLocation

__all__ = ["IOCType", "Severity", "IOCAnalysisRequest", "OSINTEvidence", "IOCAnalysisResponse"]


class IOCAnalysisRequest(BaseModel):
    value: str = Field(..., description="Analiz edilecek gösterge (IP, domain, hash, url)")
    ioc_type: IOCType


class OSINTEvidence(BaseModel):
    """Tek bir OSINT kaynağından (VirusTotal, AbuseIPDB, Shodan vb.) dönen ham kanıt."""

    source: str
    raw_data: dict = Field(default_factory=dict)


class IOCAnalysisResponse(BaseModel):
    value: str
    ioc_type: IOCType
    risk_score: int = Field(ge=0, le=100, description="0-100 arası hesaplanmış risk skoru")
    severity: Severity
    llm_analysis: str | None = None
    recommended_actions: list[str] = Field(default_factory=list, description="LLM'in önerdiği SOC aksiyon planı")
    osint_evidence: list[OSINTEvidence] = Field(default_factory=list)
    geo: GeoLocation | None = Field(None, description="Gösterge IP ise coğrafi konumu (varsa)")
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
