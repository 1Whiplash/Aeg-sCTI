"""IOC (Indicator of Compromise) analiz istek/yanıt şemaları."""

import ipaddress
from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.enums import IOCType, Severity
from app.schemas.geo import GeoLocation

__all__ = ["IOCType", "Severity", "IOCAnalysisRequest", "OSINTEvidence", "IOCAnalysisResponse"]

_HASH_LENGTHS = {32, 40, 64}  # MD5, SHA1, SHA256


class IOCAnalysisRequest(BaseModel):
    value: str = Field(
        ..., min_length=1, max_length=2048, description="Analiz edilecek gösterge (IP, domain, hash, url)"
    )
    ioc_type: IOCType

    @field_validator("value")
    @classmethod
    def strip_value(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Boş gösterge analiz edilemez.")
        return stripped

    @model_validator(mode="after")
    def validate_value_matches_type(self) -> "IOCAnalysisRequest":
        if self.ioc_type == IOCType.IP:
            try:
                ipaddress.ip_address(self.value)
            except ValueError as exc:
                raise ValueError("Geçerli bir IP adresi değil.") from exc
        elif self.ioc_type == IOCType.HASH:
            if len(self.value) not in _HASH_LENGTHS or not all(
                c in "0123456789abcdefABCDEF" for c in self.value
            ):
                raise ValueError("Geçerli bir MD5/SHA1/SHA256 hash'i değil.")
        elif self.ioc_type == IOCType.URL:
            if not self.value.startswith(("http://", "https://")):
                raise ValueError("URL, http:// veya https:// ile başlamalı.")
        elif self.ioc_type == IOCType.DOMAIN:
            if " " in self.value or "/" in self.value:
                raise ValueError("Geçerli bir domain adı değil.")
        return self


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
    exposed_services: list[str] = Field(
        default_factory=list,
        description="Shodan'a göre açık, yaygın olarak istismar edilen servisler (risk_score'u etkilemez)",
    )
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
