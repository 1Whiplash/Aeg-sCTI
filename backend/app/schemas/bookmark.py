"""Bookmark (izleme listesi) istek/yanıt şemaları."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import IOCType, Severity
from app.schemas.ioc import IOCAnalysisResponse


class BookmarkCreate(BaseModel):
    value: str = Field(..., min_length=1, max_length=512, description="Takip edilecek gösterge")
    ioc_type: IOCType
    display_name: str = Field(..., min_length=1, max_length=255, description="Analistin verdiği isim")
    notes: str | None = Field(None, max_length=1000)


class BookmarkItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    value: str
    ioc_type: IOCType
    display_name: str
    notes: str | None
    created_at: datetime


class BookmarkDiff(BaseModel):
    """İki analiz arasındaki değişimin deterministik özeti (LLM'e dayanmaz)."""

    is_first_check: bool
    previous_risk_score: int | None = None
    previous_severity: Severity | None = None
    previous_checked_at: datetime | None = None
    risk_score_delta: int | None = None
    severity_changed: bool = False
    new_exposed_services: list[str] = Field(default_factory=list)
    removed_exposed_services: list[str] = Field(default_factory=list)
    virustotal_malicious_delta: int | None = None


class BookmarkRecheckResponse(BaseModel):
    analysis: IOCAnalysisResponse
    diff: BookmarkDiff
