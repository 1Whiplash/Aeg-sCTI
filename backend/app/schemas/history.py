"""Geçmiş IOC sorgu kayıtlarının API yanıt şeması."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.core.enums import IOCType, Severity


class SearchHistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ioc_value: str
    ioc_type: IOCType
    risk_score: int
    severity: Severity
    llm_summary: str | None
    created_at: datetime
