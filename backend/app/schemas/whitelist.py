"""Whitelist (güvenli IOC listesi) istek/yanıt şemaları."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import IOCType


class WhitelistCreate(BaseModel):
    value: str = Field(..., description="Güvenli kabul edilen IP/domain")
    ioc_type: IOCType
    reason: str | None = Field(None, description="Neden güvenli kabul edildiği (örn. 'Google DNS')")


class WhitelistItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    value: str
    ioc_type: IOCType
    reason: str | None
    created_at: datetime
