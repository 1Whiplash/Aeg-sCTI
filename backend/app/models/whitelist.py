"""Yanlış alarmı (False Positive) engellemek için güvenli IOC listesi."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy import Enum as SAEnum
from sqlalchemy import func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import IOCType
from app.db.base import Base


class Whitelist(Base):
    """Cloudflare, Google DNS gibi bilinen güvenli IP/domain kayıtları."""

    __tablename__ = "whitelist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[str] = mapped_column(String(512), unique=True, index=True, nullable=False)
    ioc_type: Mapped[IOCType] = mapped_column(SAEnum(IOCType, name="ioc_type_enum"), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
