"""Geçmiş IOC sorgularının kalıcı kaydı."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy import Enum as SAEnum
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import IOCType, Severity
from app.db.base import Base


class SearchHistory(Base):
    """Bir IOC analiz isteğinin ve sonucunun tam kaydı."""

    __tablename__ = "search_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc_value: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    ioc_type: Mapped[IOCType] = mapped_column(SAEnum(IOCType, name="ioc_type_enum"), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity, name="severity_enum"), nullable=False)
    llm_summary: Mapped[str | None] = mapped_column(String, nullable=True)
    osint_raw: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
