"""Analistin isimlendirerek takibe aldığı IOC'ler (izleme listesi)."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy import Enum as SAEnum
from sqlalchemy import func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import IOCType, enum_values
from app.db.base import Base


class Bookmark(Base):
    """Tekrar tekrar kontrol edilmek istenen, isimlendirilmiş bir gösterge."""

    __tablename__ = "bookmarks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[str] = mapped_column(String(512), unique=True, index=True, nullable=False)
    ioc_type: Mapped[IOCType] = mapped_column(
        SAEnum(IOCType, name="ioc_type_enum", values_callable=enum_values), nullable=False
    )
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    notes: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
