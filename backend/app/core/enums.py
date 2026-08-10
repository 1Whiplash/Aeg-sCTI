"""Uygulama genelinde (hem ORM modelleri hem Pydantic şemaları) paylaşılan enum'lar."""

from enum import Enum


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def enum_values(enum_cls: type[Enum]) -> list[str]:
    """SQLAlchemy `Enum(..., values_callable=enum_values)` için — Postgres tarafında
    üye adı (`IP`) yerine değeri (`ip`) kullanılmasını sağlar."""
    return [member.value for member in enum_cls]
