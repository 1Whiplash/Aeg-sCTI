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
