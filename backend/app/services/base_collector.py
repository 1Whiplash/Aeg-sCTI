"""Tüm OSINT koleksiyoncuları için soyut arayüz."""

from abc import ABC, abstractmethod

import httpx

from app.core.enums import IOCType
from app.schemas.ioc import OSINTEvidence


class BaseCollector(ABC):
    """Tek bir dış kaynaktan (VirusTotal, Shodan, web scraper vb.) veri toplayan birim."""

    source_name: str

    @abstractmethod
    def supports(self, ioc_type: IOCType) -> bool:
        """Bu koleksiyoncunun verilen IOC tipi için anlamlı olup olmadığını bildirir."""
        raise NotImplementedError

    @abstractmethod
    async def collect(self, value: str, ioc_type: IOCType) -> OSINTEvidence | None:
        """IOC'yi sorgular.

        Kaynak devre dışıysa (API key yok) veya `ioc_type` desteklenmiyorsa `None` döner.
        Kaynağa ulaşılamazsa exception fırlatmaz; hatayı `raw_data={"error": ...}` içinde taşır.
        """
        raise NotImplementedError

    @staticmethod
    def safe_error_message(exc: Exception) -> str:
        """Hata mesajını kullanıcıya güvenli hale getirir.

        httpx'in varsayılan hata mesajları, isteğin tam URL'sini (bazı kaynaklarda
        API key query parametresi olarak URL'nin içinde olabiliyor) içerir. Bu mesaj
        doğrudan ekrana/PDF'e yazıldığı için ham `str(exc)` ASLA kullanılmamalı —
        sadece durum koduna dayanan, sızıntı riski taşımayan bir özet döneriz.
        """
        if isinstance(exc, httpx.HTTPStatusError):
            return f"HTTP {exc.response.status_code} hatası"
        if isinstance(exc, httpx.TimeoutException):
            return "İstek zaman aşımına uğradı"
        if isinstance(exc, httpx.HTTPError):
            return "Ağ isteği başarısız oldu"
        return "Bilinmeyen hata"
