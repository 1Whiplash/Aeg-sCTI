"""AbuseIPDB v2 API entegrasyonu (sadece IP tipi IOC'ler için)."""

import logging

import httpx

from app.core.config import settings
from app.core.enums import IOCType
from app.schemas.ioc import OSINTEvidence
from app.services.base_collector import BaseCollector

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.abuseipdb.com/api/v2"
_TIMEOUT = 10.0


class AbuseIPDBCollector(BaseCollector):
    source_name = "abuseipdb"

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type == IOCType.IP

    async def collect(self, value: str, ioc_type: IOCType) -> OSINTEvidence | None:
        if not settings.ABUSEIPDB_API_KEY or not self.supports(ioc_type):
            return None

        headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
        # verbose: aggregate skorun yanında bireysel rapor kategorilerini
        # (örn. "Brute-Force", "DDoS Attack") de döndürür — motor/kaynak
        # bazlı doğrulama görünümü için kullanılıyor (reporter kimliği
        # AbuseIPDB tarafından anonimleştirildiği için o bilgi yok).
        params = {"ipAddress": value, "maxAgeInDays": 90, "verbose": "true"}

        async with httpx.AsyncClient(base_url=_BASE_URL, timeout=_TIMEOUT, headers=headers) as client:
            try:
                response = await client.get("/check", params=params)
                response.raise_for_status()
                return OSINTEvidence(source=self.source_name, raw_data=response.json())
            except httpx.HTTPError as exc:
                logger.warning("AbuseIPDB isteği başarısız: %s", exc)
                return OSINTEvidence(
                    source=self.source_name, raw_data={"error": self.safe_error_message(exc)}
                )
