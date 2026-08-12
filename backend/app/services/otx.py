"""AlienVault OTX (Open Threat Exchange) entegrasyonu.

Shodan ve AbuseIPDB'nin aksine (sadece IP), OTX IP/domain/URL/hash'in
hepsini destekliyor — bu yüzden domain/hash analizinde VirusTotal'ın
yanında ikinci gerçek bir kaynak olarak devreye giriyor.
"""

import logging

import httpx

from app.core.config import settings
from app.core.enums import IOCType
from app.schemas.ioc import OSINTEvidence
from app.services.base_collector import BaseCollector

logger = logging.getLogger(__name__)

_BASE_URL = "https://otx.alienvault.com/api/v1"
_TIMEOUT = 10.0

_SECTION_BY_TYPE = {
    IOCType.IP: "IPv4",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
    IOCType.HASH: "file",
}


class OTXCollector(BaseCollector):
    source_name = "otx"

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in _SECTION_BY_TYPE

    async def collect(self, value: str, ioc_type: IOCType) -> OSINTEvidence | None:
        if not settings.OTX_API_KEY or not self.supports(ioc_type):
            return None

        section = _SECTION_BY_TYPE[ioc_type]
        headers = {"X-OTX-API-KEY": settings.OTX_API_KEY}

        async with httpx.AsyncClient(base_url=_BASE_URL, timeout=_TIMEOUT, headers=headers) as client:
            try:
                response = await client.get(f"/indicators/{section}/{value}/general")
                response.raise_for_status()
                return OSINTEvidence(source=self.source_name, raw_data=response.json())
            except httpx.HTTPError as exc:
                logger.warning("OTX isteği başarısız: %s", exc)
                return OSINTEvidence(source=self.source_name, raw_data={"error": str(exc)})
