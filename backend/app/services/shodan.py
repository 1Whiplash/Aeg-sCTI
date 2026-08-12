"""Shodan API entegrasyonu — açık portlar ve banner bilgisi (sadece IP tipi IOC'ler için)."""

import logging

import httpx

from app.core.config import settings
from app.core.enums import IOCType
from app.schemas.ioc import OSINTEvidence
from app.services.base_collector import BaseCollector

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.shodan.io"
_TIMEOUT = 10.0


class ShodanCollector(BaseCollector):
    source_name = "shodan"

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type == IOCType.IP

    async def collect(self, value: str, ioc_type: IOCType) -> OSINTEvidence | None:
        if not settings.SHODAN_API_KEY or not self.supports(ioc_type):
            return None

        async with httpx.AsyncClient(base_url=_BASE_URL, timeout=_TIMEOUT) as client:
            try:
                response = await client.get(
                    f"/shodan/host/{value}",
                    params={"key": settings.SHODAN_API_KEY},
                )
                response.raise_for_status()
                return OSINTEvidence(source=self.source_name, raw_data=response.json())
            except httpx.HTTPError as exc:
                logger.warning("Shodan isteği başarısız: %s", exc)
                return OSINTEvidence(
                    source=self.source_name, raw_data={"error": self.safe_error_message(exc)}
                )
