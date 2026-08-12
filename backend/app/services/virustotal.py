"""VirusTotal API v3 entegrasyonu."""

import base64
import logging

import httpx

from app.core.config import settings
from app.core.enums import IOCType
from app.schemas.ioc import OSINTEvidence
from app.services.base_collector import BaseCollector

logger = logging.getLogger(__name__)

_BASE_URL = "https://www.virustotal.com/api/v3"
_TIMEOUT = 10.0

_ENDPOINT_BY_TYPE = {
    IOCType.IP: "/ip_addresses/{value}",
    IOCType.DOMAIN: "/domains/{value}",
    IOCType.HASH: "/files/{value}",
}


class VirusTotalCollector(BaseCollector):
    source_name = "virustotal"

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in (IOCType.IP, IOCType.DOMAIN, IOCType.URL, IOCType.HASH)

    async def collect(self, value: str, ioc_type: IOCType) -> OSINTEvidence | None:
        if not settings.VIRUSTOTAL_API_KEY:
            return None

        path = self._resolve_path(value, ioc_type)
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

        async with httpx.AsyncClient(base_url=_BASE_URL, timeout=_TIMEOUT, headers=headers) as client:
            try:
                response = await client.get(path)
                response.raise_for_status()
                return OSINTEvidence(source=self.source_name, raw_data=response.json())
            except httpx.HTTPError as exc:
                logger.warning("VirusTotal isteği başarısız: %s", exc)
                return OSINTEvidence(
                    source=self.source_name, raw_data={"error": self.safe_error_message(exc)}
                )

    @staticmethod
    def _resolve_path(value: str, ioc_type: IOCType) -> str:
        if ioc_type == IOCType.URL:
            url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            return f"/urls/{url_id}"
        return _ENDPOINT_BY_TYPE[ioc_type].format(value=value)
