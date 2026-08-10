"""Pasif (standby) FortiGate SOAR istemcisi.

Faz 1'de sistem salt-okunur çalışır; bu servis `FORTIGATE_AUTO_BLOCK_ENABLED`
bayrağı açık olmadan hiçbir isteği FortiGate'e göndermez — hiçbir yerden
otomatik çağrılmaz, ileride manuel/onaylı bir aksiyon akışına bağlanmak
üzere hazır bekler.
"""

import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0


class FortiGateService:
    """FortiOS REST API üzerinden adres nesnesi oluşturarak IP engelleme."""

    def __init__(self) -> None:
        self._base_url = settings.FORTIGATE_HOST
        self._token = settings.FORTIGATE_API_KEY

    async def block_ip(self, ip_address: str, comment: str = "AegisCTI otomatik engelleme") -> bool:
        """Belirtilen IP'yi FortiGate adres nesnesi olarak ekler.

        `FORTIGATE_AUTO_BLOCK_ENABLED=False` (varsayılan) iken hiçbir ağ isteği
        göndermez, sadece loglar ve `False` döner.
        """
        if not settings.FORTIGATE_AUTO_BLOCK_ENABLED:
            logger.info(
                "FortiGate otomatik engelleme devre dışı (FORTIGATE_AUTO_BLOCK_ENABLED=false); "
                "%s için istek gönderilmedi.",
                ip_address,
            )
            return False

        if not self._base_url or not self._token:
            logger.error("FORTIGATE_HOST/FORTIGATE_API_KEY tanımlı değil, engelleme yapılamadı.")
            return False

        payload = {
            "name": f"aegisci-block-{ip_address}",
            "subnet": f"{ip_address}/32",
            "comment": comment,
        }
        headers = {"Authorization": f"Bearer {self._token}"}

        async with httpx.AsyncClient(
            base_url=self._base_url,
            timeout=_TIMEOUT,
            headers=headers,
            verify=settings.FORTIGATE_VERIFY_SSL,
        ) as client:
            try:
                response = await client.post("/api/v2/cmdb/firewall/address", json=payload)
                response.raise_for_status()
                logger.warning("FortiGate: %s adresi engellendi.", ip_address)
                return True
            except httpx.HTTPError as exc:
                logger.error("FortiGate isteği başarısız: %s", exc)
                return False
