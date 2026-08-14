"""FortiGate SOAR istemcisi — Faz 1'de pasif (standby), açıldığında GERÇEKTEN engeller.

`FORTIGATE_AUTO_BLOCK_ENABLED` bayrağı açık olmadan hiçbir ağ isteği
göndermez — hiçbir yerden otomatik çağrılmaz, sadece admin onaylı manuel
`/api/v1/actions/block-ip` çağrısıyla tetiklenir.

Açıldığında sadece bir adres nesnesi OLUŞTURMAKLA kalmaz — trafiği gerçekten
kesmek için üç adımı idempotent şekilde garanti eder:
  1. IP için bir adres nesnesi (`firewall/address`)
  2. O nesneyi tek bir blocklist adres grubuna (`firewall/addrgrp`) ekleme
  3. Bu grubu kaynak/hedef olarak kullanan İKİ engelleme politikası
     (`firewall/policy`) — biri bu IP'den gelen trafiği, biri bu IP'ye giden
     trafiği keser. Politikalar sadece bir kez oluşturulur; sonraki her
     blokla işlemi sadece adres grubuna yeni bir üye ekler.

UYARI: `FORTIGATE_BLOCK_INTERFACE` cihazınızın gerçek arayüz/topoloji adına
göre ayarlanmalı (bkz. config.py). Bu kod bir test/lab FortiGate'e karşı
doğrulanmadan üretim cihazında etkinleştirilmemeli.
"""

import asyncio
import logging
from dataclasses import dataclass

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0

# _ensure_in_blocklist_group GET'le mevcut üyeleri okuyup PUT'la tam listeyi
# geri yazıyor (read-modify-write) — FortiOS API'sinde tekil üye ekleme/
# compare-and-swap yok. Bu yüzden aynı süreç içinde çakışan iki block_ip()
# çağrısı (örn. bir analist arka arkaya iki farklı IP'yi engellerse) birbirinin
# PUT'unu sessizce ezip bir üyeyi blocklist'ten düşürebilir. Modül seviyesinde
# tek bir lock, tüm block_ip() çağrılarını serileştirerek bunu engeller.
_block_lock = asyncio.Lock()


@dataclass
class BlockResult:
    """`block_ip()` sonucu. `partial=True`, policy adımından ÖNCEKİ adımların
    (adres + blocklist grubu üyeliği) FortiGate'te canlıya geçmiş olabileceği,
    ama iki yönlü deny policy'nin garanti edilemediği anlamına gelir — bu
    durumda cihaz "hiçbir şey olmadı" değil, "kısmen engellendi" durumundadır."""

    success: bool
    partial: bool = False


def _address_name(ip_address: str) -> str:
    return f"aegisci-block-{ip_address}"


class FortiGateService:
    """FortiOS REST API v2 üzerinden adres/grup/politika nesnelerini yönetir."""

    def __init__(self) -> None:
        self._base_url = settings.FORTIGATE_HOST
        self._token = settings.FORTIGATE_API_KEY

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base_url,
            timeout=_TIMEOUT,
            headers={"Authorization": f"Bearer {self._token}"},
            verify=settings.FORTIGATE_VERIFY_SSL,
        )

    async def block_ip(self, ip_address: str, comment: str = "AegisCTI otomatik engelleme") -> BlockResult:
        """IP'yi engeller: adres nesnesi + blocklist grubu + iki yönlü deny policy.

        `FORTIGATE_AUTO_BLOCK_ENABLED=False` (varsayılan) iken hiçbir ağ isteği
        göndermez, sadece loglar ve `BlockResult(success=False)` döner.
        """
        if not settings.FORTIGATE_AUTO_BLOCK_ENABLED:
            logger.info(
                "FortiGate otomatik engelleme devre dışı (FORTIGATE_AUTO_BLOCK_ENABLED=false); "
                "%s için istek gönderilmedi.",
                ip_address,
            )
            return BlockResult(success=False)

        if not self._base_url or not self._token:
            logger.error("FORTIGATE_HOST/FORTIGATE_API_KEY tanımlı değil, engelleme yapılamadı.")
            return BlockResult(success=False)

        async with _block_lock, self._client() as client:
            group_step_done = False
            try:
                await self._ensure_address_object(client, ip_address, comment)
                await self._ensure_in_blocklist_group(client, ip_address)
                group_step_done = True
                await self._ensure_block_policies(client)
            # KeyError/IndexError/TypeError: FortiGate 200 dönüp beklenmedik bir
            # JSON şekli (örn. boş "results") verirse _ensure_in_blocklist_group'un
            # sözlük/liste erişimleri patlar — bu bir httpx.HTTPError değildir ama
            # aynı şekilde "istek başarısız" sayılıp False dönülmeli, ham exception
            # olarak /actions/block-ip'den 500 sızdırılmamalı.
            except (httpx.HTTPError, KeyError, IndexError, TypeError) as exc:
                logger.error("FortiGate isteği başarısız (%s): %s", ip_address, exc)
                if group_step_done:
                    logger.error(
                        "FortiGate: %s zaten '%s' blocklist grubuna eklenmiş olabilir "
                        "(policy adımı başarısız oldu) — cihazı MANUEL kontrol edin, "
                        "kısmi engelleme durumu oluşmuş olabilir.",
                        ip_address,
                        settings.FORTIGATE_ADDRESS_GROUP_NAME,
                    )
                return BlockResult(success=False, partial=group_step_done)

        logger.warning(
            "FortiGate: %s adresi '%s' blocklist grubuna eklendi (policy: %s / %s).",
            ip_address,
            settings.FORTIGATE_ADDRESS_GROUP_NAME,
            settings.FORTIGATE_POLICY_INBOUND_NAME,
            settings.FORTIGATE_POLICY_OUTBOUND_NAME,
        )
        return BlockResult(success=True)

    async def _ensure_address_object(self, client: httpx.AsyncClient, ip_address: str, comment: str) -> None:
        name = _address_name(ip_address)
        existing = await client.get(f"/api/v2/cmdb/firewall/address/{name}")
        if existing.status_code == 200:
            return  # zaten var, tekrar oluşturmaya gerek yok
        response = await client.post(
            "/api/v2/cmdb/firewall/address",
            json={"name": name, "subnet": f"{ip_address}/32", "comment": comment},
        )
        response.raise_for_status()

    async def _ensure_in_blocklist_group(self, client: httpx.AsyncClient, ip_address: str) -> None:
        name = _address_name(ip_address)
        group = settings.FORTIGATE_ADDRESS_GROUP_NAME

        existing = await client.get(f"/api/v2/cmdb/firewall/addrgrp/{group}")
        if existing.status_code == 404:
            response = await client.post(
                "/api/v2/cmdb/firewall/addrgrp",
                json={"name": group, "member": [{"name": name}]},
            )
            response.raise_for_status()
            return

        existing.raise_for_status()
        current_members = [m["name"] for m in existing.json()["results"][0].get("member", [])]
        if name in current_members:
            return  # zaten grupta

        response = await client.put(
            f"/api/v2/cmdb/firewall/addrgrp/{group}",
            json={"member": [{"name": m} for m in [*current_members, name]]},
        )
        response.raise_for_status()

    async def _ensure_block_policies(self, client: httpx.AsyncClient) -> None:
        group_ref = [{"name": settings.FORTIGATE_ADDRESS_GROUP_NAME}]
        all_ref = [{"name": "all"}]
        intf_ref = [{"name": settings.FORTIGATE_BLOCK_INTERFACE}]

        policies = [
            (settings.FORTIGATE_POLICY_INBOUND_NAME, group_ref, all_ref),  # blocklist'ten gelen her şey
            (settings.FORTIGATE_POLICY_OUTBOUND_NAME, all_ref, group_ref),  # blocklist'e giden her şey
        ]
        for policy_name, srcaddr, dstaddr in policies:
            existing = await client.get(
                "/api/v2/cmdb/firewall/policy", params={"filter": f"name=={policy_name}"}
            )
            existing.raise_for_status()
            if existing.json().get("results"):
                continue  # policy zaten var, üyeler zaten grup üzerinden güncel

            response = await client.post(
                "/api/v2/cmdb/firewall/policy",
                json={
                    "name": policy_name,
                    "srcintf": intf_ref,
                    "dstintf": intf_ref,
                    "srcaddr": srcaddr,
                    "dstaddr": dstaddr,
                    "action": "deny",
                    "schedule": "always",
                    "service": [{"name": "ALL"}],
                    "logtraffic": "all",
                    "status": "enable",
                    "comments": "AegisCTI tarafından otomatik oluşturuldu — blocklist grubuna referans verir.",
                },
            )
            response.raise_for_status()
