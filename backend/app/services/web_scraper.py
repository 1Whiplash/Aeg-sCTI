"""Fallback koleksiyoncu: API kaynaklarında kayıt bulunamayan domain/URL'ler için
canlı site başlığı, SSL sertifika yaşı ve WHOIS verisini kazır (Zero-Day şüphesi).

GÜVENLİK: Bu sınıf, kullanıcının verdiği bir değere sunucu tarafından canlı ağ
isteği atar — kontrolsüz bırakılırsa SSRF'e (Server-Side Request Forgery) açık
olur (örn. `169.254.169.254` bulut metadata adresi ya da `192.168.x.x` gibi bir
iç ağ adresi verilip backend'in bunlara istek atması sağlanabilir). Bu yüzden
istek atmadan önce hostname'in çözümlendiği IP'lerin özel/iç ağ/loopback
aralığında olmadığı doğrulanır; ayrıca yönlendirmeler (redirect) otomatik takip
edilmez, çünkü dışarıdan zararsız görünen bir adres bile yönlendirmeyle iç ağa
çekilebilir.
"""

import asyncio
import ipaddress
import logging
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
import whois
from bs4 import BeautifulSoup

from app.core.enums import IOCType
from app.schemas.ioc import OSINTEvidence
from app.services.base_collector import BaseCollector

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0
_SKIP_REASON = "Gösterge özel/iç ağ adresine çözümlendiği için güvenlik nedeniyle taranmadı."


class WebScraperCollector(BaseCollector):
    source_name = "web_scraper"

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in (IOCType.DOMAIN, IOCType.URL)

    async def collect(self, value: str, ioc_type: IOCType) -> OSINTEvidence | None:
        if not self.supports(ioc_type):
            return None

        domain = urlparse(value).netloc or value
        url = value if value.startswith(("http://", "https://")) else f"http://{value}"
        data: dict = {}

        is_public = await asyncio.to_thread(self._is_public_hostname, domain)
        if not is_public:
            logger.warning("SSRF önlemi: '%s' özel/iç ağ adresine çözümleniyor, taranmadı.", domain)
            data["skipped_reason"] = _SKIP_REASON
            return OSINTEvidence(source=self.source_name, raw_data=data)

        await self._fetch_html(url, data)
        await asyncio.to_thread(self._fetch_whois, domain, data)
        await asyncio.to_thread(self._fetch_ssl_age, domain, data)

        return OSINTEvidence(source=self.source_name, raw_data=data)

    @staticmethod
    def _is_public_hostname(hostname: str) -> bool:
        """Hostname'in çözümlendiği TÜM IP'lerin genel (public) internet adresi
        olduğunu doğrular — özel/loopback/link-local/rezerve aralıklardan biri
        bile bulunursa False döner (DNS-rebinding'e karşı da geçerli)."""
        try:
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            return False

        resolved_ips = {info[4][0] for info in infos}
        if not resolved_ips:
            return False

        for ip_str in resolved_ips:
            try:
                ip = ipaddress.ip_address(ip_str.split("%")[0])
            except ValueError:
                return False
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False

        return True

    async def _fetch_html(self, url: str, data: dict) -> None:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False) as client:
                response = await client.get(url)
                data["status_code"] = response.status_code
                if response.is_redirect:
                    data["redirect_location"] = response.headers.get("location")
                    return
                soup = BeautifulSoup(response.text, "html.parser")
                data["page_title"] = soup.title.get_text(strip=True) if soup.title else None
        except httpx.HTTPError as exc:
            logger.warning("Sayfa taranamadı (%s): %s", url, exc)
            data["fetch_error"] = str(exc)

    @staticmethod
    def _fetch_whois(domain: str, data: dict) -> None:
        try:
            record = whois.whois(domain)
            data["whois_registrar"] = record.registrar
            data["whois_creation_date"] = str(record.creation_date)
        except Exception as exc:  # kütüphane çok çeşitli exception tipleri fırlatabiliyor
            logger.warning("WHOIS sorgusu başarısız (%s): %s", domain, exc)
            data["whois_error"] = str(exc)

    @staticmethod
    def _fetch_ssl_age(domain: str, data: dict) -> None:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            data["ssl_cert_age_days"] = (datetime.now(timezone.utc) - not_before).days
        except Exception as exc:
            logger.warning("SSL sertifikası okunamadı (%s): %s", domain, exc)
            data["ssl_error"] = str(exc)
