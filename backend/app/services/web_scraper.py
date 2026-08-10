"""Fallback koleksiyoncu: API kaynaklarında kayıt bulunamayan domain/URL'ler için
canlı site başlığı, SSL sertifika yaşı ve WHOIS verisini kazır (Zero-Day şüphesi)."""

import asyncio
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

        await self._fetch_html(url, data)
        await asyncio.to_thread(self._fetch_whois, domain, data)
        await asyncio.to_thread(self._fetch_ssl_age, domain, data)

        return OSINTEvidence(source=self.source_name, raw_data=data)

    async def _fetch_html(self, url: str, data: dict) -> None:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
                response = await client.get(url)
                soup = BeautifulSoup(response.text, "html.parser")
                data["status_code"] = response.status_code
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
