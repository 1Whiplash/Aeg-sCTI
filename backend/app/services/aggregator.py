"""Tüm OSINT koleksiyoncularını paralel çalıştırıp tek bir kanıt listesinde birleştiren orkestratör."""

import asyncio
import logging

from app.core.enums import IOCType
from app.schemas.ioc import OSINTEvidence
from app.services.abuseipdb import AbuseIPDBCollector
from app.services.base_collector import BaseCollector
from app.services.shodan import ShodanCollector
from app.services.virustotal import VirusTotalCollector
from app.services.web_scraper import WebScraperCollector

logger = logging.getLogger(__name__)


class OSINTAggregator:
    """API tabanlı koleksiyoncuları paralel çalıştırır; hiçbiri sonuç dönmezse web scraper'a düşer."""

    def __init__(self, api_collectors: list[BaseCollector] | None = None) -> None:
        self._api_collectors: list[BaseCollector] = api_collectors or [
            VirusTotalCollector(),
            AbuseIPDBCollector(),
            ShodanCollector(),
        ]
        self._scraper = WebScraperCollector()

    async def gather(self, value: str, ioc_type: IOCType) -> list[OSINTEvidence]:
        applicable = [c for c in self._api_collectors if c.supports(ioc_type)]

        results = await asyncio.gather(*(self._safe_collect(c, value, ioc_type) for c in applicable))
        evidence = [item for item in results if item is not None]

        if not evidence and self._scraper.supports(ioc_type):
            fallback = await self._safe_collect(self._scraper, value, ioc_type)
            if fallback is not None:
                evidence.append(fallback)

        return evidence

    @staticmethod
    async def _safe_collect(
        collector: BaseCollector, value: str, ioc_type: IOCType
    ) -> OSINTEvidence | None:
        try:
            return await collector.collect(value, ioc_type)
        except Exception:
            logger.exception("%s koleksiyoncusu beklenmedik şekilde çöktü", collector.source_name)
            return OSINTEvidence(source=collector.source_name, raw_data={"error": "beklenmedik hata"})
