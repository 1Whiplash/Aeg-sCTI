"""Somut CTI sağlayıcı implementasyonu (Faz 1: iskelet/stub).

Gerçek entegrasyonlar (VirusTotal, AbuseIPDB, Shodan, OTX, MISP) bu sınıf
içinde httpx.AsyncClient ile eklenecektir. Şimdilik Read-Only moda uygun
şekilde deterministik bir "unknown" yanıtı döner.
"""

import logging

from app.core.config import settings
from app.core.enums import Severity
from app.schemas.ioc import IOCAnalysisRequest, IOCAnalysisResponse
from app.services.interfaces import ICTIProvider

logger = logging.getLogger(__name__)


class AggregatedCTIProvider(ICTIProvider):
    """Birden fazla CTI kaynağını birleştiren agregatör servis."""

    def __init__(self) -> None:
        self._sources: list[str] = []
        if settings.VIRUSTOTAL_API_KEY:
            self._sources.append("virustotal")
        if settings.ABUSEIPDB_API_KEY:
            self._sources.append("abuseipdb")
        if settings.SHODAN_API_KEY:
            self._sources.append("shodan")
        if settings.OTX_API_KEY:
            self._sources.append("otx")

    async def lookup(self, request: IOCAnalysisRequest) -> IOCAnalysisResponse:
        logger.info("IOC sorgulanıyor: %s (%s)", request.value, request.ioc_type)

        if not self._sources:
            logger.warning("Hiçbir CTI API key'i tanımlı değil; stub yanıt dönülüyor.")

        return IOCAnalysisResponse(
            value=request.value,
            ioc_type=request.ioc_type,
            risk_score=0,
            severity=Severity.LOW,
            llm_analysis="Faz 1 iskelet yanıtı: gerçek kaynak entegrasyonu henüz eklenmedi.",
            osint_evidence=[],
        )


def get_cti_provider() -> ICTIProvider:
    """FastAPI dependency injection için factory fonksiyonu."""
    return AggregatedCTIProvider()
