"""Somut CTI sağlayıcı implementasyonu.

OSINT toplama (aggregator) → LLM analizi (ollama_service) → risk skorlama
(risk_engine) zincirini çalıştırır ve sonucu `search_history` tablosuna
kalıcı olarak kaydeder. Aynı IOC kısa süre içinde tekrar sorgulanırsa
sonuç Redis önbelleğinden dönülür, zincir yeniden çalıştırılmaz.
"""

import logging

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from app.models.search_history import SearchHistory
from app.schemas.ioc import IOCAnalysisRequest, IOCAnalysisResponse
from app.services.aggregator import OSINTAggregator
from app.services.cache import AnalysisCache
from app.services.interfaces import ICTIProvider
from app.services.ollama_service import OllamaAnalysisService
from app.services.risk_engine import RiskEngine

logger = logging.getLogger(__name__)


class AggregatedCTIProvider(ICTIProvider):
    """OSINT + LLM + risk motorunu birleştiren, sonucu kalıcı kaydeden CTI sağlayıcı."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db
        self._aggregator = OSINTAggregator()
        self._llm_service = OllamaAnalysisService()
        self._risk_engine = RiskEngine()
        self._cache = AnalysisCache()

    async def lookup(self, request: IOCAnalysisRequest) -> IOCAnalysisResponse:
        cached = await self._cache.get(request.ioc_type.value, request.value)
        if cached is not None:
            logger.info("Önbellekten dönülüyor: %s (%s)", request.value, request.ioc_type)
            return IOCAnalysisResponse.model_validate(cached)

        logger.info("IOC sorgulanıyor: %s (%s)", request.value, request.ioc_type)

        osint_evidence = await self._aggregator.gather(request.value, request.ioc_type)
        llm_result = await self._llm_service.analyze(request.value, request.ioc_type, osint_evidence)
        risk_score, severity = await self._risk_engine.score(
            self._db, request.value, osint_evidence, llm_result.risk_score
        )

        response = IOCAnalysisResponse(
            value=request.value,
            ioc_type=request.ioc_type,
            risk_score=risk_score,
            severity=severity,
            llm_analysis=llm_result.threat_summary,
            recommended_actions=llm_result.recommended_actions,
            osint_evidence=osint_evidence,
        )

        await self._persist(response)
        await self._cache.set(request.ioc_type.value, request.value, response.model_dump(mode="json"))
        return response

    async def _persist(self, response: IOCAnalysisResponse) -> None:
        entry = SearchHistory(
            ioc_value=response.value,
            ioc_type=response.ioc_type,
            risk_score=response.risk_score,
            severity=response.severity,
            llm_summary=response.llm_analysis,
            osint_raw={
                "evidence": [item.model_dump(mode="json") for item in response.osint_evidence],
                "recommended_actions": response.recommended_actions,
            },
        )
        self._db.add(entry)
        await self._db.commit()


def get_cti_provider(db: AsyncSession = Depends(get_db_session)) -> ICTIProvider:
    """FastAPI dependency injection için factory fonksiyonu."""
    return AggregatedCTIProvider(db)
