"""
Servis Arayüzleri (Dependency Inversion Principle)
====================================================
Üst seviye modüller (API katmanı) somut sınıflara değil, bu soyut
arayüzlere bağımlı olur. Böylece yeni bir tehdit istihbaratı kaynağı
(ör. AbuseIPDB yerine Shodan) eklemek mevcut kodu değiştirmeyi gerektirmez
(Open/Closed Principle).
"""

from abc import ABC, abstractmethod

from app.core.enums import IOCType
from app.schemas.ioc import IOCAnalysisRequest, IOCAnalysisResponse, OSINTEvidence
from app.schemas.llm import LLMAnalysisResult


class ICTIProvider(ABC):
    """Dış tehdit istihbaratı kaynaklarına erişim için soyut arayüz."""

    @abstractmethod
    async def lookup(self, request: IOCAnalysisRequest) -> IOCAnalysisResponse:
        """Bir IOC'yi sorgular ve normalize edilmiş bir sonuç döner."""
        raise NotImplementedError


class ILLMEnrichmentService(ABC):
    """LLM (Qwen 2.5 / Ollama) tabanlı yapılandırılmış analiz arayüzü."""

    @abstractmethod
    async def analyze(
        self, value: str, ioc_type: IOCType, osint_evidence: list[OSINTEvidence]
    ) -> LLMAnalysisResult:
        """Ham OSINT kanıtlarını, şemaya uygun (structured) bir SOC analizine dönüştürür."""
        raise NotImplementedError
