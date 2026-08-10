"""
Servis Arayüzleri (Dependency Inversion Principle)
====================================================
Üst seviye modüller (API katmanı) somut sınıflara değil, bu soyut
arayüzlere bağımlı olur. Böylece yeni bir tehdit istihbaratı kaynağı
(ör. AbuseIPDB yerine Shodan) eklemek mevcut kodu değiştirmeyi gerektirmez
(Open/Closed Principle).
"""

from abc import ABC, abstractmethod

from app.schemas.ioc import IOCAnalysisRequest, IOCAnalysisResponse


class ICTIProvider(ABC):
    """Dış tehdit istihbaratı kaynaklarına erişim için soyut arayüz."""

    @abstractmethod
    async def lookup(self, request: IOCAnalysisRequest) -> IOCAnalysisResponse:
        """Bir IOC'yi sorgular ve normalize edilmiş bir sonuç döner."""
        raise NotImplementedError


class ILLMEnrichmentService(ABC):
    """LLM (Qwen 2.5 / Ollama) tabanlı analiz/raporlama zenginleştirme arayüzü."""

    @abstractmethod
    async def summarize(self, context: str) -> str:
        """Ham teknik veriyi analist-dostu bir özete dönüştürür."""
        raise NotImplementedError
