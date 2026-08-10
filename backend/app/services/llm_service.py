"""Ollama (Qwen 2.5) üzerinden LLM zenginleştirme servisi."""

import logging

import httpx

from app.core.config import settings
from app.services.interfaces import ILLMEnrichmentService

logger = logging.getLogger(__name__)


class OllamaLLMService(ILLMEnrichmentService):
    """Ollama'nın /api/generate uç noktasını çağıran async istemci."""

    def __init__(self) -> None:
        self._base_url = settings.OLLAMA_BASE_URL
        self._model = settings.OLLAMA_MODEL
        self._timeout = settings.OLLAMA_REQUEST_TIMEOUT

    async def summarize(self, context: str) -> str:
        prompt = (
            "Sen bir Siber Tehdit İstihbaratı analistisin. Aşağıdaki teknik "
            "veriyi kısa, net ve aksiyon odaklı bir SOC raporuna dönüştür:\n\n"
            f"{context}"
        )

        async with httpx.AsyncClient(base_url=self._base_url, timeout=self._timeout) as client:
            try:
                response = await client.post(
                    "/api/generate",
                    json={"model": self._model, "prompt": prompt, "stream": False},
                )
                response.raise_for_status()
                data = response.json()
                return data.get("response", "").strip()
            except httpx.HTTPError as exc:
                logger.error("Ollama isteği başarısız: %s", exc)
                return "LLM servisi şu anda kullanılamıyor."


def get_llm_service() -> ILLMEnrichmentService:
    """FastAPI dependency injection için factory fonksiyonu."""
    return OllamaLLMService()
