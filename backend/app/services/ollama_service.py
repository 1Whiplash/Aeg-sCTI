"""Ollama (Qwen 2.5) üzerinden yapılandırılmış (structured output) SOC analiz servisi.

Model çıktısı, Ollama'nın `format` parametresine `LLMAnalysisResult`'ın JSON şeması
verilerek zorlanır — yani model şemaya uymayan bir metin üretemez.
"""

import logging

import httpx

from app.core.config import settings
from app.core.enums import IOCType
from app.schemas.ioc import OSINTEvidence
from app.schemas.llm import LLMAnalysisResult
from app.services.interfaces import ILLMEnrichmentService

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "Sen deneyimli bir SOC (Security Operations Center) analistisin. Sana bir tehdit "
    "göstergesi (IP, domain, hash veya URL) hakkında toplanmış ham OSINT verisi verilecek. "
    "Bu veriyi değerlendirip SADECE istenen JSON şemasına uyan bir çıktı üret. "
    "Ek açıklama, yorum veya markdown ekleme; sadece geçerli JSON döndür."
)

_FALLBACK_RESULT = LLMAnalysisResult(
    risk_score=0,
    threat_summary="LLM servisi şu anda kullanılamıyor.",
    recommended_actions=[],
)


class OllamaAnalysisService(ILLMEnrichmentService):
    """Ollama'nın /api/generate uç noktasını çağıran async istemci."""

    def __init__(self) -> None:
        self._base_url = settings.OLLAMA_BASE_URL
        self._model = settings.OLLAMA_MODEL
        self._timeout = settings.OLLAMA_REQUEST_TIMEOUT

    async def analyze(
        self, value: str, ioc_type: IOCType, osint_evidence: list[OSINTEvidence]
    ) -> LLMAnalysisResult:
        prompt = self._build_prompt(value, ioc_type, osint_evidence)

        payload = {
            "model": self._model,
            "system": _SYSTEM_PROMPT,
            "prompt": prompt,
            "stream": False,
            "format": LLMAnalysisResult.model_json_schema(),
        }

        async with httpx.AsyncClient(base_url=self._base_url, timeout=self._timeout) as client:
            try:
                response = await client.post("/api/generate", json=payload)
                response.raise_for_status()
                raw_output = response.json().get("response", "")
                return LLMAnalysisResult.model_validate_json(raw_output)
            except httpx.HTTPError as exc:
                logger.error("Ollama isteği başarısız: %s", exc)
                return _FALLBACK_RESULT
            except ValueError as exc:
                logger.error("Ollama çıktısı beklenen şemaya uymuyor: %s", exc)
                return _FALLBACK_RESULT

    @staticmethod
    def _build_prompt(value: str, ioc_type: IOCType, osint_evidence: list[OSINTEvidence]) -> str:
        evidence_json = [item.model_dump(mode="json") for item in osint_evidence]
        return (
            f"Gösterge: {value} (tip: {ioc_type.value})\n\n"
            f"Toplanan OSINT kanıtları:\n{evidence_json}"
        )


def get_llm_service() -> ILLMEnrichmentService:
    """FastAPI dependency injection için factory fonksiyonu."""
    return OllamaAnalysisService()
