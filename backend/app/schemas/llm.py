"""Ollama/Qwen'in yapılandırılmış (structured output) analiz sonucu şeması."""

from pydantic import BaseModel, Field


class LLMAnalysisResult(BaseModel):
    risk_score: int = Field(ge=0, le=100, description="LLM'in OSINT kanıtlarına dayanarak verdiği risk skoru")
    threat_summary: str = Field(description="Analist-dostu, kısa ve aksiyon odaklı tehdit özeti")
    recommended_actions: list[str] = Field(default_factory=list, description="Önerilen SOC aksiyonları")
