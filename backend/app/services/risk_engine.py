"""OSINT kanıtlarını ve LLM skorunu ağırlıklı formülle nihai risk skoruna dönüştürür.

Skor = (AbuseIPDB × 0.35) + (VirusTotal × 0.35) + (LLM Skor × 0.30)

Girdi Whitelist tablosundaysa (bilinen güvenli IP/domain) skor doğrudan 0'dır.
"""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Severity
from app.models.whitelist import Whitelist
from app.schemas.ioc import OSINTEvidence

logger = logging.getLogger(__name__)

_ABUSEIPDB_WEIGHT = 0.35
_VIRUSTOTAL_WEIGHT = 0.35
_LLM_WEIGHT = 0.30

_CRITICAL_THRESHOLD = 80
_HIGH_THRESHOLD = 50
_MEDIUM_THRESHOLD = 20


class RiskEngine:
    async def score(
        self,
        db: AsyncSession,
        value: str,
        osint_evidence: list[OSINTEvidence],
        llm_score: int,
    ) -> tuple[int, Severity]:
        if await self._is_whitelisted(db, value):
            return 0, Severity.LOW

        abuseipdb_score = self._extract_abuseipdb_score(osint_evidence)
        virustotal_score = self._extract_virustotal_score(osint_evidence)

        weighted = (
            abuseipdb_score * _ABUSEIPDB_WEIGHT
            + virustotal_score * _VIRUSTOTAL_WEIGHT
            + llm_score * _LLM_WEIGHT
        )
        final_score = round(min(max(weighted, 0.0), 100.0))
        return final_score, self._severity_for(final_score)

    @staticmethod
    async def _is_whitelisted(db: AsyncSession, value: str) -> bool:
        result = await db.execute(select(Whitelist.id).where(Whitelist.value == value))
        return result.scalar_one_or_none() is not None

    @staticmethod
    def _extract_abuseipdb_score(evidence: list[OSINTEvidence]) -> float:
        for item in evidence:
            if item.source != "abuseipdb":
                continue
            try:
                return float(item.raw_data["data"]["abuseConfidenceScore"])
            except (KeyError, TypeError, ValueError):
                logger.warning("AbuseIPDB verisi beklenen formatta değil, 0 kabul edildi.")
        return 0.0

    @staticmethod
    def _extract_virustotal_score(evidence: list[OSINTEvidence]) -> float:
        for item in evidence:
            if item.source != "virustotal":
                continue
            try:
                stats = item.raw_data["data"]["attributes"]["last_analysis_stats"]
                total = sum(stats.values())
                if total == 0:
                    return 0.0
                malicious_weight = stats.get("malicious", 0) + stats.get("suspicious", 0) * 0.5
                return (malicious_weight / total) * 100
            except (KeyError, TypeError, ValueError):
                logger.warning("VirusTotal verisi beklenen formatta değil, 0 kabul edildi.")
        return 0.0

    @staticmethod
    def _severity_for(score: int) -> Severity:
        if score >= _CRITICAL_THRESHOLD:
            return Severity.CRITICAL
        if score >= _HIGH_THRESHOLD:
            return Severity.HIGH
        if score >= _MEDIUM_THRESHOLD:
            return Severity.MEDIUM
        return Severity.LOW
