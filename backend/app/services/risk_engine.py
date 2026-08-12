"""OSINT kanıtlarını ve LLM skorunu ağırlıklı formülle nihai risk skoruna dönüştürür.

Skor = (AbuseIPDB × 0.35) + (VirusTotal × 0.35) + (LLM Skor × 0.30)

Bir kaynaktan hiç veri gelmemişse (API key tanımlı değil, kaynak bu IOC tipini
desteklemiyor vb.) o kaynak formülden tamamen çıkarılır ve kalan kaynakların
ağırlıkları toplamı 1'e tamamlayacak şekilde ORANTISAL olarak yeniden dağıtılır.
Aksi halde (eski davranış) eksik kaynaklar sessizce "0 risk" sayılıp ağırlıklarını
formülde tutardı — bu da örn. sadece LLM'in mevcut olduğu durumlarda skorun asla
%30'u (LLM ağırlığı) geçememesine, yani gerçekten zararlı bir gösterge için bile
LLM ne kadar emin olursa olsun "düşük risk" çıkmasına yol açıyordu.

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

        # LLM her zaman mevcuttur (analiz her durumda çalışır); diğer iki kaynak
        # sadece gerçekten veri döndüyse dahil edilir.
        components: list[tuple[float, float]] = [(llm_score, _LLM_WEIGHT)]
        if abuseipdb_score is not None:
            components.append((abuseipdb_score, _ABUSEIPDB_WEIGHT))
        if virustotal_score is not None:
            components.append((virustotal_score, _VIRUSTOTAL_WEIGHT))

        total_weight = sum(weight for _, weight in components)
        weighted_sum = sum(score * weight for score, weight in components)
        final_score = round(min(max(weighted_sum / total_weight, 0.0), 100.0))
        return final_score, self._severity_for(final_score)

    @staticmethod
    async def _is_whitelisted(db: AsyncSession, value: str) -> bool:
        # Whitelist kayıtları küçük harfle saklanıyor (bkz. whitelist.py); domain'ler
        # DNS gereği büyük/küçük harf duyarsız olduğu için karşılaştırma da öyle olmalı.
        result = await db.execute(
            select(Whitelist.id).where(Whitelist.value == value.strip().lower())
        )
        return result.scalar_one_or_none() is not None

    @staticmethod
    def _extract_abuseipdb_score(evidence: list[OSINTEvidence]) -> float | None:
        """AbuseIPDB kanıtı yoksa `None` döner (formülden tamamen çıkarılır)."""
        for item in evidence:
            if item.source != "abuseipdb":
                continue
            try:
                return float(item.raw_data["data"]["abuseConfidenceScore"])
            except (KeyError, TypeError, ValueError):
                logger.warning("AbuseIPDB verisi beklenen formatta değil, kaynak göz ardı edildi.")
                return None
        return None

    @staticmethod
    def _extract_virustotal_score(evidence: list[OSINTEvidence]) -> float | None:
        """VirusTotal kanıtı yoksa `None` döner (formülden tamamen çıkarılır)."""
        for item in evidence:
            if item.source != "virustotal":
                continue
            try:
                stats = item.raw_data["data"]["attributes"]["last_analysis_stats"]
                total = sum(stats.values())
                if total == 0:
                    return None
                malicious_weight = stats.get("malicious", 0) + stats.get("suspicious", 0) * 0.5
                return (malicious_weight / total) * 100
            except (KeyError, TypeError, ValueError):
                logger.warning("VirusTotal verisi beklenen formatta değil, kaynak göz ardı edildi.")
                return None
        return None

    @staticmethod
    def _severity_for(score: int) -> Severity:
        if score >= _CRITICAL_THRESHOLD:
            return Severity.CRITICAL
        if score >= _HIGH_THRESHOLD:
            return Severity.HIGH
        if score >= _MEDIUM_THRESHOLD:
            return Severity.MEDIUM
        return Severity.LOW
