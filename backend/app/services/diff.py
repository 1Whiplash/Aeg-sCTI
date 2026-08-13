"""İki analiz kaydı arasındaki değişimi DETERMİNİSTİK olarak hesaplar.

Bilinçli tasarım kararı: bu karşılaştırmayı LLM'e yazdırmıyoruz. Küçük
modelin (Qwen 2.5 7B) nüanslı talimatları güvenilir takip etmediği daha
önce gözlemlendi (bkz. ollama_service.py'deki üçüncü taraf öneri notu).
Risk skoru farkı, severity geçişi, yeni/kaybolan açık servis gibi somut
karşılaştırmalar için LLM'e ihtiyaç yok — doğrudan koddan, her zaman aynı
girdiyle aynı çıktıyı üreten bir hesaplama yeterli ve daha güvenilir.
"""

from dataclasses import dataclass
from datetime import datetime

from app.core.enums import Severity
from app.schemas.bookmark import BookmarkDiff
from app.schemas.ioc import OSINTEvidence
from app.services.exposure import extract_exposed_services


@dataclass
class HistorySnapshot:
    risk_score: int
    severity: Severity
    osint_evidence: list[OSINTEvidence]
    created_at: datetime


def _extract_vt_malicious_count(evidence: list[OSINTEvidence]) -> int | None:
    for item in evidence:
        if item.source != "virustotal":
            continue
        stats = ((item.raw_data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats")
        if isinstance(stats, dict) and "malicious" in stats:
            return stats["malicious"]
        return None
    return None


def compute_diff(current: HistorySnapshot, previous: HistorySnapshot | None) -> BookmarkDiff:
    """`previous` yoksa (ilk kontrol) sadece `is_first_check=True` döner."""
    if previous is None:
        return BookmarkDiff(is_first_check=True)

    current_services = set(extract_exposed_services(current.osint_evidence))
    previous_services = set(extract_exposed_services(previous.osint_evidence))

    current_vt = _extract_vt_malicious_count(current.osint_evidence)
    previous_vt = _extract_vt_malicious_count(previous.osint_evidence)
    vt_delta = (
        current_vt - previous_vt if current_vt is not None and previous_vt is not None else None
    )

    return BookmarkDiff(
        is_first_check=False,
        previous_risk_score=previous.risk_score,
        previous_severity=previous.severity,
        previous_checked_at=previous.created_at,
        risk_score_delta=current.risk_score - previous.risk_score,
        severity_changed=current.severity != previous.severity,
        new_exposed_services=sorted(current_services - previous_services),
        removed_exposed_services=sorted(previous_services - current_services),
        virustotal_malicious_delta=vt_delta,
    )
