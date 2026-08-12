"""risk_engine.py'deki ağırlıklı skor formülü için birim testleri."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.enums import Severity
from app.schemas.ioc import OSINTEvidence
from app.services.risk_engine import RiskEngine


def _db_mock(whitelisted: bool = False) -> AsyncMock:
    result = MagicMock()
    result.scalar_one_or_none.return_value = "some-id" if whitelisted else None
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    return db


def _vt_evidence(malicious: int, suspicious: int, harmless: int, undetected: int) -> OSINTEvidence:
    return OSINTEvidence(
        source="virustotal",
        raw_data={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected,
                    }
                }
            }
        },
    )


def _abuseipdb_evidence(score: float) -> OSINTEvidence:
    return OSINTEvidence(source="abuseipdb", raw_data={"data": {"abuseConfidenceScore": score}})


class TestSeverityThresholds:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0, Severity.LOW),
            (19, Severity.LOW),
            (20, Severity.MEDIUM),
            (49, Severity.MEDIUM),
            (50, Severity.HIGH),
            (79, Severity.HIGH),
            (80, Severity.CRITICAL),
            (100, Severity.CRITICAL),
        ],
    )
    def test_boundaries(self, score, expected):
        assert RiskEngine._severity_for(score) == expected


class TestExtractAbuseIPDBScore:
    def test_valid(self):
        evidence = [_abuseipdb_evidence(75)]
        assert RiskEngine._extract_abuseipdb_score(evidence) == 75.0

    def test_missing_source(self):
        assert RiskEngine._extract_abuseipdb_score([]) is None

    def test_malformed_data(self):
        evidence = [OSINTEvidence(source="abuseipdb", raw_data={"unexpected": "shape"})]
        assert RiskEngine._extract_abuseipdb_score(evidence) is None


class TestExtractVirusTotalScore:
    def test_valid_weights_suspicious_as_half(self):
        # malicious=5, suspicious=2 -> (5 + 2*0.5) / 100 * 100 = 6.0
        evidence = [_vt_evidence(malicious=5, suspicious=2, harmless=90, undetected=3)]
        assert RiskEngine._extract_virustotal_score(evidence) == pytest.approx(6.0)

    def test_all_clean(self):
        evidence = [_vt_evidence(malicious=0, suspicious=0, harmless=60, undetected=40)]
        assert RiskEngine._extract_virustotal_score(evidence) == 0.0

    def test_zero_total_returns_none(self):
        evidence = [_vt_evidence(malicious=0, suspicious=0, harmless=0, undetected=0)]
        assert RiskEngine._extract_virustotal_score(evidence) is None

    def test_malformed_data(self):
        evidence = [OSINTEvidence(source="virustotal", raw_data={"unexpected": "shape"})]
        assert RiskEngine._extract_virustotal_score(evidence) is None


class TestScoreFormula:
    async def test_whitelisted_is_always_zero_low(self):
        engine = RiskEngine()
        score, severity = await engine.score(_db_mock(whitelisted=True), "8.8.8.8", [], llm_score=99)
        assert (score, severity) == (0, Severity.LOW)

    async def test_only_llm_present_equals_llm_score(self):
        # Tek bileşen kalınca ağırlık kendine bölünüp iptal olmalı: final == llm_score.
        engine = RiskEngine()
        score, _ = await engine.score(_db_mock(), "example.com", [], llm_score=73)
        assert score == 73

    async def test_llm_and_abuseipdb_proportional_reweight(self):
        # LLM=10 (w .30) + AbuseIPDB=75 (w .35), VT yok -> total_weight=.65
        # weighted = 10*.30 + 75*.35 = 29.25 -> final = 29.25/.65 = 45
        engine = RiskEngine()
        evidence = [_abuseipdb_evidence(75)]
        score, severity = await engine.score(_db_mock(), "1.2.3.4", evidence, llm_score=10)
        assert score == 45
        assert severity == Severity.MEDIUM

    async def test_all_three_sources_present(self):
        # LLM=50 (.30) + AbuseIPDB=80 (.35) + VT=6.0 (.35), total_weight=1.0
        # weighted = 15 + 28 + 2.1 = 45.1 -> round -> 45
        engine = RiskEngine()
        evidence = [
            _abuseipdb_evidence(80),
            _vt_evidence(malicious=5, suspicious=2, harmless=90, undetected=3),
        ]
        score, severity = await engine.score(_db_mock(), "1.2.3.4", evidence, llm_score=50)
        assert score == 45
        assert severity == Severity.MEDIUM

    async def test_score_never_exceeds_100_or_goes_below_0(self):
        engine = RiskEngine()
        score, _ = await engine.score(_db_mock(), "1.2.3.4", [], llm_score=100)
        assert 0 <= score <= 100
