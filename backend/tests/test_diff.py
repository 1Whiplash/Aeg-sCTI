"""diff.py'deki deterministik bookmark karşılaştırma mantığı için birim testleri."""

from datetime import datetime, timezone

from app.core.enums import Severity
from app.schemas.ioc import OSINTEvidence
from app.services.diff import HistorySnapshot, compute_diff


def _vt_evidence(malicious: int) -> OSINTEvidence:
    return OSINTEvidence(
        source="virustotal",
        raw_data={"data": {"attributes": {"last_analysis_stats": {"malicious": malicious}}}},
    )


def _shodan_evidence(ports: list) -> OSINTEvidence:
    return OSINTEvidence(source="shodan", raw_data={"ports": ports})


def _snapshot(risk_score, severity, evidence, when="2026-08-13T10:00:00Z"):
    return HistorySnapshot(
        risk_score=risk_score,
        severity=severity,
        osint_evidence=evidence,
        created_at=datetime.fromisoformat(when.replace("Z", "+00:00")),
    )


def test_first_check_has_no_previous_data():
    current = _snapshot(10, Severity.LOW, [])
    diff = compute_diff(current, None)
    assert diff.is_first_check is True
    assert diff.previous_risk_score is None
    assert diff.risk_score_delta is None


def test_risk_score_and_severity_change_detected():
    previous = _snapshot(8, Severity.LOW, [_vt_evidence(2)], when="2026-08-12T10:00:00Z")
    current = _snapshot(45, Severity.MEDIUM, [_vt_evidence(9)])

    diff = compute_diff(current, previous)

    assert diff.is_first_check is False
    assert diff.previous_risk_score == 8
    assert diff.previous_severity == Severity.LOW
    assert diff.risk_score_delta == 37
    assert diff.severity_changed is True
    assert diff.virustotal_malicious_delta == 7


def test_severity_unchanged_flagged_false():
    previous = _snapshot(20, Severity.MEDIUM, [])
    current = _snapshot(25, Severity.MEDIUM, [])
    diff = compute_diff(current, previous)
    assert diff.severity_changed is False
    assert diff.risk_score_delta == 5


def test_new_and_removed_exposed_services():
    previous = _snapshot(30, Severity.MEDIUM, [_shodan_evidence([3389, 445])])
    current = _snapshot(30, Severity.MEDIUM, [_shodan_evidence([5432, 445])])

    diff = compute_diff(current, previous)

    assert diff.new_exposed_services == ["PostgreSQL (5432)"]
    assert diff.removed_exposed_services == ["RDP (3389)"]


def test_missing_virustotal_in_either_snapshot_gives_none_delta():
    previous = _snapshot(10, Severity.LOW, [])
    current = _snapshot(10, Severity.LOW, [_vt_evidence(3)])
    diff = compute_diff(current, previous)
    assert diff.virustotal_malicious_delta is None
