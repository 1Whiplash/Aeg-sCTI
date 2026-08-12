"""exposure.py'deki Shodan port -> riskli servis çıkarımı için birim testleri."""

from app.schemas.ioc import OSINTEvidence
from app.services.exposure import extract_exposed_services


def _shodan_evidence(ports: list) -> OSINTEvidence:
    return OSINTEvidence(source="shodan", raw_data={"ports": ports})


def test_known_risky_ports_are_named():
    evidence = [_shodan_evidence([5432, 3389, 445, 135, 47001])]
    result = extract_exposed_services(evidence)
    assert result == ["PostgreSQL (5432)", "RDP (3389)", "SMB (445)"]


def test_no_risky_ports_returns_empty():
    evidence = [_shodan_evidence([80, 443, 22])]
    assert extract_exposed_services(evidence) == []


def test_no_shodan_evidence_returns_empty():
    assert extract_exposed_services([]) == []


def test_missing_or_malformed_ports_returns_empty():
    evidence = [OSINTEvidence(source="shodan", raw_data={"error": "HTTP 403 hatası"})]
    assert extract_exposed_services(evidence) == []


def test_duplicate_ports_deduplicated():
    evidence = [_shodan_evidence([3389, 3389])]
    assert extract_exposed_services(evidence) == ["RDP (3389)"]
