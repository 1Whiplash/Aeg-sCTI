"""Shodan port verisinden, yaygın olarak istismar edilen açık servisleri çıkarır.

Bu liste risk_score formülüne DAHİL EDİLMEZ (bkz. risk_engine.py) — risk_score
"bu IP kötü niyetli mi" sorusuna, VirusTotal/AbuseIPDB itibar verisine ve LLM'in
somut kanıt değerlendirmesine dayanarak cevap verir. Açık bir port/servis tek
başına kötü niyet göstergesi değildir (birçok meşru sunucu RDP/DB açık
çalıştırır); bu yüzden ayrı, bilgilendirici bir alan olarak sunulur — SOC
analistine "bu hedefte dikkat çekici bir saldırı yüzeyi var" der, skoru
etkilemez.
"""

from app.schemas.ioc import OSINTEvidence

# Port -> (görünen ad, neden dikkat çekici) : kimlik doğrulaması sık atlanan veya
# yaygın olarak istismar edilen, internete açık olduğunda risk taşıyan servisler.
_RISKY_PORTS: dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


def extract_exposed_services(evidence: list[OSINTEvidence]) -> list[str]:
    """Shodan kanıtındaki `ports` listesinden bilinen riskli servisleri döner."""
    for item in evidence:
        if item.source != "shodan":
            continue
        ports = item.raw_data.get("ports")
        if not isinstance(ports, list):
            return []
        matches = sorted(
            {f"{_RISKY_PORTS[p]} ({p})" for p in ports if isinstance(p, int) and p in _RISKY_PORTS}
        )
        return matches
    return []
