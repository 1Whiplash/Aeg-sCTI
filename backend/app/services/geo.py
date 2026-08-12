"""IP göstergeleri için coğrafi konum çıkarımı (tehdit haritası).

Kesinlik sırası:
1. Shodan'ın kendi enlem/boylamı (en hassas, doğrudan sunucu konumu)
2. AbuseIPDB'nin ülke koduna göre yaklaşık ülke merkezi
3. VirusTotal'ın ülke koduna göre yaklaşık ülke merkezi

Domain/URL/Hash tipi göstergelerin doğal bir coğrafi konumu olmadığı için
(bir dosyanın ya da alan adının "yeri" yoktur) bu tiplerde her zaman `None`
döner — yapay/yanıltıcı bir nokta üretilmez.
"""

from app.core.enums import IOCType
from app.schemas.geo import GeoLocation
from app.schemas.ioc import OSINTEvidence

# ISO 3166-1 alpha-2 ülke kodu -> yaklaşık ülke merkezi (lat, lon).
_COUNTRY_CENTROIDS: dict[str, tuple[float, float]] = {
    "US": (37.09, -95.71), "CA": (56.13, -106.35), "MX": (23.63, -102.55),
    "BR": (-14.24, -51.93), "AR": (-38.42, -63.62), "CL": (-35.68, -71.54),
    "CO": (4.57, -74.30), "PE": (-9.19, -75.02), "VE": (6.42, -66.59),
    "GB": (55.38, -3.44), "IE": (53.41, -8.24), "FR": (46.23, 2.21),
    "DE": (51.17, 10.45), "NL": (52.13, 5.29), "BE": (50.50, 4.47),
    "LU": (49.82, 6.13), "CH": (46.82, 8.23), "AT": (47.52, 14.55),
    "ES": (40.46, -3.75), "PT": (39.40, -8.22), "IT": (41.87, 12.57),
    "PL": (51.92, 19.15), "CZ": (49.82, 15.47), "SK": (48.67, 19.70),
    "HU": (47.16, 19.50), "RO": (45.94, 24.97), "BG": (42.73, 25.49),
    "GR": (39.07, 21.82), "SE": (60.13, 18.64), "NO": (60.47, 8.47),
    "DK": (56.26, 9.50), "FI": (61.92, 25.75), "IS": (64.96, -19.02),
    "EE": (58.60, 25.01), "LV": (56.88, 24.60), "LT": (55.17, 23.88),
    "UA": (48.38, 31.17), "BY": (53.71, 27.95), "RU": (61.52, 105.32),
    "TR": (38.96, 35.24), "GE": (42.32, 43.36), "AM": (40.07, 45.04),
    "AZ": (40.14, 47.58), "IL": (31.05, 34.85), "PS": (31.95, 35.23),
    "JO": (30.59, 36.24), "LB": (33.85, 35.86), "SY": (34.80, 38.99),
    "IQ": (33.22, 43.68), "IR": (32.43, 53.69), "SA": (23.89, 45.08),
    "AE": (23.42, 53.85), "QA": (25.35, 51.18), "KW": (29.31, 47.48),
    "OM": (21.47, 55.98), "YE": (15.55, 48.52), "EG": (26.82, 30.80),
    "LY": (26.34, 17.23), "TN": (33.89, 9.54), "DZ": (28.03, 1.66),
    "MA": (31.79, -7.09), "ZA": (-30.56, 22.94), "NG": (9.08, 8.68),
    "KE": (-0.02, 37.91), "ET": (9.15, 40.49), "GH": (7.95, -1.02),
    "TZ": (-6.37, 34.89), "UG": (1.37, 32.29), "IN": (20.59, 78.96),
    "PK": (30.38, 69.35), "BD": (23.68, 90.36), "LK": (7.87, 80.77),
    "NP": (28.39, 84.12), "AF": (33.94, 67.71), "KZ": (48.02, 66.92),
    "UZ": (41.38, 64.59), "CN": (35.86, 104.20), "MN": (46.86, 103.85),
    "JP": (36.20, 138.25), "KR": (35.91, 127.77), "KP": (40.34, 127.51),
    "TW": (23.70, 120.96), "HK": (22.32, 114.17), "VN": (14.06, 108.28),
    "TH": (15.87, 100.99), "MM": (21.91, 95.96), "KH": (12.57, 104.99),
    "LA": (19.86, 102.50), "MY": (4.21, 101.98), "SG": (1.35, 103.82),
    "ID": (-0.79, 113.92), "PH": (12.88, 121.77), "AU": (-25.27, 133.78),
    "NZ": (-40.90, 174.89), "FJ": (-17.71, 178.07),
}


def extract_geo(ioc_type: IOCType, evidence: list[OSINTEvidence]) -> GeoLocation | None:
    """OSINT kanıtlarından en hassas mevcut konum bilgisini çıkarır."""
    if ioc_type != IOCType.IP:
        return None

    for item in evidence:
        if item.source == "shodan":
            lat = item.raw_data.get("latitude")
            lon = item.raw_data.get("longitude")
            if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                return GeoLocation(
                    lat=lat,
                    lon=lon,
                    country=item.raw_data.get("country_name"),
                    city=item.raw_data.get("city"),
                )

    for item in evidence:
        if item.source == "abuseipdb":
            code = (item.raw_data.get("data") or {}).get("countryCode")
            centroid = _COUNTRY_CENTROIDS.get(code)
            if centroid:
                return GeoLocation(lat=centroid[0], lon=centroid[1], country=code)

    for item in evidence:
        if item.source == "virustotal":
            attrs = (item.raw_data.get("data") or {}).get("attributes") or {}
            code = attrs.get("country")
            centroid = _COUNTRY_CENTROIDS.get(code)
            if centroid:
                return GeoLocation(lat=centroid[0], lon=centroid[1], country=code)

    return None
