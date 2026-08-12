"""IP göstergeleri için coğrafi konum çıkarımı (tehdit haritası).

Kesinlik sırası:
1. Shodan'ın kendi enlem/boylamı + şehir/ülke adı (en hassas, doğrudan sunucu konumu)
2. AbuseIPDB'nin ülke koduna göre yaklaşık ülke merkezi + tam ülke adı
3. VirusTotal'ın ülke koduna göre yaklaşık ülke merkezi + tam ülke adı

Domain/URL/Hash tipi göstergelerin doğal bir coğrafi konumu olmadığı için
(bir dosyanın ya da alan adının "yeri" yoktur) bu tiplerde her zaman `None`
döner — yapay/yanıltıcı bir nokta üretilmez.
"""

from app.core.enums import IOCType
from app.schemas.geo import GeoLocation
from app.schemas.ioc import OSINTEvidence

# ISO 3166-1 alpha-2 ülke kodu -> (tam ülke adı, yaklaşık ülke merkezi lat, lon).
_COUNTRY_INFO: dict[str, tuple[str, float, float]] = {
    "US": ("Amerika Birleşik Devletleri", 37.09, -95.71), "CA": ("Kanada", 56.13, -106.35),
    "MX": ("Meksika", 23.63, -102.55), "BR": ("Brezilya", -14.24, -51.93),
    "AR": ("Arjantin", -38.42, -63.62), "CL": ("Şili", -35.68, -71.54),
    "CO": ("Kolombiya", 4.57, -74.30), "PE": ("Peru", -9.19, -75.02),
    "VE": ("Venezuela", 6.42, -66.59), "GB": ("Birleşik Krallık", 55.38, -3.44),
    "IE": ("İrlanda", 53.41, -8.24), "FR": ("Fransa", 46.23, 2.21),
    "DE": ("Almanya", 51.17, 10.45), "NL": ("Hollanda", 52.13, 5.29),
    "BE": ("Belçika", 50.50, 4.47), "LU": ("Lüksemburg", 49.82, 6.13),
    "CH": ("İsviçre", 46.82, 8.23), "AT": ("Avusturya", 47.52, 14.55),
    "ES": ("İspanya", 40.46, -3.75), "PT": ("Portekiz", 39.40, -8.22),
    "IT": ("İtalya", 41.87, 12.57), "PL": ("Polonya", 51.92, 19.15),
    "CZ": ("Çekya", 49.82, 15.47), "SK": ("Slovakya", 48.67, 19.70),
    "HU": ("Macaristan", 47.16, 19.50), "RO": ("Romanya", 45.94, 24.97),
    "BG": ("Bulgaristan", 42.73, 25.49), "GR": ("Yunanistan", 39.07, 21.82),
    "SE": ("İsveç", 60.13, 18.64), "NO": ("Norveç", 60.47, 8.47),
    "DK": ("Danimarka", 56.26, 9.50), "FI": ("Finlandiya", 61.92, 25.75),
    "IS": ("İzlanda", 64.96, -19.02), "EE": ("Estonya", 58.60, 25.01),
    "LV": ("Letonya", 56.88, 24.60), "LT": ("Litvanya", 55.17, 23.88),
    "UA": ("Ukrayna", 48.38, 31.17), "BY": ("Belarus", 53.71, 27.95),
    "RU": ("Rusya", 61.52, 105.32), "TR": ("Türkiye", 38.96, 35.24),
    "GE": ("Gürcistan", 42.32, 43.36), "AM": ("Ermenistan", 40.07, 45.04),
    "AZ": ("Azerbaycan", 40.14, 47.58), "IL": ("İsrail", 31.05, 34.85),
    "PS": ("Filistin", 31.95, 35.23), "JO": ("Ürdün", 30.59, 36.24),
    "LB": ("Lübnan", 33.85, 35.86), "SY": ("Suriye", 34.80, 38.99),
    "IQ": ("Irak", 33.22, 43.68), "IR": ("İran", 32.43, 53.69),
    "SA": ("Suudi Arabistan", 23.89, 45.08), "AE": ("Birleşik Arap Emirlikleri", 23.42, 53.85),
    "QA": ("Katar", 25.35, 51.18), "KW": ("Kuveyt", 29.31, 47.48),
    "OM": ("Umman", 21.47, 55.98), "YE": ("Yemen", 15.55, 48.52),
    "EG": ("Mısır", 26.82, 30.80), "LY": ("Libya", 26.34, 17.23),
    "TN": ("Tunus", 33.89, 9.54), "DZ": ("Cezayir", 28.03, 1.66),
    "MA": ("Fas", 31.79, -7.09), "ZA": ("Güney Afrika", -30.56, 22.94),
    "NG": ("Nijerya", 9.08, 8.68), "KE": ("Kenya", -0.02, 37.91),
    "ET": ("Etiyopya", 9.15, 40.49), "GH": ("Gana", 7.95, -1.02),
    "TZ": ("Tanzanya", -6.37, 34.89), "UG": ("Uganda", 1.37, 32.29),
    "IN": ("Hindistan", 20.59, 78.96), "PK": ("Pakistan", 30.38, 69.35),
    "BD": ("Bangladeş", 23.68, 90.36), "LK": ("Sri Lanka", 7.87, 80.77),
    "NP": ("Nepal", 28.39, 84.12), "AF": ("Afganistan", 33.94, 67.71),
    "KZ": ("Kazakistan", 48.02, 66.92), "UZ": ("Özbekistan", 41.38, 64.59),
    "CN": ("Çin", 35.86, 104.20), "MN": ("Moğolistan", 46.86, 103.85),
    "JP": ("Japonya", 36.20, 138.25), "KR": ("Güney Kore", 35.91, 127.77),
    "KP": ("Kuzey Kore", 40.34, 127.51), "TW": ("Tayvan", 23.70, 120.96),
    "HK": ("Hong Kong", 22.32, 114.17), "VN": ("Vietnam", 14.06, 108.28),
    "TH": ("Tayland", 15.87, 100.99), "MM": ("Myanmar", 21.91, 95.96),
    "KH": ("Kamboçya", 12.57, 104.99), "LA": ("Laos", 19.86, 102.50),
    "MY": ("Malezya", 4.21, 101.98), "SG": ("Singapur", 1.35, 103.82),
    "ID": ("Endonezya", -0.79, 113.92), "PH": ("Filipinler", 12.88, 121.77),
    "AU": ("Avustralya", -25.27, 133.78), "NZ": ("Yeni Zelanda", -40.90, 174.89),
    "FJ": ("Fiji", -17.71, 178.07),
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
            info = _COUNTRY_INFO.get(code)
            if info:
                name, lat, lon = info
                return GeoLocation(lat=lat, lon=lon, country=name)

    for item in evidence:
        if item.source == "virustotal":
            attrs = (item.raw_data.get("data") or {}).get("attributes") or {}
            code = attrs.get("country")
            info = _COUNTRY_INFO.get(code)
            if info:
                name, lat, lon = info
                return GeoLocation(lat=lat, lon=lon, country=name)

    return None
