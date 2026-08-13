# AegisCTI — Otonom Siber Tehdit İstihbaratı ve SOAR Platformu

Faz 1: sistem salt-okunur (Read-Only) modda çalışır — IP/domain/URL/hash
göstergelerini birden çok OSINT kaynağından toplayıp yerel bir LLM (Qwen 2.5)
ile analiz eden, risk skorlayan ve raporlayan bir SOC konsolu. Otomatik
müdahale (SOAR aksiyonları) bilinçli olarak devre dışı/pasif bırakılmıştır.

## Özellikler

- **Çok kaynaklı OSINT toplama**: VirusTotal, AbuseIPDB, Shodan, AlienVault
  OTX — paralel çalışır, hiçbiri veri dönmezse domain/URL için canlı web
  taraması (sayfa başlığı, WHOIS, SSL sertifika yaşı) fallback olarak devreye
  girer.
- **Yerel LLM analizi**: Ollama üzerinde çalışan Qwen 2.5, toplanan kanıtları
  yapılandırılmış (JSON şema zorlamalı) bir SOC raporuna çevirir — risk
  skoru, tehdit özeti, önerilen aksiyonlar. Yanıtın Türkçe kalması ve
  sadece somut kanıta dayanması için pekiştirilmiş prompt + otomatik
  yeniden deneme + yedek mesaj güvencesi var.
- **Ağırlıklı risk skorlama**: `AbuseIPDB × 0.35 + VirusTotal × 0.35 + LLM × 0.30`
  — eksik kaynaklar orantısal olarak yeniden dağıtılır, whitelist'teki
  göstergeler her zaman 0 puan alır.
- **Redis önbellekleme**: aynı gösterge kısa süre içinde tekrar sorgulanırsa
  API/LLM zinciri yeniden çalıştırılmaz (20 dakika TTL).
- **Coğrafi tehdit haritası**: IP göstergeleri için gerçek ülke sınırlarına
  sahip bir dünya haritasında konum gösterimi (Shodan hassas konum, yoksa
  ülke koduna göre yaklaşık merkez).
- **Whitelist yönetimi, sorgu geçmişi, otomatik uyarı listesi** (risk ≥ 50),
  Dashboard'da canlı istatistikler ve çoklu-nokta harita.
- **Kaynak bazlı doğrulama görünümü**: VirusTotal'ın hangi motorun (Kaspersky,
  Fortinet, ESET vb.) zararlı/şüpheli işaretlediğini isimleriyle gösterir —
  toplu sayı yerine somut doğrulama; AbuseIPDB rapor kategorileri de eklenir.
- **Açığa çıkan riskli servisler**: Shodan port verisinden RDP/SMB/PostgreSQL/
  MySQL/MongoDB/Redis gibi yaygın istismar edilen servisleri ayrı, risk
  skorunu ETKİLEMEYEN bir alanda gösterir (skor sadece bilinen kötüye
  kullanım kanıtına dayanır, açık port başlı başına kanıt sayılmaz).
- **İzleme Listesi (Bookmark)**: göstergeleri isimlendirerek kaydetme;
  "Kontrol Et" ile önbelleği atlayan taze bir analiz çalıştırıp bir önceki
  kontrolden bu yana risk skoru/severity/açık servis değişimini DETERMİNİSTİK
  (LLM'e dayanmayan) bir özet olarak gösterir.
- **PDF rapor dışa aktarma**: kurumsal görünümlü, özetlenmiş OSINT
  bulgularıyla tek tıkla indirilebilir rapor.
- **Pasif FortiGate SOAR istemcisi**: `FORTIGATE_AUTO_BLOCK_ENABLED=false`
  olduğu sürece hiçbir gerçek isteği dışarı göndermez.
- **Pasif SIEM dışa aktarımı (Syslog/CEF)**: `SIEM_EXPORT_ENABLED=false`
  olduğu sürece devre dışı; açıldığında risk skoru eşiği (`SIEM_ALERT_THRESHOLD`,
  varsayılan 50) aşan sonuçları CEF formatında syslog'a gönderir (QRadar,
  ArcSight, Splunk, Elastic dahil çoğu SIEM'le uyumlu) — gönderim arka planda
  çalışır, SIEM erişilemez olsa bile `/analyze` yanıt süresini etkilemez.
- **Güvenlik**: JWT tabanlı admin girişi (whitelist yazma + FortiGate
  aksiyonu korumalı), Redis tabanlı rate limiting (analyze/login/block-ip),
  SSRF koruması (web scraper özel/iç ağ adreslerine istek atmaz), girdi
  doğrulama.

## Klasör Yapısı

```
AegisCTI/
├── backend/                     # FastAPI (async, SOLID katmanlı mimari)
│   └── app/
│       ├── api/v1/              # auth, health, ioc, history, actions, whitelist, bookmarks
│       ├── core/                # config.py, enums.py, logging_config.py
│       ├── db/                  # SQLAlchemy engine/session
│       ├── models/               # search_history, whitelist, bookmark (ORM)
│       ├── schemas/              # Pydantic şemaları
│       └── services/             # İş mantığı + OSINT collector'lar + arayüzler
│           ├── virustotal.py / abuseipdb.py / shodan.py / otx.py / web_scraper.py
│           ├── aggregator.py     # collector'ları paralel çalıştırır
│           ├── risk_engine.py    # ağırlıklı skor formülü
│           ├── exposure.py       # Shodan port -> riskli servis çıkarımı
│           ├── diff.py           # bookmark 'yeniden kontrol' deterministik karşılaştırma
│           ├── ollama_service.py # LLM analizi (dil/kalibrasyon güvencesi)
│           ├── geo.py            # coğrafi konum çıkarımı
│           ├── cache.py          # Redis önbellek
│           ├── rate_limiter.py   # Redis tabanlı rate limiting
│           ├── auth.py           # JWT admin girişi
│           ├── fortigate_service.py  # pasif SOAR istemcisi
│           └── siem_service.py   # pasif SIEM (Syslog/CEF) dışa aktarım istemcisi
│   └── alembic/                 # DB migration'ları
├── frontend/                     # React + Vite + TailwindCSS (Obsidian Dark tema)
│   └── src/
│       ├── components/ui/        # RiskGauge, ThreatMap, Tabs, VendorVerdicts, AdminLoginGate...
│       ├── components/layout/    # Header (global arama), Sidebar
│       ├── lib/                  # api.js, auth.js, detectIocType.js, pdfExport.js
│       └── pages/                # Dashboard, Investigate, Alerts, Activity, Bookmarks, Settings
└── docker-compose.yml             # backend, frontend, postgres, redis, ollama
```

## Teknoloji Yığını

**Backend:** FastAPI, SQLAlchemy (async) + Alembic, PostgreSQL, Redis, httpx,
BeautifulSoup4, PyJWT

**Frontend:** React 18, Vite, TailwindCSS, react-router-dom, d3-geo +
topojson-client + world-atlas (harita), jsPDF

**LLM:** Ollama + Qwen 2.5 7B (yerel, GPU destekli)

## Hızlı Başlangıç

```bash
cd AegisCTI/backend
cp .env.example .env
```

`.env` içinde doldurman gerekenler:

| Değişken | Açıklama |
|---|---|
| `SECRET_KEY` | JWT imzalama anahtarı — rastgele üret (`python -c "import secrets; print(secrets.token_hex(32))"`) |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | Whitelist yazma ve FortiGate aksiyonu için admin girişi |
| `VIRUSTOTAL_API_KEY` | virustotal.com/gui/join-us (ücretsiz, dk'da 4 istek) |
| `SHODAN_API_KEY` | account.shodan.io (ücretsiz katman kısıtlı — bazı IP'lerde 403 verebilir) |
| `ABUSEIPDB_API_KEY` | abuseipdb.com/register (ücretsiz, günde 1000 istek) |
| `OTX_API_KEY` | otx.alienvault.com (ücretsiz) |

```bash
cd ..
docker compose up -d --build
docker exec aegisci-backend alembic upgrade head
```

- Frontend: http://localhost:5173
- Backend API dokümantasyonu: http://localhost:8000/docs
- Ollama: http://localhost:11434

## Testler

```bash
docker exec aegisci-backend pytest tests/ -v
docker exec aegisci-frontend npm test
```

**Not (Windows):** `npm install` Docker build sırasında bazen BuildKit
kaynaklı ağ sorunları yüzünden takılabiliyor. Takılırsa:
```bash
$env:DOCKER_BUILDKIT="0"; $env:COMPOSE_BAKE="false"; docker compose up -d --build
```

## API Uç Noktaları (özet)

| Uç nokta | Açıklama | Korumalı mı |
|---|---|---|
| `POST /api/v1/ioc/analyze` | IOC analiz (ana akış) | Rate limit (10/dk) |
| `GET /api/v1/history` | Geçmiş sorgular (`min_risk_score` filtresi destekler) | Açık |
| `GET/POST /api/v1/whitelist` | Whitelist listele/ekle | POST admin girişi ister |
| `DELETE /api/v1/whitelist/{id}` | Whitelist'ten sil | Admin girişi ister |
| `POST /api/v1/actions/block-ip` | FortiGate engelleme (pasif) | Admin + rate limit (5/dk) |
| `POST /api/v1/auth/login` | Admin girişi, JWT döner | Rate limit (5/dk, brute-force koruması) |
| `GET/POST /api/v1/bookmarks` | İzleme listesi listele/ekle | POST admin girişi ister |
| `DELETE /api/v1/bookmarks/{id}` | İzleme listesinden sil | Admin girişi ister |
| `POST /api/v1/bookmarks/{id}/recheck` | Önbelleği atlayıp taze analiz + deterministik diff | Rate limit (`/analyze` ile aynı kova, 10/dk) |

## Bilinen Sınırlamalar / Faz 2 Adayları

- Tek admin hesabı var, çok kullanıcılı yetkilendirme yok.
- Rate limiting varsayılan olarak `request.client.host`'a göre çalışır.
  Gerçek bir ters proxy arkasında dağıtılırken `.env`'de
  `TRUST_PROXY_HEADERS=true` yapılırsa `X-Forwarded-For` başlığı okunur —
  ama bu SADECE proxy'nin başlığı garanti ettiği ortamlarda güvenlidir,
  aksi halde istemci limiti sahte IP'lerle atlatabilir.
- Shodan'ın ücretsiz planı bazı "işaretli" IP'lerde (Tor node'ları vb.)
  403 dönebiliyor — hesap kısıtlaması, kod tarafında çözülemez.
- LLM küçük bir model (7B) olduğu için nadiren hâlâ hatalı çıkarım
  yapabiliyor; kod tarafında kalibrasyon kuralları ve dil-kirlenmesi
  koruması var ama %100 garanti değil.
- `FORTIGATE_AUTO_BLOCK_ENABLED` ve `READ_ONLY_MODE` Faz 2'de gerçek
  otomatik müdahale için etkinleştirilecek — şu an ikisi de pasif.
- Ollama tek seferde bir çıkarım işleyebiliyor; birden fazla analist aynı
  anda analiz isteği gönderirse (paralel kullanım) istekler kuyruğa girip
  tek başına ~20-25 saniye süren bir analiz 60-100+ saniyeye çıkabiliyor.
  Faz 2'de gerçek çok-kullanıcılı kullanım için bir istek kuyruğu/öncelik
  mekanizması ya da birden fazla model instance'ı değerlendirilmeli.
