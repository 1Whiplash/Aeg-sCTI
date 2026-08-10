# AegisCTI — Faz 1 (Read-Only CTI & SOAR İskeleti)

Otonom Siber Tehdit İstihbaratı ve SOAR platformunun ilk aşaması: analiz ve
raporlama yapan, henüz otomatik aksiyon almayan (Read-Only) modüler bir sistem.

## Klasör Yapısı

```
AegisCTI/
├── backend/                # FastAPI (async, SOLID katmanlı mimari)
│   └── app/
│       ├── api/v1/         # Route'lar (health, ioc)
│       ├── core/           # config.py, logging_config.py
│       ├── db/             # SQLAlchemy engine/session
│       ├── models/         # ORM modelleri
│       ├── schemas/        # Pydantic şemaları
│       └── services/       # İş mantığı + arayüzler (DIP)
├── frontend/                # React + Vite + TailwindCSS (dark SOC teması)
│   └── src/
│       ├── components/     # UI (shadcn/ui tarzı) + layout
│       ├── lib/             # api client, utils
│       └── pages/           # Dashboard vb.
└── docker-compose.yml       # backend, frontend, postgres, redis, ollama
```

## Hızlı Başlangıç

```bash
cd AegisCTI/backend
cp .env.example .env   # API key'lerini doldurun

cd ..
docker compose up --build
```

- Backend: http://localhost:8000/docs
- Frontend: http://localhost:5173
- Ollama (Qwen 2.5): http://localhost:11434

## Notlar

- `READ_ONLY_MODE=true` iken sistem yalnızca analiz/raporlama yapar; SOAR
  otomatik müdahale modülleri Faz 2'de bu bayrak açılarak devreye alınacaktır.
- CTI kaynak API key'leri (VirusTotal, AbuseIPDB, Shodan, OTX, MISP)
  `backend/app/core/config.py` üzerinden `Settings` sınıfına enjekte edilir.
- `ICTIProvider` ve `ILLMEnrichmentService` arayüzleri sayesinde yeni kaynaklar
  mevcut kodu bozmadan eklenebilir (SOLID: Open/Closed & Dependency Inversion).
