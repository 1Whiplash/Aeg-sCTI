"""Redis tabanlı basit sabit-pencere (fixed window) rate limiter.

Harici bir kütüphane eklemek yerine zaten kullandığımız Redis üzerinden
sayaç tutuyoruz. Amaç: `/analyze` gibi dışarı (VirusTotal, Ollama) gerçek
istek atan uçları, kişisel/otomasyon kaynaklı aşırı kullanıma karşı korumak.

Redis'e ulaşılamazsa istek engellenmez, sadece loglanır — eksik altyapı
hatalı davranışa değil (cache.py'deki aynı prensip) düşük korumaya yol açar.

İstemci IP'si varsayılan olarak `request.client.host`'tan alınır. Gerçek bir
ters proxy arkasında dağıtılıyorsa (nginx, Vite proxy vb.) `TRUST_PROXY_HEADERS`
ayarı açılarak `X-Forwarded-For` başlığından okunması sağlanabilir — ama bu
başlık istemci tarafından serbestçe ayarlanabildiği için SADECE proxy'nin
kendisi bu başlığı garanti ediyorsa güvenlidir, aksi halde limit kolayca
sahte IP'lerle atlatılabilir (bkz. config.py'deki TRUST_PROXY_HEADERS notu).
"""

import logging

import redis.asyncio as redis
from fastapi import HTTPException, Request, status

from app.core.config import settings

logger = logging.getLogger(__name__)

_client = redis.from_url(settings.REDIS_URL, decode_responses=True)


def _resolve_client_ip(request: Request) -> str:
    if settings.TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # Zincirdeki ilk adres orijinal istemcidir; proxy kendi eklediği
            # sonraki adresleri virgülle ekler.
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimiter:
    """FastAPI dependency olarak kullanılır: `Depends(RateLimiter(10, 60, "analyze"))`."""

    def __init__(self, max_requests: int, window_seconds: int, key_prefix: str) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._key_prefix = key_prefix

    async def __call__(self, request: Request) -> None:
        client_ip = _resolve_client_ip(request)
        key = f"aegisci:ratelimit:{self._key_prefix}:{client_ip}"

        try:
            count = await _client.incr(key)
            if count == 1:
                await _client.expire(key, self._window_seconds)
        except redis.RedisError as exc:
            logger.warning("Rate limiter Redis'e ulaşamadı, limit uygulanmadan devam ediliyor: %s", exc)
            return

        if count > self._max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Çok fazla istek gönderildi (dakikada en fazla {self._max_requests}). "
                    "Lütfen biraz bekleyip tekrar deneyin."
                ),
            )
