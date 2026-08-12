"""Redis tabanlı basit sabit-pencere (fixed window) rate limiter.

Harici bir kütüphane eklemek yerine zaten kullandığımız Redis üzerinden
sayaç tutuyoruz. Amaç: `/analyze` gibi dışarı (VirusTotal, Ollama) gerçek
istek atan uçları, kişisel/otomasyon kaynaklı aşırı kullanıma karşı korumak.

Redis'e ulaşılamazsa istek engellenmez, sadece loglanır — eksik altyapı
hatalı davranışa değil (cache.py'deki aynı prensip) düşük korumaya yol açar.

NOT: Bu proje şu an Vite proxy arkasında tek bir geliştirme ortamında
çalıştığı için istekler backend'e aynı IP'den (frontend container'ı) geliyor
gibi görünebilir — yani bu limit pratikte "genel" bir limit gibi davranır.
Gerçek çok-kullanıcılı bir dağıtımda ters proxy'nin X-Forwarded-For
başlığını ilettiğinden emin olunmalı.
"""

import logging

import redis.asyncio as redis
from fastapi import HTTPException, Request, status

from app.core.config import settings

logger = logging.getLogger(__name__)

_client = redis.from_url(settings.REDIS_URL, decode_responses=True)


class RateLimiter:
    """FastAPI dependency olarak kullanılır: `Depends(RateLimiter(10, 60, "analyze"))`."""

    def __init__(self, max_requests: int, window_seconds: int, key_prefix: str) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._key_prefix = key_prefix

    async def __call__(self, request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
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
