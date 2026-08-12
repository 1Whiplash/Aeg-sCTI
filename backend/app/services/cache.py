"""Redis tabanlı analiz sonucu önbelleği.

Aynı IOC kısa süre içinde tekrar sorgulanırsa OSINT + LLM zincirini yeniden
çalıştırmak yerine önbellekteki sonuç dönülür. Bu hem yanıt süresini kısaltır
hem de ücretsiz API kotalarını (VirusTotal: dakikada 4 istek) korur.

Redis'e erişilemezse önbellek sessizce devre dışı kalır — analiz akışı asla
Redis'in ayakta olmasına bağımlı olmamalı (Faz 1'in read-only garantisiyle
aynı prensip: eksik altyapı, hatalı davranışa değil düşük performansa yol açar).
"""

import json
import logging

import redis.asyncio as redis

from app.core.config import settings

logger = logging.getLogger(__name__)

_KEY_PREFIX = "aegisci:analysis"


class AnalysisCache:
    def __init__(self) -> None:
        self._client = redis.from_url(settings.REDIS_URL, decode_responses=True)

    @staticmethod
    def _key(ioc_type: str, value: str) -> str:
        return f"{_KEY_PREFIX}:{ioc_type}:{value.strip().lower()}"

    async def get(self, ioc_type: str, value: str) -> dict | None:
        try:
            raw = await self._client.get(self._key(ioc_type, value))
        except redis.RedisError as exc:
            logger.warning("Redis'ten okuma başarısız, önbellek atlanıyor: %s", exc)
            return None
        return json.loads(raw) if raw else None

    async def set(self, ioc_type: str, value: str, payload: dict) -> None:
        try:
            await self._client.set(
                self._key(ioc_type, value),
                json.dumps(payload, default=str),
                ex=settings.CACHE_TTL_SECONDS,
            )
        except redis.RedisError as exc:
            logger.warning("Redis'e yazma başarısız, önbellek atlanıyor: %s", exc)
