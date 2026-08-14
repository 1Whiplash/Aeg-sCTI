"""`/api/v1/auth/login` uç noktası için uçtan uca testler.

Rate limiter gerçek Redis'e karşı çalışıyor (bkz. app/services/rate_limiter.py);
ASGITransport varsayılan olarak istemciyi 127.0.0.1 gibi gösterdiği için testler
arasında dakikalık pencere paylaşılmasın diye o anahtar her testten önce silinir.
"""

import pytest_asyncio
from httpx import AsyncClient

from app.core.config import settings
from app.services.rate_limiter import _client as redis_client


@pytest_asyncio.fixture(autouse=True)
async def _reset_login_rate_limit():
    await redis_client.delete("aegisci:ratelimit:login:127.0.0.1")
    yield
    await redis_client.delete("aegisci:ratelimit:login:127.0.0.1")


async def test_login_with_valid_credentials_returns_token(client: AsyncClient):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": settings.ADMIN_USERNAME, "password": settings.ADMIN_PASSWORD},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"]
    assert body["token_type"] == "bearer"


async def test_login_with_wrong_password_returns_401(client: AsyncClient):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": settings.ADMIN_USERNAME, "password": "yanlis-sifre"},
    )
    assert resp.status_code == 401


async def test_login_with_unknown_username_returns_401(client: AsyncClient):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "olmayan-kullanici", "password": settings.ADMIN_PASSWORD},
    )
    assert resp.status_code == 401


async def test_login_rate_limit_blocks_after_five_attempts(client: AsyncClient):
    for _ in range(5):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"username": settings.ADMIN_USERNAME, "password": "yanlis-sifre"},
        )
        assert resp.status_code == 401

    blocked_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": settings.ADMIN_USERNAME, "password": settings.ADMIN_PASSWORD},
    )
    assert blocked_resp.status_code == 429
