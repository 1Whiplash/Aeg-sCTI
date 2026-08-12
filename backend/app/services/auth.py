"""JWT tabanlı basit admin kimlik doğrulaması.

Faz 1'de tek bir yönetici hesabı (.env'deki ADMIN_USERNAME/ADMIN_PASSWORD)
üzerinden çalışır — çok kullanıcılı bir kimlik sistemi bu fazın kapsamı
dışında. Sadece durum değiştiren uçları (whitelist yazma, FortiGate aksiyonu)
korumak için yeterli; analyze/history gibi salt-okunur uçlar bilinçli olarak
açık bırakılıyor.
"""

import secrets
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Header, HTTPException, status

from app.core.config import settings

_ALGORITHM = "HS256"


def authenticate(username: str, password: str) -> bool:
    """Kullanıcı adı/şifreyi zamanlama saldırılarına karşı güvenli şekilde karşılaştırır."""
    return secrets.compare_digest(username, settings.ADMIN_USERNAME) and secrets.compare_digest(
        password, settings.ADMIN_PASSWORD
    )


def create_access_token(username: str) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expires_at}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=_ALGORITHM)


async def require_auth(authorization: str | None = Header(default=None)) -> str:
    """FastAPI dependency: geçerli bir `Bearer <token>` yoksa 401 döner."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bu işlem için giriş yapmanız gerekiyor.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Oturum geçersiz veya süresi dolmuş, tekrar giriş yapın.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    return payload["sub"]
