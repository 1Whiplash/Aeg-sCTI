"""Admin girişi uç noktası."""

from fastapi import APIRouter, Depends, HTTPException, status

from app.schemas.auth import LoginRequest, TokenResponse
from app.services.auth import authenticate, create_access_token
from app.services.rate_limiter import RateLimiter

router = APIRouter(prefix="/auth", tags=["Auth"])

# Brute-force şifre denemesine karşı: dakikada en fazla 5 giriş denemesi.
_login_rate_limit = RateLimiter(max_requests=5, window_seconds=60, key_prefix="login")


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, _rate_limit: None = Depends(_login_rate_limit)) -> TokenResponse:
    if not authenticate(payload.username, payload.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kullanıcı adı veya şifre hatalı.",
        )
    return TokenResponse(access_token=create_access_token(payload.username))
