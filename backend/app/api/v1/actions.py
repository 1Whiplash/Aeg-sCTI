"""Manuel tetiklemeli SOAR aksiyon uç noktaları (Faz 1: pasif/standby).

FortiGate'e gerçekten istek gitmesi için hem burası çağrılmalı HEM DE
`FORTIGATE_AUTO_BLOCK_ENABLED=true` olmalı — varsayılan (false) durumda
bu uç nokta hep "engellenmedi" cevabı döner. Admin girişi gerektirir.
"""

from fastapi import APIRouter, Depends

from app.schemas.actions import BlockIPRequest, BlockIPResponse
from app.services.auth import require_auth
from app.services.fortigate_service import FortiGateService
from app.services.rate_limiter import RateLimiter

router = APIRouter(prefix="/actions", tags=["Actions"])

# Gerçek bir aksiyon uç noktası (ileride firewall kuralı tetikleyebilir),
# analyze'den daha sıkı bir limit uyguluyoruz.
_block_ip_rate_limit = RateLimiter(max_requests=5, window_seconds=60, key_prefix="block-ip")


@router.post("/block-ip", response_model=BlockIPResponse)
async def block_ip(
    request: BlockIPRequest,
    _admin: str = Depends(require_auth),
    _rate_limit: None = Depends(_block_ip_rate_limit),
) -> BlockIPResponse:
    """Analistin manuel onayıyla bir IP'yi FortiGate'te engellemeyi dener."""
    service = FortiGateService()
    blocked = await service.block_ip(request.ip_address)

    if blocked:
        return BlockIPResponse(blocked=True, message=f"{request.ip_address} FortiGate'te engellendi.")

    return BlockIPResponse(
        blocked=False,
        message=(
            "Engelleme gerçekleştirilmedi — FORTIGATE_AUTO_BLOCK_ENABLED devre dışı "
            "veya FortiGate bağlantısı başarısız."
        ),
    )
