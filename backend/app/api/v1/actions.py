"""Manuel tetiklemeli SOAR aksiyon uç noktaları (Faz 1: pasif/standby).

FortiGate'e gerçekten istek gitmesi için hem burası çağrılmalı HEM DE
`FORTIGATE_AUTO_BLOCK_ENABLED=true` olmalı — varsayılan (false) durumda
bu uç nokta hep "engellenmedi" cevabı döner.
"""

from fastapi import APIRouter

from app.schemas.actions import BlockIPRequest, BlockIPResponse
from app.services.fortigate_service import FortiGateService

router = APIRouter(prefix="/actions", tags=["Actions"])


@router.post("/block-ip", response_model=BlockIPResponse)
async def block_ip(request: BlockIPRequest) -> BlockIPResponse:
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
