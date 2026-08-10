"""IOC analiz uç noktaları (Faz 1: Read-Only analiz ve raporlama)."""

from fastapi import APIRouter, Depends

from app.schemas.ioc import IOCAnalysisRequest, IOCAnalysisResponse
from app.services.cti_provider import get_cti_provider
from app.services.interfaces import ICTIProvider

router = APIRouter(prefix="/ioc", tags=["Threat Intelligence"])


@router.post("/analyze", response_model=IOCAnalysisResponse)
async def analyze_ioc(
    request: IOCAnalysisRequest,
    provider: ICTIProvider = Depends(get_cti_provider),
) -> IOCAnalysisResponse:
    """Bir IOC'yi (IP, domain, hash, url) birleşik CTI kaynaklarında sorgular ve kaydeder.

    Bu uç nokta salt sorgulama yapar (yazma/aksiyon içermez), bu yüzden
    `READ_ONLY_MODE`'dan bağımsız her zaman çalışır. Faz 1'in "salt-okunur"
    garantisi, aksiyon alan tarafta (`fortigate_service`) `FORTIGATE_AUTO_BLOCK_ENABLED`
    bayrağıyla sağlanıyor.
    """
    return await provider.lookup(request)
