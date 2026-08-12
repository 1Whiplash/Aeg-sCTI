"""IOC analiz uç noktaları (Faz 1: Read-Only analiz ve raporlama)."""

from fastapi import APIRouter, Depends

from app.schemas.ioc import IOCAnalysisRequest, IOCAnalysisResponse
from app.services.cti_provider import get_cti_provider
from app.services.interfaces import ICTIProvider
from app.services.rate_limiter import RateLimiter

router = APIRouter(prefix="/ioc", tags=["Threat Intelligence"])

# VirusTotal'ın ücretsiz kotası dakikada 4 istek; bu limit hem o kotayı hem
# de Ollama/GPU yükünü otomasyon kaynaklı aşırı kullanıma karşı korur.
_analyze_rate_limit = RateLimiter(max_requests=10, window_seconds=60, key_prefix="analyze")


@router.post("/analyze", response_model=IOCAnalysisResponse)
async def analyze_ioc(
    request: IOCAnalysisRequest,
    provider: ICTIProvider = Depends(get_cti_provider),
    _rate_limit: None = Depends(_analyze_rate_limit),
) -> IOCAnalysisResponse:
    """Bir IOC'yi (IP, domain, hash, url) birleşik CTI kaynaklarında sorgular ve kaydeder.

    Bu uç nokta salt sorgulama yapar (yazma/aksiyon içermez), bu yüzden
    `READ_ONLY_MODE`'dan bağımsız her zaman çalışır. Faz 1'in "salt-okunur"
    garantisi, aksiyon alan tarafta (`fortigate_service`) `FORTIGATE_AUTO_BLOCK_ENABLED`
    bayrağıyla sağlanıyor.
    """
    return await provider.lookup(request)
