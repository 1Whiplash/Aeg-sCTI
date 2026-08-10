"""IOC analiz uç noktaları (Faz 1: Read-Only analiz ve raporlama)."""

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.config import settings
from app.schemas.ioc import IOCAnalysisRequest, IOCAnalysisResponse
from app.services.cti_provider import get_cti_provider
from app.services.interfaces import ICTIProvider

router = APIRouter(prefix="/ioc", tags=["Threat Intelligence"])


@router.post("/analyze", response_model=IOCAnalysisResponse)
async def analyze_ioc(
    request: IOCAnalysisRequest,
    provider: ICTIProvider = Depends(get_cti_provider),
) -> IOCAnalysisResponse:
    """Bir IOC'yi (IP, domain, hash, url) birleşik CTI kaynaklarında sorgular."""
    if not settings.READ_ONLY_MODE:
        # Faz 1 dışında SOAR aksiyonları burada tetiklenebilir; şimdilik kilitli.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sistem Read-Only modda çalışıyor.",
        )
    return await provider.lookup(request)
