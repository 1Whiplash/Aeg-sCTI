"""Bookmark (izleme listesi) yönetim ve 'yeniden kontrol et' uç noktaları.

Listeleme/ekleme/silme whitelist.py deseniyle aynı: listeleme herkese açık,
yazma admin girişi gerektirir. `/recheck` ise mevcut `/ioc/analyze` gibi
açık ama aynı rate limit kovasını paylaşır (aynı pahalı OSINT+LLM zincirini
tetikliyor).
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from app.models.bookmark import Bookmark
from app.models.search_history import SearchHistory
from app.schemas.bookmark import BookmarkCreate, BookmarkDiff, BookmarkItem, BookmarkRecheckResponse
from app.schemas.ioc import IOCAnalysisRequest, OSINTEvidence
from app.services.auth import require_auth
from app.services.cti_provider import get_cti_provider
from app.services.diff import HistorySnapshot, compute_diff
from app.services.interfaces import ICTIProvider
from app.services.rate_limiter import RateLimiter

router = APIRouter(prefix="/bookmarks", tags=["Bookmarks"])

# /ioc/analyze ile AYNI kovayı paylaşır (key_prefix="analyze") — recheck de
# ayni pahalı zinciri (OSINT + LLM) çalıştırdığı için ayrı bir limit
# tanımlamak /analyze limitini bookmarks üzerinden bypass etmeyi mümkün kılardı.
_recheck_rate_limit = RateLimiter(max_requests=10, window_seconds=60, key_prefix="analyze")


@router.get("", response_model=list[BookmarkItem])
async def list_bookmarks(db: AsyncSession = Depends(get_db_session)) -> list[BookmarkItem]:
    result = await db.execute(select(Bookmark).order_by(Bookmark.created_at.desc()))
    return list(result.scalars().all())


@router.post("", response_model=BookmarkItem, status_code=status.HTTP_201_CREATED)
async def create_bookmark(
    payload: BookmarkCreate,
    db: AsyncSession = Depends(get_db_session),
    _admin: str = Depends(require_auth),
) -> BookmarkItem:
    entry = Bookmark(
        value=payload.value.strip(),
        ioc_type=payload.ioc_type,
        display_name=payload.display_name.strip(),
        notes=payload.notes,
    )
    db.add(entry)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Bu gösterge zaten kayıtlı."
        ) from exc
    await db.refresh(entry)
    return entry


@router.delete("/{bookmark_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_bookmark(
    bookmark_id: int,
    db: AsyncSession = Depends(get_db_session),
    _admin: str = Depends(require_auth),
) -> None:
    result = await db.execute(delete(Bookmark).where(Bookmark.id == bookmark_id))
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Kayıt bulunamadı.")


@router.post("/{bookmark_id}/recheck", response_model=BookmarkRecheckResponse)
async def recheck_bookmark(
    bookmark_id: int,
    db: AsyncSession = Depends(get_db_session),
    provider: ICTIProvider = Depends(get_cti_provider),
    _rate_limit: None = Depends(_recheck_rate_limit),
) -> BookmarkRecheckResponse:
    """Bookmark'ı önbelleği atlayarak taze analiz eder ve bir önceki
    kayıtla karşılaştırıp DETERMİNİSTİK bir değişim özeti döner."""
    bookmark = await db.get(Bookmark, bookmark_id)
    if bookmark is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Bookmark bulunamadı.")

    previous_row = (
        await db.execute(
            select(SearchHistory)
            .where(SearchHistory.ioc_value == bookmark.value, SearchHistory.ioc_type == bookmark.ioc_type)
            .order_by(SearchHistory.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    analysis = await provider.lookup(
        IOCAnalysisRequest(value=bookmark.value, ioc_type=bookmark.ioc_type), force_refresh=True
    )

    previous_snapshot = None
    if previous_row is not None:
        previous_evidence = [
            OSINTEvidence.model_validate(item)
            for item in (previous_row.osint_raw or {}).get("evidence", [])
        ]
        previous_snapshot = HistorySnapshot(
            risk_score=previous_row.risk_score,
            severity=previous_row.severity,
            osint_evidence=previous_evidence,
            created_at=previous_row.created_at,
        )

    current_snapshot = HistorySnapshot(
        risk_score=analysis.risk_score,
        severity=analysis.severity,
        osint_evidence=analysis.osint_evidence,
        created_at=analysis.analyzed_at,
    )

    diff: BookmarkDiff = compute_diff(current_snapshot, previous_snapshot)
    return BookmarkRecheckResponse(analysis=analysis, diff=diff)
