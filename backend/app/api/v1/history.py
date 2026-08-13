"""Geçmiş IOC sorgularını listeleyen/silen uç noktalar.

Listeleme herkese açık (Faz 1 felsefesiyle uyumlu); silme admin girişi
gerektirir — kayıt silme geri alınamaz bir işlem olduğu için whitelist/
bookmark silmeyle aynı korumaya tabi.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from app.models.search_history import SearchHistory
from app.schemas.history import SearchHistoryItem
from app.services.auth import require_auth

router = APIRouter(prefix="/history", tags=["History"])


@router.get("", response_model=list[SearchHistoryItem])
async def list_history(
    limit: int = Query(50, ge=1, le=200),
    min_risk_score: int | None = Query(None, ge=0, le=100, description="Sadece bu skorun üzerindekiler"),
    db: AsyncSession = Depends(get_db_session),
) -> list[SearchHistoryItem]:
    """Geçmiş IOC sorgularını en yeniden en eskiye doğru listeler."""
    query = select(SearchHistory).order_by(SearchHistory.created_at.desc()).limit(limit)
    if min_risk_score is not None:
        query = query.where(SearchHistory.risk_score >= min_risk_score)
    result = await db.execute(query)
    return list(result.scalars().all())


@router.delete("/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_history_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db_session),
    _admin: str = Depends(require_auth),
) -> None:
    result = await db.execute(delete(SearchHistory).where(SearchHistory.id == entry_id))
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Kayıt bulunamadı.")
