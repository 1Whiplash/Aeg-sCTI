"""Geçmiş IOC sorgularını listeleyen uç nokta."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from app.models.search_history import SearchHistory
from app.schemas.history import SearchHistoryItem

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
