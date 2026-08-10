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
    db: AsyncSession = Depends(get_db_session),
) -> list[SearchHistoryItem]:
    """Geçmiş IOC sorgularını en yeniden en eskiye doğru listeler."""
    result = await db.execute(
        select(SearchHistory).order_by(SearchHistory.created_at.desc()).limit(limit)
    )
    return list(result.scalars().all())
