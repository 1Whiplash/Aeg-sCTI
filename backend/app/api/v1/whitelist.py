"""Güvenli IOC listesi (whitelist) yönetim uç noktaları."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session
from app.models.whitelist import Whitelist
from app.schemas.whitelist import WhitelistCreate, WhitelistItem

router = APIRouter(prefix="/whitelist", tags=["Whitelist"])


@router.get("", response_model=list[WhitelistItem])
async def list_whitelist(db: AsyncSession = Depends(get_db_session)) -> list[WhitelistItem]:
    result = await db.execute(select(Whitelist).order_by(Whitelist.created_at.desc()))
    return list(result.scalars().all())


@router.post("", response_model=WhitelistItem, status_code=status.HTTP_201_CREATED)
async def create_whitelist_entry(
    payload: WhitelistCreate, db: AsyncSession = Depends(get_db_session)
) -> WhitelistItem:
    entry = Whitelist(value=payload.value.strip(), ioc_type=payload.ioc_type, reason=payload.reason)
    db.add(entry)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Bu değer whitelist'te zaten kayıtlı.",
        ) from exc
    await db.refresh(entry)
    return entry


@router.delete("/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_whitelist_entry(entry_id: int, db: AsyncSession = Depends(get_db_session)) -> None:
    result = await db.execute(delete(Whitelist).where(Whitelist.id == entry_id))
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Kayıt bulunamadı.")
