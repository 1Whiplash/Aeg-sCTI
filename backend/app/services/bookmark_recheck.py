"""Bir bookmark'ı önbelleği atlayarak yeniden analiz edip önceki kayıtla
deterministik olarak karşılaştıran ortak mantık.

Hem manuel "Kontrol Et" API uç noktası (api/v1/bookmarks.py) hem de
zamanlanmış otomatik kontrol (bookmark_scheduler.py) bu fonksiyonu
kullanır — aynı mantığın iki yerde ayrı yazılıp zamanla birbirinden
sapmasını önlemek için.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.bookmark import Bookmark
from app.models.search_history import SearchHistory
from app.schemas.bookmark import BookmarkDiff
from app.schemas.ioc import IOCAnalysisRequest, IOCAnalysisResponse, OSINTEvidence
from app.services.diff import HistorySnapshot, compute_diff
from app.services.interfaces import ICTIProvider


async def recheck_bookmark_and_diff(
    db: AsyncSession, bookmark: Bookmark, provider: ICTIProvider
) -> tuple[IOCAnalysisResponse, BookmarkDiff]:
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

    diff = compute_diff(current_snapshot, previous_snapshot)
    return analysis, diff
