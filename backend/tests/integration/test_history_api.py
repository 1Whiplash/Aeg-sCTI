"""`/api/v1/history` uç noktaları için uçtan uca testler."""

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import IOCType, Severity
from app.models.search_history import SearchHistory


async def _insert_history_entry(
    db_session: AsyncSession, ioc_value: str, risk_score: int = 30
) -> int:
    entry = SearchHistory(
        ioc_value=ioc_value,
        ioc_type=IOCType.IP,
        risk_score=risk_score,
        severity=Severity.MEDIUM,
        llm_summary="test",
        osint_raw={"evidence": [], "recommended_actions": []},
        geo=None,
    )
    db_session.add(entry)
    await db_session.commit()
    await db_session.refresh(entry)
    return entry.id


async def test_list_history_returns_inserted_entry(client: AsyncClient, db_session: AsyncSession):
    await _insert_history_entry(db_session, "11.11.11.11")

    resp = await client.get("/api/v1/history")
    assert resp.status_code == 200
    values = [item["ioc_value"] for item in resp.json()]
    assert "11.11.11.11" in values


async def test_list_history_filters_by_min_risk_score(client: AsyncClient, db_session: AsyncSession):
    await _insert_history_entry(db_session, "22.22.22.22", risk_score=10)
    await _insert_history_entry(db_session, "33.33.33.33", risk_score=90)

    resp = await client.get("/api/v1/history", params={"min_risk_score": 50})
    assert resp.status_code == 200
    values = [item["ioc_value"] for item in resp.json()]
    assert "33.33.33.33" in values
    assert "22.22.22.22" not in values


async def test_delete_history_entry_requires_auth(client: AsyncClient, db_session: AsyncSession):
    entry_id = await _insert_history_entry(db_session, "44.44.44.44")

    resp = await client.delete(f"/api/v1/history/{entry_id}")
    assert resp.status_code == 401


async def test_delete_history_entry_removes_it(client: AsyncClient, db_session: AsyncSession, admin_headers):
    entry_id = await _insert_history_entry(db_session, "55.55.55.55")

    delete_resp = await client.delete(f"/api/v1/history/{entry_id}", headers=admin_headers)
    assert delete_resp.status_code == 204

    list_resp = await client.get("/api/v1/history")
    values = [item["ioc_value"] for item in list_resp.json()]
    assert "55.55.55.55" not in values


async def test_delete_nonexistent_history_entry_returns_404(client: AsyncClient, admin_headers):
    resp = await client.delete("/api/v1/history/999999", headers=admin_headers)
    assert resp.status_code == 404
