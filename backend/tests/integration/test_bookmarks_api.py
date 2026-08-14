"""`/api/v1/bookmarks` uç noktaları için uçtan uca (gerçek HTTP + gerçek DB) testler.

`/recheck` dış OSINT/LLM zincirini tetiklediği için `get_cti_provider`
bağımlılığı sahte (fake) bir sağlayıcıyla değiştirilir — amaç dış servisleri
mocklamak, API+DB entegrasyonunu gerçek bırakmaktır.
"""

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Severity
from app.models.search_history import SearchHistory
from app.schemas.ioc import IOCAnalysisRequest, IOCAnalysisResponse
from app.services.cti_provider import get_cti_provider
from app.services.interfaces import ICTIProvider


class _FakeCTIProvider(ICTIProvider):
    """Dış ağ çağrısı yapmadan sahte bir analiz üretir ve search_history'ye yazar."""

    def __init__(self, db: AsyncSession, risk_score: int = 42) -> None:
        self._db = db
        self._risk_score = risk_score

    async def lookup(
        self, request: IOCAnalysisRequest, force_refresh: bool = False
    ) -> IOCAnalysisResponse:
        response = IOCAnalysisResponse(
            value=request.value,
            ioc_type=request.ioc_type,
            risk_score=self._risk_score,
            severity=Severity.MEDIUM,
            llm_analysis="test analizi",
            recommended_actions=[],
            osint_evidence=[],
            exposed_services=[],
        )
        self._db.add(
            SearchHistory(
                ioc_value=response.value,
                ioc_type=response.ioc_type,
                risk_score=response.risk_score,
                severity=response.severity,
                llm_summary=response.llm_analysis,
                osint_raw={"evidence": [], "recommended_actions": []},
                geo=None,
            )
        )
        await self._db.commit()
        return response


async def test_bookmark_full_crud_flow(client: AsyncClient, app, db_session: AsyncSession, admin_headers):
    app.dependency_overrides[get_cti_provider] = lambda: _FakeCTIProvider(db_session)

    create_resp = await client.post(
        "/api/v1/bookmarks",
        json={
            "value": "1.2.3.4",
            "ioc_type": "ip",
            "display_name": "Test IP",
            "notes": "entegrasyon testi",
        },
        headers=admin_headers,
    )
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert created["value"] == "1.2.3.4"
    assert created["display_name"] == "Test IP"
    bookmark_id = created["id"]

    list_resp = await client.get("/api/v1/bookmarks")
    assert list_resp.status_code == 200
    values = [item["value"] for item in list_resp.json()]
    assert "1.2.3.4" in values

    recheck_resp = await client.post(f"/api/v1/bookmarks/{bookmark_id}/recheck")
    assert recheck_resp.status_code == 200
    recheck_body = recheck_resp.json()
    assert recheck_body["analysis"]["value"] == "1.2.3.4"
    assert recheck_body["diff"]["is_first_check"] is True

    delete_resp = await client.delete(f"/api/v1/bookmarks/{bookmark_id}", headers=admin_headers)
    assert delete_resp.status_code == 204

    list_after_delete = await client.get("/api/v1/bookmarks")
    values_after_delete = [item["value"] for item in list_after_delete.json()]
    assert "1.2.3.4" not in values_after_delete


async def test_create_bookmark_requires_auth(client: AsyncClient):
    resp = await client.post(
        "/api/v1/bookmarks",
        json={"value": "5.6.7.8", "ioc_type": "ip", "display_name": "Yetkisiz"},
    )
    assert resp.status_code == 401


async def test_delete_bookmark_requires_auth(client: AsyncClient, admin_headers):
    create_resp = await client.post(
        "/api/v1/bookmarks",
        json={"value": "9.9.9.9", "ioc_type": "ip", "display_name": "Test"},
        headers=admin_headers,
    )
    bookmark_id = create_resp.json()["id"]

    resp = await client.delete(f"/api/v1/bookmarks/{bookmark_id}")
    assert resp.status_code == 401


async def test_create_duplicate_bookmark_returns_409(client: AsyncClient, admin_headers):
    payload = {"value": "10.10.10.10", "ioc_type": "ip", "display_name": "Ilk"}
    first = await client.post("/api/v1/bookmarks", json=payload, headers=admin_headers)
    assert first.status_code == 201

    second = await client.post(
        "/api/v1/bookmarks",
        json={**payload, "display_name": "Ikinci"},
        headers=admin_headers,
    )
    assert second.status_code == 409

    # Duplicate denemesinden sonra tablo hâlâ kullanılabilir olmalı (rollback
    # sadece savepoint'e geri sarmalı, dış test transaction'ını bozmamalı).
    list_resp = await client.get("/api/v1/bookmarks")
    assert list_resp.status_code == 200


async def test_delete_nonexistent_bookmark_returns_404(client: AsyncClient, admin_headers):
    resp = await client.delete("/api/v1/bookmarks/999999", headers=admin_headers)
    assert resp.status_code == 404
