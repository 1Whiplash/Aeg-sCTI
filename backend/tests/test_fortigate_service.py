"""fortigate_service.py'deki idempotent policy-wiring mantığı için birim testleri.

Gerçek bir FortiGate cihazına karşı test edilemez (elimizde yok) — bu
testler sadece BİZİM KODUMUZUN doğru sırada, doğru endpoint'lere,
idempotent şekilde istek attığını doğrular. FortiOS'un gerçek davranışı
(arayüz adları, policy eşleşme mantığı vb.) gerçek/lab bir cihazda ayrıca
doğrulanmalı — bkz. README'deki uyarı notu.
"""

import asyncio
from unittest.mock import AsyncMock, patch

import httpx

from app.services.fortigate_service import FortiGateService, _address_name, _block_lock


def _resp(status_code: int, json_body: dict | None = None) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        json=json_body if json_body is not None else {},
        request=httpx.Request("GET", "https://fortigate.local/"),
    )


class _FakeAsyncClient:
    def __init__(self, get=None, post=None, put=None):
        self.get = get or AsyncMock(return_value=_resp(200))
        self.post = post or AsyncMock(return_value=_resp(200))
        self.put = put or AsyncMock(return_value=_resp(200))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _enabled():
    return patch.multiple(
        "app.services.fortigate_service.settings",
        FORTIGATE_AUTO_BLOCK_ENABLED=True,
        FORTIGATE_HOST="https://fortigate.local",
        FORTIGATE_API_KEY="test-token",
        FORTIGATE_BLOCK_INTERFACE="any",
        FORTIGATE_ADDRESS_GROUP_NAME="AegisCTI-Blocklist",
        FORTIGATE_POLICY_INBOUND_NAME="AegisCTI-Block-Inbound",
        FORTIGATE_POLICY_OUTBOUND_NAME="AegisCTI-Block-Outbound",
    )


class TestDisabledOrUnconfigured:
    async def test_disabled_by_default_sends_nothing(self):
        service = FortiGateService()
        with patch.object(FortiGateService, "_client") as mock_client:
            result = await service.block_ip("1.2.3.4")
        assert result.success is False
        assert result.partial is False
        mock_client.assert_not_called()

    async def test_missing_host_sends_nothing(self):
        service = FortiGateService()
        with patch.multiple(
            "app.services.fortigate_service.settings",
            FORTIGATE_AUTO_BLOCK_ENABLED=True,
            FORTIGATE_HOST=None,
            FORTIGATE_API_KEY="test-token",
        ):
            with patch.object(FortiGateService, "_client") as mock_client:
                result = await service.block_ip("1.2.3.4")
        assert result.success is False
        mock_client.assert_not_called()


class TestBlockIpEnabled:
    async def test_creates_address_group_and_both_policies_when_missing(self):
        ip = "1.2.3.4"
        name = _address_name(ip)

        async def fake_get(url, params=None, **kwargs):
            if url.endswith(f"/firewall/address/{name}"):
                return _resp(404)
            if url.endswith("/firewall/addrgrp/AegisCTI-Blocklist"):
                return _resp(404)
            if url.endswith("/firewall/policy"):
                return _resp(200, {"results": []})
            raise AssertionError(f"beklenmeyen GET: {url}")

        get_mock = AsyncMock(side_effect=fake_get)
        post_mock = AsyncMock(return_value=_resp(200))
        client = _FakeAsyncClient(get=get_mock, post=post_mock)

        with _enabled(), patch.object(FortiGateService, "_client", return_value=client):
            service = FortiGateService()
            result = await service.block_ip(ip)

        assert result.success is True
        assert result.partial is False
        # address + addrgrp + 2 policy = 4 POST
        assert post_mock.call_count == 4
        post_paths = [call.args[0] for call in post_mock.call_args_list]
        assert "/api/v2/cmdb/firewall/address" in post_paths
        assert "/api/v2/cmdb/firewall/addrgrp" in post_paths
        assert post_paths.count("/api/v2/cmdb/firewall/policy") == 2

        addrgrp_call = next(c for c in post_mock.call_args_list if c.args[0] == "/api/v2/cmdb/firewall/addrgrp")
        assert addrgrp_call.kwargs["json"]["member"] == [{"name": name}]

    async def test_everything_already_exists_creates_nothing(self):
        ip = "1.2.3.4"
        name = _address_name(ip)

        async def fake_get(url, params=None, **kwargs):
            if url.endswith(f"/firewall/address/{name}"):
                return _resp(200)
            if url.endswith("/firewall/addrgrp/AegisCTI-Blocklist"):
                return _resp(200, {"results": [{"member": [{"name": name}]}]})
            if url.endswith("/firewall/policy"):
                return _resp(200, {"results": [{"name": "already-there"}]})
            raise AssertionError(f"beklenmeyen GET: {url}")

        get_mock = AsyncMock(side_effect=fake_get)
        post_mock = AsyncMock(return_value=_resp(200))
        client = _FakeAsyncClient(get=get_mock, post=post_mock)

        with _enabled(), patch.object(FortiGateService, "_client", return_value=client):
            service = FortiGateService()
            result = await service.block_ip(ip)

        assert result.success is True
        post_mock.assert_not_called()

    async def test_group_exists_but_ip_missing_appends_via_put(self):
        ip = "1.2.3.4"
        name = _address_name(ip)

        async def fake_get(url, params=None, **kwargs):
            if url.endswith(f"/firewall/address/{name}"):
                return _resp(200)
            if url.endswith("/firewall/addrgrp/AegisCTI-Blocklist"):
                return _resp(200, {"results": [{"member": [{"name": "other-ip"}]}]})
            if url.endswith("/firewall/policy"):
                return _resp(200, {"results": [{"name": "already-there"}]})
            raise AssertionError(f"beklenmeyen GET: {url}")

        get_mock = AsyncMock(side_effect=fake_get)
        put_mock = AsyncMock(return_value=_resp(200))
        client = _FakeAsyncClient(get=get_mock, put=put_mock)

        with _enabled(), patch.object(FortiGateService, "_client", return_value=client):
            service = FortiGateService()
            result = await service.block_ip(ip)

        assert result.success is True
        put_mock.assert_called_once()
        members = put_mock.call_args.kwargs["json"]["member"]
        assert {"name": "other-ip"} in members
        assert {"name": name} in members

    async def test_http_error_returns_false(self):
        ip = "1.2.3.4"
        name = _address_name(ip)

        async def fake_get(url, params=None, **kwargs):
            if url.endswith(f"/firewall/address/{name}"):
                return _resp(404)  # adres yok -> POST ile oluşturulacak (başarılı)
            if url.endswith("/firewall/addrgrp/AegisCTI-Blocklist"):
                return _resp(500)  # grup sorgusu patlıyor -> raise_for_status tetiklenmeli
            raise AssertionError(f"beklenmeyen GET: {url}")

        get_mock = AsyncMock(side_effect=fake_get)
        post_mock = AsyncMock(return_value=_resp(200))
        client = _FakeAsyncClient(get=get_mock, post=post_mock)

        with _enabled(), patch.object(FortiGateService, "_client", return_value=client):
            service = FortiGateService()
            result = await service.block_ip(ip)

        assert result.success is False
        # Hata grup adımından ÖNCE (adres GET'i başarılı ama grup GET'i 500) oluştu,
        # grup üyeliği hiç garanti edilmedi -> kısmi durum yok.
        assert result.partial is False

    async def test_malformed_group_response_returns_false_without_raising(self):
        """FortiGate 200 dönüp beklenmedik bir JSON şekli (örn. boş 'results')
        verirse, ham IndexError/KeyError dışarı sızıp /block-ip'yi 500'e
        düşürmemeli — httpx.HTTPError değil ama yine de 'başarısız' sayılmalı."""
        ip = "1.2.3.4"
        name = _address_name(ip)

        async def fake_get(url, params=None, **kwargs):
            if url.endswith(f"/firewall/address/{name}"):
                return _resp(200)
            if url.endswith("/firewall/addrgrp/AegisCTI-Blocklist"):
                return _resp(200, {"results": []})  # beklenmeyen şekil: results boş
            raise AssertionError(f"beklenmeyen GET: {url}")

        get_mock = AsyncMock(side_effect=fake_get)
        client = _FakeAsyncClient(get=get_mock)

        with _enabled(), patch.object(FortiGateService, "_client", return_value=client):
            service = FortiGateService()
            result = await service.block_ip(ip)  # raise etmemeli

        assert result.success is False
        assert result.partial is False

    async def test_policy_step_failure_after_group_success_is_reported_as_partial(self):
        """Adres + grup üyeliği adımları BAŞARILI olduktan sonra policy adımı
        patlarsa, FortiGate'te canlı bir durum değişikliği zaten olmuş olabilir
        — bu 'hiçbir şey olmadı' değil, 'kısmi' olarak işaretlenmeli ki analist
        cihazı manuel kontrol etme ihtiyacını anlasın."""
        ip = "1.2.3.4"
        name = _address_name(ip)

        async def fake_get(url, params=None, **kwargs):
            if url.endswith(f"/firewall/address/{name}"):
                return _resp(200)
            if url.endswith("/firewall/addrgrp/AegisCTI-Blocklist"):
                return _resp(200, {"results": [{"member": [{"name": name}]}]})
            if url.endswith("/firewall/policy"):
                return _resp(500)  # policy adımı patlıyor
            raise AssertionError(f"beklenmeyen GET: {url}")

        get_mock = AsyncMock(side_effect=fake_get)
        client = _FakeAsyncClient(get=get_mock)

        with _enabled(), patch.object(FortiGateService, "_client", return_value=client):
            service = FortiGateService()
            result = await service.block_ip(ip)

        assert result.success is False
        assert result.partial is True


class TestConcurrentBlockIp:
    async def test_second_call_waits_for_lock_held_by_first(self):
        with _enabled(), patch.object(FortiGateService, "_client", return_value=_FakeAsyncClient(
            get=AsyncMock(return_value=_resp(200, {"results": [{"member": []}, {"name": "x"}]}))
        )):
            service = FortiGateService()
            await _block_lock.acquire()
            try:
                task = asyncio.create_task(service.block_ip("1.2.3.4"))
                await asyncio.sleep(0.05)
                assert not task.done(), "block_ip lock elde etmeden ilerlememeli"
            finally:
                _block_lock.release()

            result = await task
            assert result.success is True
