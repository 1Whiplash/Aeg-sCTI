"""bookmark_scheduler.py'deki saat ayrıştırma, scheduler kurulum ve
zamanlanmış kontrol döngüsü mantığı için birim testleri."""

from unittest.mock import AsyncMock, MagicMock, patch

from app.core.enums import IOCType
from app.services import bookmark_scheduler
from app.services.bookmark_scheduler import _parse_check_times, create_scheduler, run_bookmark_check_job


class TestParseCheckTimes:
    def test_parses_multiple_times(self):
        assert _parse_check_times("08:00,17:00") == [(8, 0), (17, 0)]

    def test_trims_whitespace(self):
        assert _parse_check_times(" 08:00 , 17:00 ") == [(8, 0), (17, 0)]

    def test_ignores_empty_segments(self):
        assert _parse_check_times("08:00,,17:00") == [(8, 0), (17, 0)]

    def test_skips_invalid_entries(self):
        assert _parse_check_times("08:00,not-a-time,17:00") == [(8, 0), (17, 0)]

    def test_skips_out_of_range_entries(self):
        assert _parse_check_times("08:60,24:00,17:00") == [(17, 0)]

    def test_empty_string_returns_empty_list(self):
        assert _parse_check_times("") == []


class TestCreateScheduler:
    def test_disabled_by_default_returns_none(self):
        with patch("app.services.bookmark_scheduler.settings.BOOKMARK_AUTO_CHECK_ENABLED", False):
            assert create_scheduler() is None

    def test_enabled_creates_scheduler_with_jobs(self):
        with patch("app.services.bookmark_scheduler.settings.BOOKMARK_AUTO_CHECK_ENABLED", True), patch(
            "app.services.bookmark_scheduler.settings.BOOKMARK_CHECK_TIMES", "08:00,17:00"
        ):
            scheduler = create_scheduler()
            assert scheduler is not None
            assert len(scheduler.get_jobs()) == 2

    def test_enabled_with_no_valid_times_returns_none(self):
        with patch("app.services.bookmark_scheduler.settings.BOOKMARK_AUTO_CHECK_ENABLED", True), patch(
            "app.services.bookmark_scheduler.settings.BOOKMARK_CHECK_TIMES", ""
        ):
            assert create_scheduler() is None


def _mock_bookmark(value: str) -> MagicMock:
    bookmark = MagicMock()
    bookmark.value = value
    bookmark.ioc_type = IOCType.IP
    bookmark.display_name = f"Test {value}"
    return bookmark


class TestRunBookmarkCheckJob:
    async def test_db_failure_on_one_bookmark_rolls_back_and_continues_to_next(self):
        """Bir bookmark'ın recheck'i DB katmanında patlarsa, session rollback
        edilmeli ve döngü kalan bookmark'lara devam edebilmeli — aksi halde
        session'ın transaction'ı 'aborted' kalıp sonraki tüm bookmark'ları da
        sessizce başarısız kılar (bkz. bookmark_scheduler.py'deki rollback notu)."""
        bookmark_a = _mock_bookmark("1.1.1.1")
        bookmark_b = _mock_bookmark("2.2.2.2")

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [bookmark_a, bookmark_b]
        mock_db.execute.return_value = mock_result

        mock_session_cm = AsyncMock()
        mock_session_cm.__aenter__.return_value = mock_db
        mock_session_cm.__aexit__.return_value = False

        with patch("app.services.bookmark_scheduler.AsyncSessionLocal", return_value=mock_session_cm), patch(
            "app.services.bookmark_scheduler.AggregatedCTIProvider"
        ), patch(
            "app.services.bookmark_scheduler.recheck_bookmark_and_diff",
            AsyncMock(side_effect=[Exception("db patladı"), (MagicMock(), MagicMock())]),
        ) as mock_recheck, patch(
            "app.services.bookmark_scheduler.is_meaningful_change", return_value=False
        ), patch("app.services.bookmark_scheduler.send_bookmark_report"):
            await run_bookmark_check_job()

        assert mock_recheck.await_count == 2
        mock_db.rollback.assert_awaited_once()

    async def test_skips_run_if_previous_run_still_in_progress(self):
        """BOOKMARK_CHECK_TIMES'taki her saat farklı bir APScheduler job id'sidir,
        bu yüzden max_instances=1 aralarında koruma sağlamaz — modül seviyesindeki
        _job_lock, bir önceki çalışma bitmeden yenisinin başlamasını engellemeli."""
        async with bookmark_scheduler._job_lock:
            with patch("app.services.bookmark_scheduler.AsyncSessionLocal") as mock_session_factory:
                await run_bookmark_check_job()
                mock_session_factory.assert_not_called()
