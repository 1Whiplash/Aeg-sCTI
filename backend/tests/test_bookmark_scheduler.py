"""bookmark_scheduler.py'deki saat ayrıştırma ve scheduler kurulum
mantığı için birim testleri (gerçek bir zamanlanmış görev çalıştırmaz)."""

from unittest.mock import patch

from app.services.bookmark_scheduler import _parse_check_times, create_scheduler


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
