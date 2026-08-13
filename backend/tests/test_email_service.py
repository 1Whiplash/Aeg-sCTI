"""email_service.py'deki anlamlı-değişiklik filtresi ve rapor oluşturma
mantığı için birim testleri (gerçek SMTP bağlantısı kurulmaz)."""

from unittest.mock import MagicMock, patch

from app.core.enums import IOCType, Severity
from app.schemas.bookmark import BookmarkDiff
from app.schemas.ioc import IOCAnalysisResponse
from app.services.email_service import (
    BookmarkChangeReport,
    build_report_html,
    build_report_text,
    is_meaningful_change,
    send_bookmark_report,
)


def _analysis(risk_score=45, severity=Severity.MEDIUM) -> IOCAnalysisResponse:
    return IOCAnalysisResponse(
        value="1.2.3.4", ioc_type=IOCType.IP, risk_score=risk_score, severity=severity, llm_analysis="test"
    )


def _report(diff: BookmarkDiff) -> BookmarkChangeReport:
    return BookmarkChangeReport(
        display_name="Test Sunucu", value="1.2.3.4", ioc_type="ip", analysis=_analysis(), diff=diff
    )


class TestIsMeaningfulChange:
    def test_first_check_is_never_meaningful(self):
        assert is_meaningful_change(BookmarkDiff(is_first_check=True)) is False

    def test_severity_change_is_meaningful(self):
        diff = BookmarkDiff(
            is_first_check=False, severity_changed=True, risk_score_delta=2,
            previous_risk_score=43, previous_severity=Severity.LOW,
        )
        assert is_meaningful_change(diff) is True

    def test_small_score_delta_is_not_meaningful(self):
        with patch("app.services.email_service.settings.BOOKMARK_ALERT_MIN_SCORE_DELTA", 15):
            diff = BookmarkDiff(is_first_check=False, severity_changed=False, risk_score_delta=5)
            assert is_meaningful_change(diff) is False

    def test_large_score_delta_is_meaningful(self):
        with patch("app.services.email_service.settings.BOOKMARK_ALERT_MIN_SCORE_DELTA", 15):
            diff = BookmarkDiff(is_first_check=False, severity_changed=False, risk_score_delta=-20)
            assert is_meaningful_change(diff) is True

    def test_new_exposed_service_is_meaningful(self):
        diff = BookmarkDiff(
            is_first_check=False, severity_changed=False, risk_score_delta=0,
            new_exposed_services=["RDP (3389)"],
        )
        assert is_meaningful_change(diff) is True

    def test_no_change_is_not_meaningful(self):
        diff = BookmarkDiff(is_first_check=False, severity_changed=False, risk_score_delta=0)
        assert is_meaningful_change(diff) is False


class TestReportBuilders:
    def test_text_report_contains_key_facts(self):
        diff = BookmarkDiff(
            is_first_check=False, previous_risk_score=20, previous_severity=Severity.LOW,
            risk_score_delta=25, severity_changed=True, new_exposed_services=["RDP (3389)"],
        )
        text = build_report_text([_report(diff)], total_checked=5)
        assert "5 gösterge kontrol edildi" in text
        assert "1 tanesinde" in text
        assert "Test Sunucu" in text
        assert "20 -> 45" in text
        assert "RDP (3389)" in text

    def test_html_report_contains_key_facts(self):
        diff = BookmarkDiff(is_first_check=False, previous_risk_score=20, risk_score_delta=25)
        html = build_report_html([_report(diff)], total_checked=3)
        assert "Test Sunucu" in html
        assert "1.2.3.4" in html
        assert "<table" in html

    def test_empty_reports_still_renders(self):
        text = build_report_text([], total_checked=4)
        html = build_report_html([], total_checked=4)
        assert "4 gösterge kontrol edildi" in text
        assert "<table" in html


class TestSendBookmarkReport:
    def test_disabled_sends_nothing(self):
        with patch("app.services.email_service.settings.EMAIL_ALERTS_ENABLED", False):
            with patch("smtplib.SMTP") as mock_smtp:
                send_bookmark_report([_report(BookmarkDiff(is_first_check=False))], 1)
                mock_smtp.assert_not_called()

    def test_no_reports_sends_nothing(self):
        with patch("app.services.email_service.settings.EMAIL_ALERTS_ENABLED", True):
            with patch("smtplib.SMTP") as mock_smtp:
                send_bookmark_report([], 5)
                mock_smtp.assert_not_called()

    def test_missing_recipients_sends_nothing(self):
        with patch("app.services.email_service.settings.EMAIL_ALERTS_ENABLED", True), patch(
            "app.services.email_service.settings.ANALYST_EMAILS", None
        ):
            with patch("smtplib.SMTP") as mock_smtp:
                send_bookmark_report([_report(BookmarkDiff(is_first_check=False))], 1)
                mock_smtp.assert_not_called()

    def test_enabled_with_recipients_sends_via_smtp(self):
        with patch("app.services.email_service.settings.EMAIL_ALERTS_ENABLED", True), patch(
            "app.services.email_service.settings.ANALYST_EMAILS", "analist@ornek.com"
        ), patch("app.services.email_service.settings.SMTP_USERNAME", "bot@ornek.com"), patch(
            "app.services.email_service.settings.SMTP_PASSWORD", "sifre"
        ):
            mock_server = MagicMock()
            with patch("smtplib.SMTP") as mock_smtp:
                mock_smtp.return_value.__enter__.return_value = mock_server
                send_bookmark_report([_report(BookmarkDiff(is_first_check=False))], 1)
                mock_server.login.assert_called_once_with("bot@ornek.com", "sifre")
                mock_server.sendmail.assert_called_once()

    def test_smtp_error_does_not_raise(self):
        with patch("app.services.email_service.settings.EMAIL_ALERTS_ENABLED", True), patch(
            "app.services.email_service.settings.ANALYST_EMAILS", "analist@ornek.com"
        ), patch("app.services.email_service.settings.SMTP_USERNAME", "bot@ornek.com"), patch(
            "app.services.email_service.settings.SMTP_PASSWORD", "sifre"
        ):
            with patch("smtplib.SMTP", side_effect=OSError("baglanti reddedildi")):
                send_bookmark_report([_report(BookmarkDiff(is_first_check=False))], 1)  # raise etmemeli
