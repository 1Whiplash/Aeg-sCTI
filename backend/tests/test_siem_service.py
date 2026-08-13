"""siem_service.py'deki CEF mesaj oluşturma ve gönderim eşiği için birim testleri."""

from unittest.mock import AsyncMock, patch

import pytest

from app.core.enums import IOCType, Severity
from app.schemas.ioc import IOCAnalysisResponse
from app.services import siem_service
from app.services.siem_service import build_cef_message, export_to_siem


def _response(risk_score=75, value="1.2.3.4", llm_analysis="Zararli aktivite tespit edildi.") -> IOCAnalysisResponse:
    return IOCAnalysisResponse(
        value=value,
        ioc_type=IOCType.IP,
        risk_score=risk_score,
        severity=Severity.HIGH,
        llm_analysis=llm_analysis,
    )


class TestBuildCefMessage:
    def test_header_and_fields_present(self):
        message = build_cef_message(_response())
        assert message.startswith("CEF:0|AegisCTI|SOC-Platform|")
        assert "src=1.2.3.4" in message
        assert "cs1=ip" in message
        assert "cs2=75" in message
        assert "cs3=high" in message
        assert "msg=Zararli aktivite tespit edildi." in message

    def test_severity_scaled_to_0_10(self):
        assert "|7|" in build_cef_message(_response(risk_score=75))
        assert "|10|" in build_cef_message(_response(risk_score=100))
        assert "|0|" in build_cef_message(_response(risk_score=5))

    def test_pipe_and_equals_in_message_are_escaped(self):
        message = build_cef_message(_response(llm_analysis="Risk=yuksek | dikkat"))
        assert "msg=Risk\\=yuksek | dikkat" in message

    def test_newlines_in_message_stripped(self):
        message = build_cef_message(_response(llm_analysis="satir1\nsatir2"))
        assert "\n" not in message.split("msg=", 1)[1]


class TestExportToSiem:
    async def test_disabled_by_default_sends_nothing(self):
        with patch.object(siem_service.settings, "SIEM_EXPORT_ENABLED", False):
            with patch("app.services.siem_service._send_sync") as mock_send:
                await export_to_siem(_response())
                mock_send.assert_not_called()

    async def test_below_threshold_sends_nothing(self):
        with patch.object(siem_service.settings, "SIEM_EXPORT_ENABLED", True), patch.object(
            siem_service.settings, "SIEM_HOST", "127.0.0.1"
        ), patch.object(siem_service.settings, "SIEM_ALERT_THRESHOLD", 50):
            with patch("app.services.siem_service._send_sync") as mock_send:
                await export_to_siem(_response(risk_score=20))
                mock_send.assert_not_called()

    async def test_enabled_and_above_threshold_sends(self):
        with patch.object(siem_service.settings, "SIEM_EXPORT_ENABLED", True), patch.object(
            siem_service.settings, "SIEM_HOST", "127.0.0.1"
        ), patch.object(siem_service.settings, "SIEM_ALERT_THRESHOLD", 50):
            with patch("app.services.siem_service._send_sync") as mock_send:
                await export_to_siem(_response(risk_score=75))
                mock_send.assert_called_once()

    async def test_send_failure_never_raises(self):
        with patch.object(siem_service.settings, "SIEM_EXPORT_ENABLED", True), patch.object(
            siem_service.settings, "SIEM_HOST", "127.0.0.1"
        ), patch.object(siem_service.settings, "SIEM_ALERT_THRESHOLD", 50):
            with patch("app.services.siem_service._send_sync", side_effect=OSError("baglanti reddedildi")):
                await export_to_siem(_response(risk_score=75))  # exception firlatmamali
