"""Syslog/CEF üzerinden pasif SIEM dışa aktarım istemcisi.

FortiGate entegrasyonuyla aynı felsefe (bkz. fortigate_service.py):
`SIEM_EXPORT_ENABLED=False` (varsayılan) iken hiçbir soket bağlantısı
kurulmaz. Açıldığında bile gönderim ASLA `/ioc/analyze` yanıt süresini
etkilememeli — SIEM ulaşılamaz/yavaşsa bile analiz akışı normal hızda
dönmeli. Bu yüzden gönderim `asyncio.to_thread` ile arka planda çalışır,
kısa bir zaman aşımı vardır ve her türlü hata sessizce loglanıp yutulur
(rate_limiter.py'deki "eksik altyapı düşük korumaya yol açar, hataya değil"
prensibiyle aynı).

CEF (Common Event Format), QRadar/ArcSight/Splunk/Elastic/Graylog dahil
hemen hemen her SIEM'in syslog üzerinden okuyabildiği evrensel bir format.
"""

import asyncio
import logging
import socket

from app.core.config import settings
from app.schemas.ioc import IOCAnalysisResponse

logger = logging.getLogger(__name__)

_SEND_TIMEOUT_SECONDS = 5.0
_SOCKET_TIMEOUT_SECONDS = 3.0

# CEF başlık alanlarında `\` ve `|`, extension değerlerinde `\` ve `=` kaçırılmalı.
_CEF_HEADER_ESCAPE = str.maketrans({"\\": "\\\\", "|": "\\|"})
_CEF_EXT_ESCAPE = str.maketrans({"\\": "\\\\", "=": "\\="})


def _cef_header_field(value: str) -> str:
    return value.translate(_CEF_HEADER_ESCAPE)


def _cef_ext_value(value: str) -> str:
    # Syslog mesajları tek satır olmalı; msg içindeki satır sonlarını temizle.
    return value.translate(_CEF_EXT_ESCAPE).replace("\n", " ").replace("\r", " ")


def build_cef_message(result: IOCAnalysisResponse) -> str:
    """Bir IOC analiz sonucunu CEF (Common Event Format) syslog mesajına çevirir."""
    # CEF severity 0-10 aralığında; risk_score (0-100) orantılı ölçekleniyor.
    cef_severity = max(0, min(10, result.risk_score // 10))

    header = "|".join(
        [
            "CEF:0",
            _cef_header_field("AegisCTI"),
            _cef_header_field("SOC-Platform"),
            _cef_header_field(settings.APP_VERSION),
            _cef_header_field("ioc-alert"),
            _cef_header_field("IOC Risk Alert"),
            str(cef_severity),
        ]
    )
    extension = (
        f"src={_cef_ext_value(result.value)} "
        f"cs1Label=IOCType cs1={_cef_ext_value(result.ioc_type.value)} "
        f"cs2Label=RiskScore cs2={result.risk_score} "
        f"cs3Label=Severity cs3={_cef_ext_value(result.severity.value)} "
        f"msg={_cef_ext_value(result.llm_analysis or '')}"
    )
    return f"{header}|{extension}"


def _send_sync(message: str) -> None:
    """Bloklayan soket işlemi — sadece `asyncio.to_thread` üzerinden çağrılmalı."""
    data = (message + "\n").encode("utf-8")
    sock_type = socket.SOCK_STREAM if settings.SIEM_PROTOCOL == "tcp" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, sock_type) as sock:
        sock.settimeout(_SOCKET_TIMEOUT_SECONDS)
        if settings.SIEM_PROTOCOL == "tcp":
            sock.connect((settings.SIEM_HOST, settings.SIEM_PORT))
            sock.sendall(data)
        else:
            sock.sendto(data, (settings.SIEM_HOST, settings.SIEM_PORT))


async def export_to_siem(result: IOCAnalysisResponse) -> None:
    """Risk skoru eşiği aşılmışsa sonucu SIEM'e CEF olarak gönderir.

    Hiçbir durumda exception fırlatmaz — çağıran taraf sonucu beklemek/
    kontrol etmek zorunda değildir (fire-and-forget).
    """
    if not settings.SIEM_EXPORT_ENABLED:
        return
    if result.risk_score < settings.SIEM_ALERT_THRESHOLD:
        return
    if not settings.SIEM_HOST:
        logger.warning("SIEM_EXPORT_ENABLED=true ama SIEM_HOST tanımlı değil, gönderim atlandı.")
        return

    message = build_cef_message(result)
    try:
        await asyncio.wait_for(asyncio.to_thread(_send_sync, message), timeout=_SEND_TIMEOUT_SECONDS)
        logger.info("SIEM'e CEF olayı gönderildi: %s (risk=%s)", result.value, result.risk_score)
    except Exception as exc:  # noqa: BLE001 — SIEM erişilemezliği analiz akışını asla etkilememeli
        logger.warning("SIEM'e gönderim başarısız: %s", exc)
