"""İzleme listesi değişim raporlarını e-posta ile gönderen pasif istemci.

FortiGate/SIEM ile aynı felsefe: `EMAIL_ALERTS_ENABLED=False` (varsayılan)
iken hiçbir SMTP bağlantısı kurulmaz.

Rapor içeriği LLM'e YAZDIRILMAZ — `diff.py`'nin deterministik çıktısı
doğrudan HTML/düz metne dönüştürülür (bkz. diff.py'deki gerekçe: küçük
modelin nüanslı bir görevi güvenilir yapmasına güvenilmiyor). Sadece
`is_meaningful_change()` eşiğini aşan gerçek değişiklikler rapora girer —
her kontролde "değişiklik yok" e-postası atıp gürültü yaratmamak için.
"""

import html
import logging
import smtplib
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import settings
from app.schemas.bookmark import BookmarkDiff
from app.schemas.ioc import IOCAnalysisResponse

logger = logging.getLogger(__name__)

_SEVERITY_LABEL_TR = {"critical": "Kritik", "high": "Yüksek", "medium": "Orta", "low": "Düşük"}


@dataclass
class BookmarkChangeReport:
    display_name: str
    value: str
    ioc_type: str
    analysis: IOCAnalysisResponse
    diff: BookmarkDiff


def is_meaningful_change(diff: BookmarkDiff) -> bool:
    """E-postada raporlanmaya değer bir değişiklik mi?

    İlk kontrol (karşılaştıracak geçmiş yok) hiçbir zaman raporlanmaz.
    Aksi halde: önem derecesi değiştiyse, risk skoru
    `BOOKMARK_ALERT_MIN_SCORE_DELTA` eşiğini aştıysa, ya da açığa çıkan
    servis listesi değiştiyse "anlamlı" sayılır.
    """
    if diff.is_first_check:
        return False
    if diff.severity_changed:
        return True
    if diff.risk_score_delta is not None and abs(diff.risk_score_delta) >= settings.BOOKMARK_ALERT_MIN_SCORE_DELTA:
        return True
    if diff.new_exposed_services or diff.removed_exposed_services:
        return True
    return False


def _severity_tr(value) -> str:
    if value is None:
        return "-"
    key = value.value if hasattr(value, "value") else str(value)
    return _SEVERITY_LABEL_TR.get(key, key)


def _format_delta(delta: int | None) -> str:
    if delta is None:
        return "-"
    return f"+{delta}" if delta > 0 else str(delta)


def build_report_text(reports: list[BookmarkChangeReport], total_checked: int) -> str:
    lines = [
        f"AegisCTI İzleme Listesi Raporu",
        f"{total_checked} gösterge kontrol edildi, {len(reports)} tanesinde anlamlı değişiklik var.",
        "",
    ]
    for r in reports:
        lines.append(f"- {r.display_name} ({r.value}, {r.ioc_type.upper()})")
        lines.append(
            f"  Risk skoru: {r.diff.previous_risk_score} -> {r.analysis.risk_score} "
            f"({_format_delta(r.diff.risk_score_delta)})"
        )
        if r.diff.severity_changed:
            lines.append(f"  Önem: {_severity_tr(r.diff.previous_severity)} -> {_severity_tr(r.analysis.severity)}")
        if r.diff.new_exposed_services:
            lines.append(f"  Yeni açık servis: {', '.join(r.diff.new_exposed_services)}")
        if r.diff.removed_exposed_services:
            lines.append(f"  Artık açık olmayan servis: {', '.join(r.diff.removed_exposed_services)}")
        lines.append("")
    return "\n".join(lines)


def build_report_html(reports: list[BookmarkChangeReport], total_checked: int) -> str:
    rows = []
    for r in reports:
        severity_row = ""
        if r.diff.severity_changed:
            severity_row = (
                f'<div style="color:#e5484d;font-size:13px;margin-top:4px;">'
                f"Önem: {_severity_tr(r.diff.previous_severity)} → {_severity_tr(r.analysis.severity)}</div>"
            )
        services_row = ""
        if r.diff.new_exposed_services:
            services_row += (
                f'<div style="font-size:13px;color:#555;margin-top:4px;">'
                f"Yeni açık servis: {', '.join(r.diff.new_exposed_services)}</div>"
            )
        if r.diff.removed_exposed_services:
            services_row += (
                f'<div style="font-size:13px;color:#555;margin-top:4px;">'
                f"Artık açık olmayan servis: {', '.join(r.diff.removed_exposed_services)}</div>"
            )
        rows.append(f"""
        <tr>
          <td style="padding:12px 8px;border-bottom:1px solid #e2e2e2;">
            <b>{html.escape(r.display_name)}</b><br>
            <code style="font-size:12px;color:#666;">{html.escape(r.value)} · {html.escape(r.ioc_type.upper())}</code>
          </td>
          <td style="padding:12px 8px;border-bottom:1px solid #e2e2e2;">
            {r.diff.previous_risk_score} → <b>{r.analysis.risk_score}</b>
            <span style="color:#888;">({_format_delta(r.diff.risk_score_delta)})</span>
            {severity_row}
            {services_row}
          </td>
        </tr>
        """)

    return f"""
    <html>
      <body style="font-family:-apple-system,Segoe UI,Arial,sans-serif;color:#1a1a1a;max-width:640px;margin:0 auto;">
        <h2 style="margin-bottom:4px;">AegisCTI İzleme Listesi Raporu</h2>
        <p style="color:#666;font-size:14px;margin-top:0;">
          {total_checked} gösterge kontrol edildi, <b>{len(reports)}</b> tanesinde anlamlı değişiklik var.
        </p>
        <table style="width:100%;border-collapse:collapse;">
          <thead>
            <tr style="text-align:left;font-size:12px;color:#888;text-transform:uppercase;">
              <th style="padding:8px;border-bottom:2px solid #1a1a1a;">Gösterge</th>
              <th style="padding:8px;border-bottom:2px solid #1a1a1a;">Değişim</th>
            </tr>
          </thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
        <p style="color:#999;font-size:12px;margin-top:24px;">
          Bu rapor deterministik olarak (LLM'e yazdırılmadan) oluşturuldu — AegisCTI Faz 1.
        </p>
      </body>
    </html>
    """


def send_bookmark_report(reports: list[BookmarkChangeReport], total_checked: int) -> None:
    """Anlamlı değişiklik varsa e-posta gönderir; yoksa sessizce loglar.

    `EMAIL_ALERTS_ENABLED=False` (varsayılan) iken hiçbir SMTP bağlantısı
    kurmaz. Hata durumunda exception fırlatmaz — çağıran taraf (scheduler)
    bir e-posta gönderim hatası yüzünden çökmemeli.
    """
    if not settings.EMAIL_ALERTS_ENABLED:
        logger.info("E-posta bildirimleri devre dışı (EMAIL_ALERTS_ENABLED=false).")
        return
    if not reports:
        logger.info(
            "İzleme listesi kontrolü: %d gösterge kontrol edildi, anlamlı değişiklik yok, e-posta gönderilmedi.",
            total_checked,
        )
        return

    recipients = [addr.strip() for addr in (settings.ANALYST_EMAILS or "").split(",") if addr.strip()]
    if not recipients:
        logger.warning("EMAIL_ALERTS_ENABLED=true ama ANALYST_EMAILS boş, e-posta gönderilmedi.")
        return
    if not settings.SMTP_USERNAME or not settings.SMTP_PASSWORD:
        logger.warning("SMTP_USERNAME/SMTP_PASSWORD tanımlı değil, e-posta gönderilmedi.")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"AegisCTI İzleme Listesi Raporu — {len(reports)} göstergede değişiklik"
    msg["From"] = settings.SMTP_FROM_ADDRESS or settings.SMTP_USERNAME
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(build_report_text(reports, total_checked), "plain", "utf-8"))
    msg.attach(MIMEText(build_report_html(reports, total_checked), "html", "utf-8"))

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.sendmail(msg["From"], recipients, msg.as_string())
        logger.info("İzleme listesi raporu %d alıcıya gönderildi (%d değişiklik).", len(recipients), len(reports))
    except Exception as exc:  # noqa: BLE001 — e-posta hatası scheduler'ı çökertmemeli
        logger.error("E-posta gönderimi başarısız: %s", exc)
