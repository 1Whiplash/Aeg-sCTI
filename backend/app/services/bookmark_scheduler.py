"""İzleme listesindeki göstergeleri zamanlanmış olarak yeniden kontrol eder.

`BOOKMARK_AUTO_CHECK_ENABLED=False` (varsayılan) iken main.py bu
scheduler'ı hiç başlatmaz. Çalıştığında TÜM bookmark'ları sırayla (paralel
değil — Ollama zaten tek seferde bir çıkarım işliyor, bkz. README'deki
performans notu) yeniden analiz eder, deterministik diff hesaplar ve
ANLAMLI değişiklik varsa (bkz. email_service.is_meaningful_change) tek bir
özet e-postada raporlar.
"""

import asyncio
import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select

from app.core.config import settings
from app.db.session import AsyncSessionLocal
from app.models.bookmark import Bookmark
from app.services.bookmark_recheck import recheck_bookmark_and_diff
from app.services.cti_provider import AggregatedCTIProvider
from app.services.email_service import BookmarkChangeReport, is_meaningful_change, send_bookmark_report

logger = logging.getLogger(__name__)

# BOOKMARK_CHECK_TIMES'taki her saat, APScheduler'da AYRI bir job id'si olarak
# kaydedilir (bkz. create_scheduler). APScheduler'ın varsayılan max_instances=1
# koruması sadece AYNI job id'nin kendi kendiyle üst üste binmesini engeller —
# örn. 08:00 çalışması bitmeden 17:00 tetiklenirse (bookmark sayısı arttıkça
# gerçek bir risk), bu FARKLI job id'ler olduğu için ikisi paralel çalışabilir.
# Tüm job'lar aynı fonksiyonu çağırdığı için modül seviyesinde tek bir lock,
# job id'den bağımsız olarak üst üste binmeyi engeller.
_job_lock = asyncio.Lock()


def _parse_check_times(raw: str) -> list[tuple[int, int]]:
    """"08:00,17:00" -> [(8, 0), (17, 0)]. Geçersiz girdiler atlanır (loglanır)."""
    times: list[tuple[int, int]] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            hour_str, minute_str = part.split(":")
            hour, minute = int(hour_str), int(minute_str)
            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                raise ValueError("saat/dakika aralık dışı")
            times.append((hour, minute))
        except ValueError:
            logger.warning("BOOKMARK_CHECK_TIMES içinde geçersiz saat atlandı: %r", part)
    return times


async def run_bookmark_check_job() -> None:
    """Tüm bookmark'ları yeniden kontrol edip anlamlı değişiklikleri e-postayla raporlar.

    Farklı BOOKMARK_CHECK_TIMES saatleri farklı job id'leri olduğu için,
    bir önceki çalışma hâlâ sürüyorsa (uzun bir izleme listesi yüzünden)
    bu tetiklemeyi paralel başlatmak yerine atlar.
    """
    if _job_lock.locked():
        logger.warning(
            "Önceki zamanlanmış izleme listesi kontrolü hâlâ çalışıyor, bu tetikleme atlandı."
        )
        return

    async with _job_lock:
        await _run_bookmark_check_job_locked()


async def _run_bookmark_check_job_locked() -> None:
    logger.info("Zamanlanmış izleme listesi kontrolü başlıyor.")
    async with AsyncSessionLocal() as db:
        bookmarks = (await db.execute(select(Bookmark))).scalars().all()
        if not bookmarks:
            logger.info("İzleme listesinde gösterge yok, kontrol atlandı.")
            return

        provider = AggregatedCTIProvider(db)
        reports: list[BookmarkChangeReport] = []
        for bookmark in bookmarks:
            try:
                analysis, diff = await recheck_bookmark_and_diff(db, bookmark, provider)
            except Exception as exc:  # noqa: BLE001 — bir gösterge başarısız olsa da diğerleri devam etmeli
                logger.error("Zamanlanmış kontrol başarısız (%s): %s", bookmark.value, exc)
                # Hata bir DB işlemi sırasında oluştuysa (commit/execute), session'ın
                # transaction'ı "aborted" durumda kalır ve rollback yapılmadan sonraki
                # her db.execute() de aynı şekilde patlar — bu da tek bir DB hatasının
                # kalan tüm bookmark'ları sessizce iptal etmesine yol açar. Rollback,
                # session'ı bir sonraki bookmark için temiz bir transaction'a döndürür.
                await db.rollback()
                continue
            if is_meaningful_change(diff):
                reports.append(
                    BookmarkChangeReport(
                        display_name=bookmark.display_name,
                        value=bookmark.value,
                        ioc_type=bookmark.ioc_type.value,
                        analysis=analysis,
                        diff=diff,
                    )
                )

        logger.info(
            "İzleme listesi kontrolü bitti: %d gösterge kontrol edildi, %d anlamlı değişiklik.",
            len(bookmarks),
            len(reports),
        )
        # smtplib bloklayan bir kütüphane — event loop'u kilitlememesi için ayrı thread'de çalıştır.
        await asyncio.to_thread(send_bookmark_report, reports, len(bookmarks))


def create_scheduler() -> AsyncIOScheduler | None:
    """`BOOKMARK_AUTO_CHECK_ENABLED=False` ise None döner (hiçbir job kurulmaz)."""
    if not settings.BOOKMARK_AUTO_CHECK_ENABLED:
        logger.info("Bookmark otomatik kontrolü devre dışı (BOOKMARK_AUTO_CHECK_ENABLED=false).")
        return None

    check_times = _parse_check_times(settings.BOOKMARK_CHECK_TIMES)
    if not check_times:
        logger.warning("BOOKMARK_CHECK_TIMES içinde geçerli saat yok, scheduler kurulmadı.")
        return None

    scheduler = AsyncIOScheduler()
    for hour, minute in check_times:
        scheduler.add_job(
            run_bookmark_check_job,
            trigger=CronTrigger(hour=hour, minute=minute),
            id=f"bookmark-check-{hour:02d}{minute:02d}",
            replace_existing=True,
        )
    logger.info("Bookmark otomatik kontrolü kuruldu: %s", settings.BOOKMARK_CHECK_TIMES)
    return scheduler
