"""Ollama (Qwen 2.5) üzerinden yapılandırılmış (structured output) SOC analiz servisi.

Model çıktısı, Ollama'nın `format` parametresine `LLMAnalysisResult`'ın JSON şeması
verilerek zorlanır — yani model şemaya uymayan bir metin üretemez.

Küçük (7B) model bazen prompt talimatına rağmen yanıtın içine yabancı alfabe
(Çince/Japonca/Kiril/Arapça) karıştırabiliyor. Bu, prompt sıkılaştırmasıyla
tamamen önlenemediği için ek bir güvence katmanı var: çıktı kontrol edilir,
kirlenme tespit edilirse bir kez daha (daha sert bir uyarıyla) denenir; hâlâ
düzelmezse kullanıcıya bozuk metin göstermek yerine güvenli bir mesaja düşülür.
"""

import logging
import re

import httpx

from app.core.config import settings
from app.core.enums import IOCType
from app.schemas.ioc import OSINTEvidence
from app.schemas.llm import LLMAnalysisResult
from app.services.interfaces import ILLMEnrichmentService

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "Sen deneyimli bir SOC (Security Operations Center) analistisin. Sana bir tehdit "
    "göstergesi (IP, domain, hash veya URL) hakkında toplanmış ham OSINT verisi verilecek "
    "(bu ham veri İngilizce olabilir, kaynak API'lerden geldiği gibi kalır).\n\n"
    "KURALLAR:\n"
    "1. `threat_summary` ve `recommended_actions` alanlarındaki TÜM metin, ham OSINT verisi "
    "İngilizce olsa dahi, kesinlikle ve eksiksiz TÜRKÇE olmalıdır. Tek bir İngilizce, Çince, "
    "Japonca, Korece, Rusça veya başka bir dilden kelime/cümle bile kullanma; teknik terimlerin "
    "de Türkçe karşılığını kullan.\n"
    "2. Profesyonel bir SOC analistinin kurumsal raporlama diliyle, net, teknik ama anlaşılır yaz.\n"
    "3. `risk_score`'u SADECE somut, olumsuz kanıta dayandır (örn. VirusTotal motor tespiti, "
    "gerçek kötüye kullanım şikayeti, bilinen zararlı IP/domain/hash eşleşmesi). SSL sertifikası, "
    "SPF/DKIM/DMARC, CAA kaydı gibi standart güvenlik önlemlerinin VARLIĞI her zaman OLUMLU bir "
    "işarettir — bunları ASLA risk gerekçesi olarak gösterme. Çok sayıda TXT/DNS kaydı büyük "
    "kurumsal sitelerde normaldir ve tek başına şüpheli değildir. Somut kötü niyet kanıtı yoksa "
    "risk_score düşük olmalıdır (0-20 aralığı).\n"
    "4. İncelenen gösterge (IP/domain/URL/hash), analistin KENDİ kurumunun bir varlığı DEĞİL, "
    "dışarıdan gözlemlenen üçüncü taraf bir hedeftir; analistin o sunucu/servis üzerinde HİÇBİR "
    "yönetim yetkisi yoktur. Bu yüzden `recommended_actions` içinde 'şu servisi kapatın', 'şu "
    "sunucuyu yapılandırın', 'pg_hba.conf dosyasını düzenleyin', 'şifreleme ayarlayın' gibi "
    "hedefi doğrudan yönetebileceğini varsayan İFADELERİ ASLA KULLANMA — bunlar analistin "
    "yapamayacağı şeylerdir. Bunun yerine SADECE analistin kendi ortamında yapabileceği şeyleri "
    "öner. Örnek: 'RDP hizmetini kapatın' YANLIŞ, 'Bu IP'den gelen RDP (3389) trafiğini kendi "
    "güvenlik duvarınızda engelleyin ve izleyin' DOĞRU. 'PostgreSQL'i yapılandırın' YANLIŞ, 'Bu "
    "IP'yi CTI platformunda işaretleyip veritabanı sunucularınıza erişim loglarını gözden "
    "geçirin' DOĞRU. Diğer örnekler: izlemeye almak, whitelist dışı bırakmak, ilgili abuse/NOC "
    "iletişim adresine (varsa) bildirmek, gösterge gerçekten kurum içi bir varlıksa ilgili ekiple "
    "paylaşmak.\n"
    "5. SADECE istenen JSON şemasına uyan bir çıktı üret. Ek açıklama, yorum veya markdown "
    "ekleme; sadece geçerli JSON döndür."
)

_FALLBACK_RESULT = LLMAnalysisResult(
    risk_score=0,
    threat_summary="LLM servisi şu anda kullanılamıyor.",
    recommended_actions=[],
)

# CJK (Çince/Japonca), Hangul (Korece), Kiril ve Arapça alfabe aralıkları.
_NON_TURKISH_SCRIPT = re.compile(
    r"[一-鿿぀-ヿ가-힯Ѐ-ӿ؀-ۿ]"
)


class OllamaAnalysisService(ILLMEnrichmentService):
    """Ollama'nın /api/generate uç noktasını çağıran async istemci."""

    def __init__(self) -> None:
        self._base_url = settings.OLLAMA_BASE_URL
        self._model = settings.OLLAMA_MODEL
        self._timeout = settings.OLLAMA_REQUEST_TIMEOUT

    async def analyze(
        self, value: str, ioc_type: IOCType, osint_evidence: list[OSINTEvidence]
    ) -> LLMAnalysisResult:
        result = await self._generate(value, ioc_type, osint_evidence)

        if result is not None and self._is_contaminated(result):
            logger.warning(
                "LLM çıktısında yabancı alfabe tespit edildi (%s), sıkılaştırılmış promptla tekrar deneniyor.",
                value,
            )
            retry = await self._generate(value, ioc_type, osint_evidence, reinforce=True)
            result = retry if retry is not None else result

        if result is None:
            return _FALLBACK_RESULT

        if self._is_contaminated(result):
            logger.error(
                "LLM ikinci denemede de Türkçe kuralına uymadı (%s), güvenli mesaja düşülüyor.", value
            )
            return LLMAnalysisResult(
                risk_score=result.risk_score,
                threat_summary=(
                    "LLM bu gösterge için güvenilir bir Türkçe özet üretemedi. "
                    "Aşağıdaki OSINT kanıtlarını manuel olarak inceleyin."
                ),
                recommended_actions=["OSINT kanıtlarını manuel olarak gözden geçirin."],
            )

        return result

    async def _generate(
        self,
        value: str,
        ioc_type: IOCType,
        osint_evidence: list[OSINTEvidence],
        reinforce: bool = False,
    ) -> LLMAnalysisResult | None:
        prompt = self._build_prompt(value, ioc_type, osint_evidence, reinforce)

        payload = {
            "model": self._model,
            "system": _SYSTEM_PROMPT,
            "prompt": prompt,
            "stream": False,
            "format": LLMAnalysisResult.model_json_schema(),
            # Risk skorlaması bir sınıflandırma görevi, yaratıcılığa gerek yok.
            # Düşük sıcaklık olmadan aynı kanıtlarla her çağrıda farklı bir
            # risk_score/metin üretiliyordu (bkz. Aktivite geçmişindeki
            # google.com için 21-42 arası savrulan skorlar).
            "options": {"temperature": 0, "seed": 42},
        }

        async with httpx.AsyncClient(base_url=self._base_url, timeout=self._timeout) as client:
            try:
                response = await client.post("/api/generate", json=payload)
                response.raise_for_status()
                raw_output = response.json().get("response", "")
                return LLMAnalysisResult.model_validate_json(raw_output)
            except httpx.HTTPError as exc:
                logger.error("Ollama isteği başarısız: %s", exc)
                return None
            except ValueError as exc:
                logger.error("Ollama çıktısı beklenen şemaya uymuyor: %s", exc)
                return None

    @staticmethod
    def _is_contaminated(result: LLMAnalysisResult) -> bool:
        combined = result.threat_summary + " ".join(result.recommended_actions)
        return bool(_NON_TURKISH_SCRIPT.search(combined))

    @staticmethod
    def _build_prompt(
        value: str, ioc_type: IOCType, osint_evidence: list[OSINTEvidence], reinforce: bool
    ) -> str:
        evidence_json = [item.model_dump(mode="json") for item in osint_evidence]
        reminder = (
            "HATIRLATMA: `threat_summary` ve `recommended_actions` alanlarını baştan sona "
            "MUTLAKA TÜRKÇE yaz. Yukarıdaki OSINT verisi İngilizce olsa bile, cevabında tek "
            "bir İngilizce/Çince/Japonca/Korece/Rusça kelime veya cümle KULLANMA."
        )
        if reinforce:
            reminder = (
                "SON UYARI: Önceki cevabın Türkçe DIŞINDA bir alfabe (Çince/Japonca/Korece/Kiril/"
                "Arapça) içeriyordu, bu KABUL EDİLEMEZ. Bu kez `threat_summary` ve "
                "`recommended_actions` alanlarındaki HER KELİME sadece Türk alfabesindeki "
                "harflerden (a-z, ç, ğ, ı, ö, ş, ü) oluşmalı. Başka hiçbir alfabe kullanma."
            )
        return (
            f"Gösterge: {value} (tip: {ioc_type.value})\n\n"
            f"Toplanan OSINT kanıtları:\n{evidence_json}\n\n{reminder}"
        )


def get_llm_service() -> ILLMEnrichmentService:
    """FastAPI dependency injection için factory fonksiyonu."""
    return OllamaAnalysisService()
