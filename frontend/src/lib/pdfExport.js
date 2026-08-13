import jsPDF from "jspdf";

const SEVERITY_COLORS = {
  critical: [220, 38, 38],
  high: [234, 88, 12],
  medium: [217, 158, 10],
  low: [22, 163, 74],
};
const DEFAULT_SEVERITY_COLOR = [107, 114, 128];

const HEADER_BG = [15, 23, 42]; // #0F172A - Obsidian Dark kart rengi

const MARGIN_X = 14;
const MAX_WIDTH = 180;
const LINE_HEIGHT = 5;
const RAW_LINE_HEIGHT = 3.6;
const MAX_RAW_LINES = 25;

const SOURCE_LABELS = {
  virustotal: "VIRUSTOTAL",
  abuseipdb: "ABUSEIPDB",
  shodan: "SHODAN",
  web_scraper: "WHOIS / WEB TARAMASI",
};

const TR_TO_ASCII = {
  ç: "c",
  Ç: "C",
  ğ: "g",
  Ğ: "G",
  ı: "i",
  İ: "I",
  ö: "o",
  Ö: "O",
  ş: "s",
  Ş: "S",
  ü: "u",
  Ü: "U",
};

/**
 * jsPDF'in standart fontları (Helvetica) Türkçe karakterleri doğru render edemiyor
 * ve ASCII dışı herhangi bir Unicode karakterde (Kiril, Arapça, CJK vb.) bozuk
 * kutu/glif üretiyor — önce Türkçe karşılıklarına çeviriyor, sonra kalan tüm
 * ASCII-dışı karakterleri güvenli şekilde eliyoruz.
 */
function pdfSafe(text) {
  if (typeof text !== "string") return text;
  const transliterated = text.replace(/[çÇğĞıİöÖşŞüÜ]/g, (char) => TR_TO_ASCII[char] ?? char);
  return transliterated.replace(/[^\x00-\x7F]/g, "");
}

function drawHeader(doc, result) {
  const pageWidth = doc.internal.pageSize.getWidth();
  doc.setFillColor(...HEADER_BG);
  doc.rect(0, 0, pageWidth, 28, "F");

  doc.setTextColor(255, 255, 255);
  doc.setFont(undefined, "bold");
  doc.setFontSize(16);
  doc.text("AegisCTI", MARGIN_X, 13);

  doc.setFont(undefined, "normal");
  doc.setFontSize(9);
  doc.setTextColor(190, 200, 220);
  doc.text(pdfSafe("Otonom Tehdit Istihbarati - Analiz Raporu"), MARGIN_X, 20);

  doc.setFontSize(8);
  doc.text(
    new Date(result.analyzed_at).toLocaleString("tr-TR"),
    pageWidth - MARGIN_X,
    20,
    { align: "right" },
  );
}

function drawSeverityBadge(doc, severity, x, y) {
  const color = SEVERITY_COLORS[severity] ?? DEFAULT_SEVERITY_COLOR;
  const label = pdfSafe(severity).toUpperCase();
  doc.setFont(undefined, "bold");
  doc.setFontSize(9);
  const width = doc.getTextWidth(label) + 10;

  doc.setFillColor(...color);
  doc.roundedRect(x, y, width, 8, 2, 2, "F");
  doc.setTextColor(255, 255, 255);
  doc.text(label, x + 5, y + 5.5);
  doc.setFont(undefined, "normal");
  return width;
}

function drawSectionTitle(doc, title, y, accentColor) {
  doc.setFont(undefined, "bold");
  doc.setFontSize(12);
  doc.setTextColor(30, 30, 30);
  doc.text(pdfSafe(title), MARGIN_X, y);

  doc.setDrawColor(...accentColor);
  doc.setLineWidth(0.7);
  doc.line(MARGIN_X, y + 1.8, MARGIN_X + 36, y + 1.8);
  doc.setFont(undefined, "normal");
}

function drawFooter(doc) {
  const pageHeight = doc.internal.pageSize.getHeight();
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    doc.text(
      pdfSafe(`AegisCTI - Faz 1 Read-Only SOC Platformu | Sayfa ${i}/${pageCount}`),
      MARGIN_X,
      pageHeight - 10,
    );
  }
}

/** VirusTotal/AbuseIPDB gibi bilinen kaynaklar için ham JSON yerine okunaklı madde
 * listesi üretir. Tanınmayan kaynaklar için null döner (çağıran taraf ham veriye düşer). */
function summarizeEvidence(item) {
  const data = item.raw_data;

  if (item.source === "virustotal" && data?.data?.attributes) {
    const attrs = data.data.attributes;
    const lines = [];
    const stats = attrs.last_analysis_stats;
    if (stats) {
      const total = Object.values(stats).reduce((sum, v) => sum + (Number(v) || 0), 0);
      lines.push(`Motor tespiti: ${stats.malicious ?? 0}/${total} zararli, ${stats.suspicious ?? 0} supheli olarak isaretledi`);
    }
    const results = attrs.last_analysis_results;
    if (results) {
      const maliciousNames = Object.entries(results)
        .filter(([, v]) => v?.category === "malicious")
        .map(([name]) => name);
      const suspiciousNames = Object.entries(results)
        .filter(([, v]) => v?.category === "suspicious")
        .map(([name]) => name);
      if (maliciousNames.length > 0) {
        lines.push(`Zararli isaretleyen motorlar: ${maliciousNames.join(", ")}`);
      }
      if (suspiciousNames.length > 0) {
        lines.push(`Supheli isaretleyen motorlar: ${suspiciousNames.join(", ")}`);
      }
    }
    if (Array.isArray(attrs.names) && attrs.names.length > 0) {
      lines.push(`Bilinen dosya/gosterge adlari: ${attrs.names.slice(0, 3).join(", ")}`);
    }
    if (typeof attrs.reputation === "number") {
      lines.push(`VirusTotal itibar puani: ${attrs.reputation}`);
    }
    if (attrs.last_modification_date) {
      lines.push(`Son guncelleme: ${new Date(attrs.last_modification_date * 1000).toLocaleDateString("tr-TR")}`);
    }
    return lines.length > 0 ? lines : null;
  }

  if (item.source === "abuseipdb" && data?.data) {
    const d = data.data;
    const lines = [];
    if (typeof d.abuseConfidenceScore === "number") {
      lines.push(`Kotuye kullanim guven skoru: %${d.abuseConfidenceScore}`);
    }
    if (typeof d.totalReports === "number") {
      lines.push(`Toplam sikayet sayisi: ${d.totalReports}`);
    }
    if (d.countryCode) lines.push(`Ulke: ${d.countryCode}`);
    if (d.isp) lines.push(`Servis saglayici (ISS): ${d.isp}`);
    if (d.domain) lines.push(`Iliskili domain: ${d.domain}`);
    return lines.length > 0 ? lines : null;
  }

  if (item.source === "web_scraper" && data) {
    if (data.skipped_reason) {
      return [`Guvenlik nedeniyle taranmadi: ${data.skipped_reason}`];
    }

    const lines = [];
    if (data.page_title) lines.push(`Sayfa basligi: ${data.page_title}`);
    if (data.status_code) lines.push(`HTTP durum kodu: ${data.status_code}`);
    if (data.redirect_location) lines.push(`Yonlendirme hedefi: ${data.redirect_location}`);
    if (data.fetch_error) lines.push(`Sayfa taranamadi: ${data.fetch_error}`);

    if (data.whois_registrar) lines.push(`WHOIS kayit sirketi: ${data.whois_registrar}`);
    if (data.whois_creation_date) lines.push(`WHOIS olusturulma tarihi: ${data.whois_creation_date}`);
    if (data.whois_error) lines.push(`WHOIS sorgusu yapilamadi: ${data.whois_error}`);

    if (typeof data.ssl_cert_age_days === "number") {
      lines.push(`SSL sertifika yasi: ${data.ssl_cert_age_days} gun`);
    }
    if (data.ssl_error) lines.push(`SSL sertifika bilgisi alinamadi: ${data.ssl_error}`);

    return lines.length > 0 ? lines : null;
  }

  return null;
}

function ensureSpace(doc, y, pageHeight, needed = 15) {
  if (y > pageHeight - needed) {
    doc.addPage();
    return 20;
  }
  return y;
}

function drawEvidenceBlock(doc, item, y, pageHeight, accentColor) {
  y = ensureSpace(doc, y, pageHeight, 20);

  doc.setFont(undefined, "bold");
  doc.setFontSize(9);
  doc.setTextColor(...accentColor);
  doc.text(SOURCE_LABELS[item.source] ?? pdfSafe(item.source).toUpperCase(), MARGIN_X, y);
  doc.setFont(undefined, "normal");
  doc.setTextColor(60, 60, 60);
  y += 5;

  const summary = summarizeEvidence(item);

  if (summary) {
    doc.setFontSize(9);
    for (const line of summary) {
      y = ensureSpace(doc, y, pageHeight);
      const wrapped = doc.splitTextToSize(`- ${pdfSafe(line)}`, MAX_WIDTH);
      for (const w of wrapped) {
        y = ensureSpace(doc, y, pageHeight);
        doc.text(w, MARGIN_X + 2, y);
        y += LINE_HEIGHT;
      }
    }
    return y + 3;
  }

  doc.setFontSize(8);
  doc.setFont("courier", "normal");
  let rawLines = doc.splitTextToSize(pdfSafe(JSON.stringify(item.raw_data, null, 2)), MAX_WIDTH);
  const truncated = rawLines.length > MAX_RAW_LINES;
  if (truncated) rawLines = rawLines.slice(0, MAX_RAW_LINES);

  for (const line of rawLines) {
    y = ensureSpace(doc, y, pageHeight);
    doc.text(line, MARGIN_X, y);
    y += RAW_LINE_HEIGHT;
  }
  if (truncated) {
    y = ensureSpace(doc, y, pageHeight);
    doc.setFont(undefined, "italic");
    doc.text("(...devami uygulama arayuzunde goruntulenebilir)", MARGIN_X, y);
    y += RAW_LINE_HEIGHT;
  }
  doc.setFont(undefined, "normal");
  return y + 6;
}

/** Bir IOC analiz sonucunu tek tıkla kurumsal görünümlü bir PDF raporu olarak indirir. */
export function exportAnalysisPdf(result) {
  const doc = new jsPDF();
  const pageHeight = doc.internal.pageSize.getHeight();
  const accentColor = SEVERITY_COLORS[result.severity] ?? DEFAULT_SEVERITY_COLOR;

  drawHeader(doc, result);

  let y = 40;

  doc.setTextColor(20, 20, 20);
  doc.setFont(undefined, "bold");
  doc.setFontSize(14);
  doc.text(pdfSafe(result.value), MARGIN_X, y);
  y += 7;

  doc.setFont(undefined, "normal");
  doc.setFontSize(10);
  doc.setTextColor(90, 90, 90);
  doc.text(`Tip: ${result.ioc_type.toUpperCase()}`, MARGIN_X, y);
  y += 10;

  doc.setFont(undefined, "bold");
  doc.setFontSize(11);
  doc.setTextColor(20, 20, 20);
  doc.text(`Risk Skoru: ${result.risk_score}/100`, MARGIN_X, y + 5.5);
  drawSeverityBadge(doc, result.severity, MARGIN_X + 70, y);
  y += 18;

  drawSectionTitle(doc, "AI SOC Analisti Raporu", y, accentColor);
  y += 8;
  doc.setFontSize(10);
  doc.setTextColor(40, 40, 40);
  const summaryLines = doc.splitTextToSize(pdfSafe(result.llm_analysis || "-"), MAX_WIDTH);
  for (const line of summaryLines) {
    y = ensureSpace(doc, y, pageHeight);
    doc.text(line, MARGIN_X, y);
    y += LINE_HEIGHT;
  }
  y += 6;

  if (result.recommended_actions?.length > 0) {
    y = ensureSpace(doc, y, pageHeight, 25);
    drawSectionTitle(doc, "Onerilen Aksiyonlar", y, accentColor);
    y += 8;
    doc.setFontSize(10);
    doc.setTextColor(40, 40, 40);
    result.recommended_actions.forEach((action, index) => {
      const lines = doc.splitTextToSize(pdfSafe(`${index + 1}. ${action}`), MAX_WIDTH);
      for (const line of lines) {
        y = ensureSpace(doc, y, pageHeight);
        doc.text(line, MARGIN_X, y);
        y += LINE_HEIGHT;
      }
      y += 1;
    });
    doc.setFont(undefined, "italic");
    doc.setFontSize(8);
    doc.setTextColor(120, 120, 120);
    const disclaimer = doc.splitTextToSize(
      pdfSafe(
        "Not: Bu oneriler LLM tarafindan uretildi ve bazen hedefi dogrudan yonetebileceginizi " +
          "varsayan ifadeler icerebilir. Gosterge sizin kontrolunuzde degilse, sadece " +
          "izleme/engelleme adimlarini uygulayin.",
      ),
      MAX_WIDTH,
    );
    for (const line of disclaimer) {
      y = ensureSpace(doc, y, pageHeight);
      doc.text(line, MARGIN_X, y);
      y += RAW_LINE_HEIGHT;
    }
    doc.setFont(undefined, "normal");
    doc.setTextColor(40, 40, 40);
    y += 4;
  }

  if (result.exposed_services?.length > 0) {
    y = ensureSpace(doc, y, pageHeight, 20);
    drawSectionTitle(doc, "Acika Cikan Riskli Servisler", y, accentColor);
    y += 8;
    doc.setFontSize(10);
    doc.setTextColor(40, 40, 40);
    doc.text(pdfSafe(result.exposed_services.join(", ")), MARGIN_X, y);
    y += LINE_HEIGHT + 3;
    doc.setFontSize(8);
    doc.setTextColor(120, 120, 120);
    doc.setFont(undefined, "italic");
    const note = doc.splitTextToSize(
      pdfSafe(
        "Shodan'a gore acik - risk skorunu etkilemez, saldiri yuzeyi hakkinda bilgi verir.",
      ),
      MAX_WIDTH,
    );
    for (const line of note) {
      y = ensureSpace(doc, y, pageHeight);
      doc.text(line, MARGIN_X, y);
      y += RAW_LINE_HEIGHT;
    }
    doc.setFont(undefined, "normal");
    y += 4;
  }

  y = ensureSpace(doc, y, pageHeight, 25);
  drawSectionTitle(doc, "OSINT Kanitlari", y, accentColor);
  y += 8;

  if (result.osint_evidence.length === 0) {
    doc.setFont(undefined, "italic");
    doc.setFontSize(9);
    doc.setTextColor(120, 120, 120);
    doc.text(pdfSafe("Hicbir kaynaktan veri donmedi."), MARGIN_X, y);
    doc.setFont(undefined, "normal");
  } else {
    for (const item of result.osint_evidence) {
      y = drawEvidenceBlock(doc, item, y, pageHeight, accentColor);
    }
  }

  drawFooter(doc);
  doc.save(`aegisci-${result.value}-${Date.now()}.pdf`);
}
