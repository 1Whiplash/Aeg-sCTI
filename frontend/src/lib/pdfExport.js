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
 * jsPDF'in standart fontları (Helvetica) Türkçe karakterleri (ı, ş, ğ vb.)
 * doğru render edemiyor — PDF'e yazmadan önce ASCII karşılıklarına çeviriyoruz.
 */
function pdfSafe(text) {
  if (typeof text !== "string") return text;
  return text.replace(/[çÇğĞıİöÖşŞüÜ]/g, (char) => TR_TO_ASCII[char] ?? char);
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
  doc.text(summaryLines, MARGIN_X, y);
  y += summaryLines.length * 5 + 8;

  if (result.recommended_actions?.length > 0) {
    drawSectionTitle(doc, "Onerilen Aksiyonlar", y, accentColor);
    y += 8;
    doc.setFontSize(10);
    doc.setTextColor(40, 40, 40);
    result.recommended_actions.forEach((action, index) => {
      const lines = doc.splitTextToSize(pdfSafe(`${index + 1}. ${action}`), MAX_WIDTH);
      doc.text(lines, MARGIN_X, y);
      y += lines.length * 5 + 2;
    });
    y += 6;
  }

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
      if (y > pageHeight - 30) {
        doc.addPage();
        y = 20;
      }
      doc.setFont(undefined, "bold");
      doc.setFontSize(9);
      doc.setTextColor(...accentColor);
      doc.text(pdfSafe(item.source).toUpperCase(), MARGIN_X, y);
      doc.setFont(undefined, "normal");
      doc.setTextColor(60, 60, 60);
      y += 5;
      doc.setFontSize(8);
      const raw = doc.splitTextToSize(pdfSafe(JSON.stringify(item.raw_data, null, 2)), MAX_WIDTH);
      doc.text(raw, MARGIN_X, y);
      y += raw.length * 3.6 + 6;
    }
  }

  drawFooter(doc);
  doc.save(`aegisci-${result.value}-${Date.now()}.pdf`);
}
