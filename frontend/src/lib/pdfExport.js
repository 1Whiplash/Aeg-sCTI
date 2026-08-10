import jsPDF from "jspdf";

/** Bir IOC analiz sonucunu tek sayfalık kurumsal bir PDF raporu olarak indirir. */
export function exportAnalysisPdf(result) {
  const doc = new jsPDF();
  const marginX = 14;
  const maxWidth = 180;
  let y = 18;

  doc.setFontSize(16);
  doc.text("AegisCTI - Tehdit Analiz Raporu", marginX, y);
  y += 8;

  doc.setFontSize(10);
  doc.setTextColor(100);
  doc.text(`Oluşturulma: ${new Date(result.analyzed_at).toLocaleString("tr-TR")}`, marginX, y);
  y += 10;

  doc.setTextColor(0);
  doc.setFontSize(12);
  doc.text(`Gösterge: ${result.value}`, marginX, y);
  y += 7;
  doc.text(`Tip: ${result.ioc_type.toUpperCase()}`, marginX, y);
  y += 7;
  doc.text(`Risk Skoru: ${result.risk_score}/100`, marginX, y);
  y += 7;
  doc.text(`Önem Derecesi: ${result.severity.toUpperCase()}`, marginX, y);
  y += 10;

  doc.setFontSize(13);
  doc.text("AI SOC Analisti Raporu", marginX, y);
  y += 7;
  doc.setFontSize(10);
  const summaryLines = doc.splitTextToSize(result.llm_analysis || "-", maxWidth);
  doc.text(summaryLines, marginX, y);
  y += summaryLines.length * 5 + 10;

  doc.setFontSize(13);
  doc.text("OSINT Kanıtları", marginX, y);
  y += 7;
  doc.setFontSize(9);

  if (result.osint_evidence.length === 0) {
    doc.text("Hiçbir kaynaktan veri dönmedi.", marginX, y);
  } else {
    for (const item of result.osint_evidence) {
      if (y > 270) {
        doc.addPage();
        y = 18;
      }
      doc.setFont(undefined, "bold");
      doc.text(item.source, marginX, y);
      doc.setFont(undefined, "normal");
      y += 5;
      const raw = doc.splitTextToSize(JSON.stringify(item.raw_data, null, 2), maxWidth);
      doc.text(raw, marginX, y);
      y += raw.length * 4 + 6;
    }
  }

  doc.save(`aegisci-${result.value}-${Date.now()}.pdf`);
}
