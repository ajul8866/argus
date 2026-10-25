/**
 * Minimal dependency-free PDF writer used only when a headless Chrome binary
 * is unavailable. It emits text-only, paginated reports with Helvetica.
 */
export function buildFallbackPdf(lines: string[], title: string): Uint8Array {
  const pageWidth = 612;
  const pageHeight = 792;
  const margin = 50;
  const fontSize = 9;
  const lineHeight = 12;
  const maxLines = Math.floor((pageHeight - margin * 2 - 30) / lineHeight);
  const prepared: string[] = [];
  prepared.push(title);
  prepared.push(`Generated: ${new Date().toISOString()}`);
  prepared.push("");
  for (const raw of lines) {
    const clean = raw
      .replace(/\r/g, "")
      .replace(/[#*_]/g, "")
      .replace(/^-\s+/, "• ")
      .replace(/^\d+\.\s+/, (match) => match)
      .replace(/\t/g, "    ");
    if (clean.trim() === "") {
      prepared.push("");
      continue;
    }
    for (const wrapped of wrap(clean, 104)) prepared.push(wrapped);
  }

  const pages: string[][] = [];
  for (let index = 0; index < prepared.length; index += maxLines) {
    pages.push(prepared.slice(index, index + maxLines));
  }
  if (pages.length === 0) pages.push([title]);

  const objects: string[] = [];
  const pageIds = Array.from({ length: pages.length }, (_, index) => 3 + index * 2);
  const fontObjectId = 3 + pages.length * 2;
  const catalogId = 1;
  const pagesId = 2;
  objects.push(`<< /Type /Catalog /Pages ${pagesId} 0 R >>`);
  objects.push(
    `<< /Type /Pages /Kids [${pageIds.map((pageId) => `${pageId} 0 R`).join(" ")}] /Count ${pages.length} >>`,
  );
  for (let index = 0; index < pages.length; index += 1) {
    const pageId = pageIds[index]!;
    const contentId = pageId + 1;
    objects.push(
      `<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 ${pageWidth} ${pageHeight}] /Resources << /Font << /F1 ${fontObjectId} 0 R >> >> /Contents ${contentId} 0 R >>`,
    );
    const body = pages[index] ?? [];
    const streamLines: string[] = [];
    streamLines.push("BT");
    streamLines.push(`/F1 14 Tf ${margin} ${pageHeight - margin} Td (${pdfEscape(body[0] ?? title)}) Tj`);
    streamLines.push(`/F1 ${fontSize} Tf 0 -20 Td ${lineHeight} TL`);
    for (const line of body.slice(1)) {
      streamLines.push(`(${pdfEscape(line)}) Tj T*`);
    }
    streamLines.push("ET");
    streamLines.push(`BT /F1 8 Tf ${margin} ${margin - 18} Td (Page ${index + 1} of ${pages.length}) Tj ET`);
    const stream = streamLines.join("\n");
    objects.push(`<< /Length ${Buffer.byteLength(stream, "latin1")} >>\nstream\n${stream}\nendstream`);
  }
  objects.push(`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>`);

  let pdf = "%PDF-1.4\n%\u00e2\u00e3\u00cf\u00d3\n";
  const offsets: number[] = [];
  for (let index = 0; index < objects.length; index += 1) {
    offsets.push(Buffer.byteLength(pdf, "latin1"));
    pdf += `${index + 1} 0 obj\n${objects[index]}\nendobj\n`;
  }
  const xrefOffset = Buffer.byteLength(pdf, "latin1");
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets) {
    pdf += `${String(offset).padStart(10, "0")} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root ${catalogId} 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  return new Uint8Array(Buffer.from(pdf, "latin1"));
}

function wrap(text: string, width: number): string[] {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = "";
  for (const word of words) {
    if (current.length === 0) {
      current = word;
    } else if (current.length + word.length + 1 <= width) {
      current += ` ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);
  return lines.length > 0 ? lines : [""];
}

function pdfEscape(text: string): string {
  return text
    .replace(/[\u0000-\u001f\u007f-\u009f\u0100-\uffff]/g, "?")
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}
