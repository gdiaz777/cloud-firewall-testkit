// Shared helpers for the Word documents (docx npm).
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, ImageRun, Header, Footer,
  AlignmentType, WidthType, ShadingType, BorderStyle, LevelFormat, PageNumber, PageBreak,
  HeadingLevel, TableOfContents, VerticalAlign,
} = require("docx");

const FONT = "Arial";
const C = { navy: "1F2937", accent: "C8102E", blue: "1D4ED8", muted: "6B7280", line: "D1D5DB",
  head: "1F2937", zebra: "F9FAFB", ok: "DCFCE7", okInk: "166534", bad: "FEE2E2", badInk: "991B1B",
  warn: "FEF3C7", warnInk: "92400E", info: "DBEAFE", infoInk: "1E3A8A" };
const PAGE_W = 11906, MARGIN = 1134, CONTENT_W = PAGE_W - 2 * MARGIN; // A4, 2 cm

const run = (text, o = {}) => new TextRun({ text, font: FONT, ...o });
// Text with simple **bold**
function rich(text, o = {}) {
  return String(text).split(/(\*\*[^*]+\*\*)/).filter(Boolean).map((t) =>
    t.startsWith("**") ? run(t.slice(2, -2), { ...o, bold: true }) : run(t, o));
}
const P = (text, o = {}) => new Paragraph({ children: rich(text, { size: o.size || 21, color: o.color }),
  spacing: { after: o.after ?? 120, before: o.before ?? 0, line: 276 }, alignment: o.align, keepNext: o.keepNext });
const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [run(t)] });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [run(t)] });
const H3 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_3, children: [run(t)] });
const bullet = (t) => new Paragraph({ numbering: { reference: "bul", level: 0 }, children: rich(t, { size: 21 }), spacing: { after: 60 } });
const numbered = (t, instance) => new Paragraph({ numbering: { reference: "num", level: 0, ...(instance ? { instance } : {}) }, children: rich(t, { size: 21 }), spacing: { after: 60 } });
const pageBreak = () => new Paragraph({ children: [new PageBreak()] });
const caption = (t) => new Paragraph({ children: [run(t, { size: 17, italics: true, color: C.muted })], alignment: AlignmentType.CENTER, spacing: { after: 200 } });

function pngSize(path) {
  const b = fs.readFileSync(path);
  return { w: b.readUInt32BE(16), h: b.readUInt32BE(20), data: b };
}
function image(path, widthPx = 620) {
  const { w, h, data } = pngSize(path);
  return new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 80, after: 60 }, keepNext: true,
    children: [new ImageRun({ type: "png", data, transformation: { width: widthPx, height: Math.round(widthPx * h / w) } })] });
}

const border = { style: BorderStyle.SINGLE, size: 4, color: C.line };
const borders = { top: border, bottom: border, left: border, right: border };
const STATUS = {
  OK: [C.ok, C.okInk], "Cumple": [C.ok, C.okInk], "Pasa": [C.ok, C.okInk],
  "No cumple": [C.bad, C.badInk], FAIL: [C.bad, C.badInk],
  "Parcial": [C.warn, C.warnInk], "Pendiente": [C.warn, C.warnInk], "Ajustado": [C.info, C.infoInk],
  "Pass": [C.ok, C.okInk], "Fail": [C.bad, C.badInk], "Partial": [C.warn, C.warnInk], "Measure": [C.info, C.infoInk], "Not applicable": ["F3F4F6", C.muted],
  "Medida": [C.info, C.infoInk], "No aplica": ["F3F4F6", C.muted], "Fuera de alcance": ["F3F4F6", C.muted], "Puede aplicar": [C.info, C.infoInk],
};
function cell(text, width, o = {}) {
  const st = o.status ? Object.entries(STATUS).find(([k]) => String(text).startsWith(k)) : null;
  const fill = o.fill || (st ? st[1][0] : o.zebra ? C.zebra : "FFFFFF");
  const color = o.color || (st ? st[1][1] : C.navy);
  const lines = String(text).split("\n");
  return new TableCell({
    borders, width: { size: width, type: WidthType.DXA }, verticalAlign: VerticalAlign.CENTER,
    shading: { fill, type: ShadingType.CLEAR, color: "auto" },
    margins: { top: 70, bottom: 70, left: 100, right: 100 },
    children: lines.map((l) => new Paragraph({ alignment: o.align, spacing: { after: 0 },
      children: rich(l, { size: o.size || 18, bold: o.bold || !!st, color }) })),
  });
}
// cols: [{h:"Header", w:fraction, status?:true, align?}]
function table(cols, rows, o = {}) {
  const total = o.width || CONTENT_W;
  const sum = cols.reduce((a, c) => a + c.w, 0);
  const widths = cols.map((c) => Math.round(total * c.w / sum));
  widths[widths.length - 1] += total - widths.reduce((a, b) => a + b, 0);
  const head = new TableRow({ tableHeader: true, children: cols.map((c, i) =>
    cell(c.h, widths[i], { fill: C.head, color: "FFFFFF", bold: true, size: 18, align: c.align })) });
  const body = rows.map((r, ri) => new TableRow({ cantSplit: true, children: r.map((v, i) =>
    cell(v, widths[i], { status: cols[i].status, zebra: ri % 2 === 1, align: cols[i].align, bold: cols[i].bold })) }));
  return new Table({ width: { size: total, type: WidthType.DXA }, columnWidths: widths, rows: [head, ...body] });
}
// KPI row: [{v:"60/60", l:"Segmentation", s:"OK"}]
function kpis(items) {
  const w = Math.floor(CONTENT_W / items.length);
  const widths = items.map(() => w); widths[widths.length - 1] += CONTENT_W - w * items.length;
  const mk = (it, i) => {
    const [fill, ink] = STATUS[it.s] || [C.info, C.infoInk];
    const bw = { style: BorderStyle.SINGLE, size: 24, color: "FFFFFF" };
    return new TableCell({ width: { size: widths[i], type: WidthType.DXA }, shading: { fill, type: ShadingType.CLEAR, color: "auto" },
      borders: { top: bw, bottom: bw, left: bw, right: bw }, margins: { top: 140, bottom: 140, left: 80, right: 80 },
      children: [
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 }, children: [run(it.v, { size: 34, bold: true, color: ink })] }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 0 }, children: [run(it.l, { size: 17, color: ink })] }),
      ] });
  };
  return new Table({ width: { size: CONTENT_W, type: WidthType.DXA }, columnWidths: widths, rows: [new TableRow({ children: items.map(mk) })] });
}
function callout(title, text, kind = "info") {
  const [fill, ink] = { info: [C.info, C.infoInk], ok: [C.ok, C.okInk], warn: [C.warn, C.warnInk] }[kind];
  const bl = { style: BorderStyle.SINGLE, size: 24, color: ink };
  const nb = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
  return new Table({ width: { size: CONTENT_W, type: WidthType.DXA }, columnWidths: [CONTENT_W], rows: [new TableRow({ children: [
    new TableCell({ width: { size: CONTENT_W, type: WidthType.DXA }, shading: { fill, type: ShadingType.CLEAR, color: "auto" },
      borders: { left: bl, top: nb, bottom: nb, right: nb }, margins: { top: 120, bottom: 120, left: 200, right: 200 },
      children: [new Paragraph({ spacing: { after: 60 }, children: [run(title, { bold: true, size: 20, color: ink })] }),
        ...[].concat(text).map((t) => new Paragraph({ spacing: { after: 40 }, children: rich(t, { size: 19, color: C.navy }) }))] }),
  ] })] });
}
const spacer = (after = 120) => new Paragraph({ spacing: { after }, children: [] });

function cover({ title, subtitle, meta, kicker = "CHECK POINT CLOUD FIREWALL · SECURITY VALIDATION" }) {
  return [
    new Paragraph({ spacing: { before: 2400, after: 120 }, children: [run(kicker, { size: 20, bold: true, color: C.accent, characterSpacing: 40 })] }),
    new Paragraph({ spacing: { after: 240 }, border: { bottom: { style: BorderStyle.SINGLE, size: 12, color: C.accent, space: 8 } },
      children: [run(title, { size: 56, bold: true, color: C.navy })] }),
    new Paragraph({ spacing: { after: 600 }, children: [run(subtitle, { size: 26, color: C.muted })] }),
    ...meta.map(([k, v]) => new Paragraph({ spacing: { after: 60 }, children: [run(`${k}: `, { size: 20, bold: true, color: C.navy }), run(v, { size: 20, color: C.navy })] })),
    pageBreak(),
  ];
}

function makeDoc({ title, children, footer = "Check Point Software Technologies · Confidential · Page " }) {
  return new Document({
    creator: "Check Point Software Technologies", title, features: { updateFields: true },
    styles: {
      default: { document: { run: { font: FONT, size: 21, color: C.navy } } },
      paragraphStyles: [
        { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { font: FONT, size: 32, bold: true, color: C.navy }, paragraph: { spacing: { before: 360, after: 160 }, keepNext: true, outlineLevel: 0,
            border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: C.accent, space: 4 } } } },
        { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { font: FONT, size: 26, bold: true, color: C.navy }, paragraph: { spacing: { before: 280, after: 120 }, keepNext: true, outlineLevel: 1 } },
        { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { font: FONT, size: 22, bold: true, color: C.blue }, paragraph: { spacing: { before: 200, after: 80 }, keepNext: true, outlineLevel: 2 } },
      ],
    },
    numbering: { config: [
      { reference: "bul", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 270 } } } }] },
      { reference: "num", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 300 } } } }] },
    ] },
    sections: [{
      properties: { page: { size: { width: PAGE_W, height: 16838 }, margin: { top: 1134, bottom: 1134, left: MARGIN, right: MARGIN } } },
      headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [run(title, { size: 16, color: C.muted })] })] }) },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [
        run(footer, { size: 16, color: C.muted }),
        new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 16, color: C.muted })] })] }) },
      children,
    }],
  });
}
const toc = (label = "Contents") => [new Paragraph({ children: [run(label, { size: 28, bold: true, color: C.navy })], spacing: { after: 120 } }),
  new TableOfContents(label, { hyperlink: true, headingStyleRange: "1-2" }), pageBreak()];

async function write(doc, path) { fs.writeFileSync(path, await Packer.toBuffer(doc)); console.log("  ", path); }

module.exports = { P, H1, H2, H3, bullet, numbered, pageBreak, caption, image, table, kpis, callout, spacer, cover, makeDoc, toc, write, CONTENT_W, C };
