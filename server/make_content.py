#!/usr/bin/env python3
"""Generates the test content (at image build time).
  /srv/www/demo           files served by the server (EICAR, benign files of several formats, synthetic data)
  /opt/testkit/samples    files uploaded by the client
Synthetic data only: card-brand test numbers (valid Luhn) and sample IBANs.
"""
import gzip, io, os, random, struct, zipfile, zlib

WWW, SMP = "/srv/www", "/opt/testkit/samples"
D = os.path.join(WWW, "demo")
for p in (D, os.path.join(D, "gz"), SMP):
    os.makedirs(p, exist_ok=True)

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
CARDS = ["4111 1111 1111 1111", "5555 5555 5555 4444", "3782 822463 10005", "4012 8888 8888 1881", "6011 1111 1111 1117",
         "5105 1051 0510 5100", "4000 0566 5566 5556", "3714 496353 98431"]
CARDS_TXT = "Payment list (synthetic test data)\n" + "\n".join(f"Customer {i+1:02d};Card {c};Expiry 12/2{i%9}" for i, c in enumerate(CARDS)) + "\n"
IBAN_TXT = "Transfers (synthetic data)\n" + "\n".join(f"Supplier {i};IBAN {b}" for i, b in enumerate(
    ["ES91 2100 0418 4502 0005 1332", "ES79 2100 0813 6101 2345 6789", "DE89 3704 0044 0532 0130 00", "GB29 NWBK 6016 1331 9268 19",
     "FR14 2004 1010 0505 0001 3M02 606", "IT60 X054 2811 1010 0000 0123 456"], 1)) + "\n"


def w(path, data, mode="wb"):
    with open(path, mode) as f:
        f.write(data)


# --- Anti-Virus
w(f"{D}/eicar.com", EICAR); w(f"{D}/eicar.txt", EICAR); w(f"{SMP}/eicar.com", EICAR)
with zipfile.ZipFile(f"{D}/eicar.zip", "w") as z:
    z.writestr("eicar.com", EICAR)
with zipfile.ZipFile(f"{D}/eicar2.zip", "w") as z:
    z.write(f"{D}/eicar.zip", "eicar.zip")
w(f"{D}/gz/eicar.txt", gzip.compress(EICAR))           # nginx lo sirve con Content-Encoding: gzip

# --- Content Awareness (synthetic)
w(f"{D}/cards.txt", CARDS_TXT, "w"); w(f"{SMP}/cards.txt", CARDS_TXT, "w"); w(f"{SMP}/iban.txt", IBAN_TXT, "w")
w(f"{SMP}/cards.json", '{"payments":[' + ",".join(f'{{"holder":"Customer {i}","pan":"{c}"}}' for i, c in enumerate(CARDS)) + "]}", "w")
lorem = ("Operational report of the test lab. No sensitive data in this paragraph. " * 20 + "\n")
filler = (lorem * (2 * 1024 * 1024 // len(lorem) + 1))[:2 * 1024 * 1024]
w(f"{D}/cards_2m.txt", filler + "\n" + CARDS_TXT, "w")
benign = "Benign test document. Nothing to see here.\n"
w(f"{D}/benign.txt", benign, "w"); w(f"{SMP}/benign.txt", "informe trimestral sin datos sensibles\n", "w")
with zipfile.ZipFile(f"{D}/benign.zip", "w") as z:
    z.writestr("benign.txt", benign)
w(f"{D}/benign.sh", "#!/bin/bash\n# Script de mantenimiento de ejemplo\nfor f in /var/log/*.log; do gzip -9 \"$f\"; done\nsystemctl restart nginx\n", "w")
w(f"{D}/benign.json", '{"project":"testkit","environments":["PRO","PRE","DEV","COMM"],"status":"ok"}', "w")
w(f"{D}/benign.csv", "environment,cidr,az\nPRO,10.0.0.0/16,eu-west-1b\nPRE,10.1.0.0/16,eu-west-1a\nDEV,10.2.0.0/16,eu-west-1b\nCOMM,10.3.0.0/16,eu-west-1a\n", "w")
random.seed(42)
w(f"{D}/benign_10m.bin", random.randbytes(10 * 1024 * 1024))

# Minimal valid PDF
objs = ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        None, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
stream = b"BT /F1 18 Tf 72 760 Td (Firewall Testkit - benign document) Tj ET"
objs[3] = f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream"
pdf = io.BytesIO(); pdf.write(b"%PDF-1.4\n"); offs = []
for i, o in enumerate(objs, 1):
    offs.append(pdf.tell()); pdf.write(f"{i} 0 obj\n".encode()); pdf.write(o if isinstance(o, bytes) else o.encode()); pdf.write(b"\nendobj\n")
x = pdf.tell(); pdf.write(f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n".encode())
for o in offs:
    pdf.write(f"{o:010d} 00000 n \n".encode())
pdf.write(f"trailer << /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()); w(f"{D}/benign.pdf", pdf.getvalue())

# PNG 64x64
raw = b"".join(b"\0" + bytes([(x * 4) % 256, (y * 4) % 256, 160] * 1)[:3] * 1 + b"" for y in range(64) for x in range(1))
rows = b"".join(b"\0" + b"".join(bytes([(x * 4) % 256, (y * 4) % 256, 160]) for x in range(64)) for y in range(64))
chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
w(f"{D}/benign.png", b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 64, 64, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))

# Minimal DOCX / XLSX (OOXML)
CT_DOC = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
RELS_DOC = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'


def docx(path, paras):
    body = "".join(f"<w:p><w:r><w:t xml:space=\"preserve\">{p}</w:t></w:r></w:p>" for p in paras)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", CT_DOC); z.writestr("_rels/.rels", RELS_DOC)
        z.writestr("word/document.xml", f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{body}</w:body></w:document>')


docx(f"{D}/benign.docx", ["Firewall Testkit - benign document.", "Test content without sensitive data."])
docx(f"{D}/cards.docx", ["Pending payments (synthetic test data)"] + [f"Card {c}" for c in CARDS])
CT_X = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'
with zipfile.ZipFile(f"{D}/benign.xlsx", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("[Content_Types].xml", CT_X)
    z.writestr("_rels/.rels", RELS_DOC.replace("word/document.xml", "xl/workbook.xml"))
    z.writestr("xl/workbook.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Testkit" sheetId="1" r:id="rId1"/></sheets></workbook>')
    z.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
    z.writestr("xl/worksheets/sheet1.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Entorno</t></is></c><c r="B1"><v>1</v></c></row></sheetData></worksheet>')

w(f"{WWW}/index.html", "<!doctype html><title>FW-TESTKIT-OK</title><h1>FW-TESTKIT-OK · test server</h1>\n", "w")
print("content generated:", sorted(os.listdir(D)))
