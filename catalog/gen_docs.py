#!/usr/bin/env python3
"""Writes docs/en/test-catalog.md and docs/es/catalogo-pruebas.md from catalog/tests.json."""
import json, os

H = os.path.dirname(os.path.abspath(__file__))
cat = json.load(open(os.path.join(H, "tests.json"), encoding="utf-8"))
EXP = {"en": {"ALLOW": "Allowed", "BLOCK": "Blocked", "INSPECTED": "Decrypted", "NOT_INSPECTED": "Not decrypted", "VALID": "Cert. valid", "INVALID": "Cert. rejected",
              "PRESERVED": "IP preserved", "LIMITED": "Authorized only", "MEASURE": "Measure", "NO_FLOW": "No flow", "MATRIX": "Per matrix"},
       "es": {"ALLOW": "Permitido", "BLOCK": "Bloqueado", "INSPECTED": "Descifrado", "NOT_INSPECTED": "Sin descifrar", "VALID": "Cert. válido", "INVALID": "Cert. rechazado",
              "PRESERVED": "IP conservada", "LIMITED": "Solo autorizados", "MEASURE": "Medida", "NO_FLOW": "Sin flujo", "MATRIX": "Según matriz"}}
TX = {"en": dict(file="docs/en/test-catalog.md", title="Test catalog", intro="Generated from `catalog/tests.json`. Every case lists its objective, the policy prerequisites, the automated checks and, separately, notes on how Check Point handles it (shown in the portal and reports only when the solution under test is Check Point).",
                 summary="Summary", domain="Domain", cases="Cases", checks="Checks", obj="Objective", how="Check Point notes", req="Policy prerequisites",
                 evi="Evidence", prio="Priority", id="ID", check="Check", what="What it does", exp="Expected", blade="Capability", only="only from role", inf="informative", other="Español: [catalogo-pruebas.md](../es/catalogo-pruebas.md)"),
      "es": dict(file="docs/es/catalogo-pruebas.md", title="Catálogo de pruebas", intro="Generado desde `catalog/tests.json`. Cada caso indica su objetivo, los requisitos de política, las comprobaciones automáticas y, aparte, notas de cómo lo resuelve Check Point (en el portal y los informes solo aparecen si la solución probada es Check Point).",
                 summary="Resumen", domain="Dominio", cases="Casos", checks="Comprobaciones", obj="Objetivo", how="Notas de Check Point", req="Requisitos de política",
                 evi="Evidencias", prio="Prioridad", id="ID", check="Prueba", what="Qué hace", exp="Esperado", blade="Capacidad", only="solo desde el papel", inf="informativa", other="English: [test-catalog.md](../en/test-catalog.md)")}

for L, t in TX.items():
    md = [f"# {t['title']}", "", f"_{t['other']}_", "", t["intro"], "", f"## {t['summary']}", "", f"| {t['domain']} | {t['cases']} | {t['checks']} |", "|---|---:|---:|"]
    for d in cat["domains"]:
        cs = [c for c in cat["cases"] if c["domain"] == d["id"]]
        md.append(f"| [{d['id']} · {d['name'][L]}](#{d['id'].lower()}) | {len(cs)} | {sum(len(c['checks']) for c in cs)} |")
    for d in cat["domains"]:
        md += ["", f'<a id="{d["id"].lower()}"></a>', f"## {d['id']} · {d['name'][L]}"]
        for c in [c for c in cat["cases"] if c["domain"] == d["id"]]:
            md += ["", f"### {c['id']} · {c['title'][L]}", "", f"**{t['prio']}:** {c['priority_label'][L]}  ",
                   f"**{t['obj']}:** {c['objective'][L]}  ", f"**{t['req']}:** {c['requires'][L]}  ", f"_{t['how']}: {c['vendor_notes']['checkpoint'][L]}_", "",
                   f"| {t['id']} | {t['check']} | {t['what']} | {t['exp']} | {t['blade']} |", "|---|---|---|---|---|"]
            for k in c["checks"]:
                extra = []
                if k.get("roles"):
                    extra.append(f"{t['only']} `{', '.join(k['roles'])}`")
                if k.get("informative"):
                    extra.append(t["inf"])
                name = k["name"][L] + (f" ({'; '.join(extra)})" if extra else "")
                md.append(f"| {k['id']} | {name} | {k['explain'][L]} | {EXP[L].get(k['expect'], k['expect'])} | {k['blade']} |")
    out = os.path.join(H, "..", t["file"]); os.makedirs(os.path.dirname(out), exist_ok=True)
    open(out, "w", encoding="utf-8").write("\n".join(md) + "\n")
    print(out)
