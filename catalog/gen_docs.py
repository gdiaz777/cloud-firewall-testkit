#!/usr/bin/env python3
"""Writes docs/en/test-catalog.md and docs/es/catalogo-pruebas.md from catalog/tests.json."""
import json, os

H = os.path.dirname(os.path.abspath(__file__))
cat = json.load(open(os.path.join(H, "tests.json"), encoding="utf-8"))
EXP = {"en": {"ALLOW": "Allowed", "BLOCK": "Blocked", "INSPECTED": "Decrypted", "NOT_INSPECTED": "Not decrypted", "VALID": "Cert. valid", "INVALID": "Cert. rejected",
              "PRESERVED": "IP preserved", "LIMITED": "Authorized only", "MEASURE": "Measure", "NO_FLOW": "No flow", "MATRIX": "Per matrix", "PASS": "Criterion met"},
       "es": {"ALLOW": "Permitido", "BLOCK": "Bloqueado", "INSPECTED": "Descifrado", "NOT_INSPECTED": "Sin descifrar", "VALID": "Cert. válido", "INVALID": "Cert. rechazado",
              "PRESERVED": "IP conservada", "LIMITED": "Solo autorizados", "MEASURE": "Medida", "NO_FLOW": "Sin flujo", "MATRIX": "Según matriz", "PASS": "Cumple criterio"}}
TX = {"en": dict(file="docs/en/test-catalog.md", title="Test catalog", intro="Generated from `catalog/tests.json`. Every case lists its objective, the policy prerequisites, the automated checks and, separately, notes on how Check Point handles it (shown in the portal and reports only when the solution under test is Check Point).",
                 summary="Summary", domain="Domain", cases="Cases", checks="Checks", obj="Objective", how="Check Point notes", req="Policy prerequisites",
                 evi="Evidence", prio="Priority", id="ID", check="Check", what="What it does", exp="Expected", blade="Capability", only="only from role", inf="informative", other="Español: [catalogo-pruebas.md](../es/catalogo-pruebas.md)",
                 manual="Manual", proc="Procedure", expd="Expected result", bp="Check Point best practice", ctl="control agent", scope="needs extra infrastructure", mcol="Manual",
                 fw="Firewall configuration for the tests", fwcp="Check Point recommended baseline", req2="Firewall configuration needed"),
      "es": dict(file="docs/es/catalogo-pruebas.md", title="Catálogo de pruebas", intro="Generado desde `catalog/tests.json`. Cada caso indica su objetivo, los requisitos de política, las comprobaciones automáticas y, aparte, notas de cómo lo resuelve Check Point (en el portal y los informes solo aparecen si la solución probada es Check Point).",
                 summary="Resumen", domain="Dominio", cases="Casos", checks="Comprobaciones", obj="Objetivo", how="Notas de Check Point", req="Requisitos de política",
                 evi="Evidencias", prio="Prioridad", id="ID", check="Prueba", what="Qué hace", exp="Esperado", blade="Capacidad", only="solo desde el papel", inf="informativa", other="English: [test-catalog.md](../en/test-catalog.md)",
                 manual="Manual", proc="Procedimiento", expd="Resultado esperado", bp="Buena práctica de Check Point", ctl="agente de control", scope="requiere infraestructura adicional", mcol="Manuales",
                 fw="Configuración del firewall para las pruebas", fwcp="Configuración base recomendada de Check Point", req2="Configuración necesaria en el firewall")}

for L, t in TX.items():
    md = [f"# {t['title']}", "", f"_{t['other']}_", "", t["intro"], "", f"## {t['summary']}", "", f"| {t['domain']} | {t['cases']} | {t['mcol']} | {t['checks']} |", "|---|---:|---:|---:|"]
    for d in cat["domains"]:
        cs = [c for c in cat["cases"] if c["domain"] == d["id"]]
        md.append(f"| [{d['id']} · {d['name'][L]}](#{d['id'].lower()}) | {len(cs)} | {sum(c.get('mode') == 'manual' for c in cs)} | {sum(len(c['checks']) for c in cs)} |")
    g = cat.get("config_guide", {})
    md += ["", f"## {t['fw']}", ""] + [f"{i}. {x[L]}" for i, x in enumerate(g.get("firewall", []), 1)]
    md += ["", f"### {t['fwcp']}", ""] + [f"- {x[L]}" for x in g.get("checkpoint", [])]
    for d in cat["domains"]:
        md += ["", f'<a id="{d["id"].lower()}"></a>', f"## {d['id']} · {d['name'][L]}"]
        for c in [c for c in cat["cases"] if c["domain"] == d["id"]]:
            tag = f" · _{t['manual']}_" if c.get("mode") == "manual" else (f" · _{t['ctl']}_" if any(k.get("runner") == "control" for k in c["checks"]) else "")
            md += ["", f"### {c['id']} · {c['title'][L]}", "", f"**{t['prio']}:** {c['priority_label'][L]}{tag}" + (f" · _{t['scope']}_" if c.get("scope") else "") + "  ",
                   f"**{t['obj']}:** {c['objective'][L]}  ", f"**{t['req2']}:** {c['requires'][L]}  ", f"_{t['how']}: {c['vendor_notes']['checkpoint'][L]}_  "]
            if c.get("bp_checkpoint"):
                md.append(f"_{t['bp']}: {c['bp_checkpoint'][L]}_")
            if c.get("mode") == "manual":
                md += ["", f"**{t['proc']}:**", ""] + [f"{i}. {x[L]}" for i, x in enumerate(c.get("procedure", []), 1)] + ["", f"**{t['expd']}:** {c['expected'][L]}  ", f"**{t['evi']}:** {c['evidence'][L]}"]
                continue
            md += ["", f"| {t['id']} | {t['check']} | {t['what']} | {t['exp']} | {t['blade']} |", "|---|---|---|---|---|"]
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
