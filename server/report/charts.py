#!/usr/bin/env python3
"""Charts for a run report.  charts.py <run.json> <tests.json> <outdir> [en|es]"""
import json, sys, os
from collections import Counter, defaultdict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

run = json.load(open(sys.argv[1], encoding="utf-8")); cat = json.load(open(sys.argv[2], encoding="utf-8")); out = sys.argv[3]
L = sys.argv[4] if len(sys.argv) > 4 else "en"
os.makedirs(out, exist_ok=True)
TX = {"en": dict(ok="Expected result", fail="Unexpected", info="Measure / informative", err="Execution error", checks="Checks", run="checks executed",
                 asexp="as expected", https="Attacks and content that must be blocked"),
      "es": dict(ok="Resultado esperado", fail="No esperado", info="Medida / informativa", err="Error de ejecución", checks="Comprobaciones", run="comprobaciones ejecutadas",
                 asexp="como se esperaba", https="Ataques y contenidos que deben bloquearse")}[L]
COL = {"OK": "#16a34a", "FAIL": "#dc2626", "INFO": "#2563eb", "SKIP": "#d1d5db", "ERROR": "#991b1b"}
LBL = {"OK": TX["ok"], "FAIL": TX["fail"], "INFO": TX["info"], "ERROR": TX["err"]}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
res = [dict(r, agent=a) for a, ag in run["agents"].items() for r in ag["results"] if r["status"] != "SKIP"]
dom_name = {d["id"]: (d["name"].get(L) if isinstance(d["name"], dict) else d["name"]) for d in cat["domains"]}
order = [d["id"] for d in cat["domains"]]


def stacked(ax, labels, data):
    left = [0] * len(labels)
    for k in ("OK", "FAIL", "ERROR", "INFO"):
        v = [data[x][k] for x in labels]
        if any(v):
            ax.barh(labels, v, left=left, color=COL[k], label=LBL[k], height=0.62)
            left = [a + b for a, b in zip(left, v)]
    return left


# 1. Overall donut
c = Counter(r["status"] for r in res)
keys = [k for k in ("OK", "FAIL", "ERROR", "INFO") if c[k]]
fig, ax = plt.subplots(figsize=(6.4, 3.2))
if keys:
    ax.pie([c[k] for k in keys], colors=[COL[k] for k in keys], startangle=90, counterclock=False, wedgeprops=dict(width=0.38, edgecolor="white"))
okp = 100 * c["OK"] / max(1, c["OK"] + c["FAIL"] + c["ERROR"])
ax.text(0, 0.08, f"{okp:.0f} %", ha="center", va="center", fontsize=22, fontweight="bold", color="#1f2937")
ax.text(0, -0.2, TX["asexp"], ha="center", va="center", fontsize=9, color="#6b7280")
ax.legend([f"{LBL[k]} ({c[k]})" for k in keys], loc="center left", bbox_to_anchor=(1, 0.5), frameon=False)
ax.set_title(f"{sum(c[k] for k in keys)} {TX['run']}", loc="left", fontsize=11, color="#1f2937")
fig.tight_layout(); fig.savefig(f"{out}/summary.png", dpi=170); plt.close(fig)

# 2. By domain
by = defaultdict(Counter)
for r in res:
    by[r["case"].split("-")[0]][r["status"]] += 1
doms = [d for d in order if d in by][::-1]
if doms:
    labels = [f"{d} · {dom_name[d]}" for d in doms]
    data = {f"{d} · {dom_name[d]}": by[d] for d in doms}
    fig, ax = plt.subplots(figsize=(7.2, 0.42 * len(doms) + 1.1))
    left = stacked(ax, labels, data)
    for i, d in enumerate(doms):
        ax.text(left[i] + 0.3, i, f"{by[d]['OK']}/{by[d]['OK'] + by[d]['FAIL'] + by[d]['ERROR']}", va="center", fontsize=9, color="#374151")
    ax.set_xlabel(TX["checks"]); ax.legend(loc="lower right", frameon=False, fontsize=8)
    fig.tight_layout(); fig.savefig(f"{out}/domains.png", dpi=170); plt.close(fig)

# 3. By blade
bb = defaultdict(Counter)
for r in res:
    bb[(r.get("blade") or "Other").split(" / ")[0].split(" (")[0]][r["status"]] += 1
bl = sorted(bb, key=lambda b: -sum(bb[b].values()))[:12][::-1]
if bl:
    fig, ax = plt.subplots(figsize=(7.2, 0.38 * len(bl) + 1.1))
    stacked(ax, bl, bb)
    ax.set_xlabel(TX["checks"]); ax.legend(loc="lower right", frameon=False, fontsize=8)
    fig.tight_layout(); fig.savefig(f"{out}/blades.png", dpi=170); plt.close(fig)

# 4. HTTP vs HTTPS (checks that must block)
pp = defaultdict(Counter)
for r in res:
    p = "HTTPS" if "HTTPSi" in (r.get("blade") or "") else ("HTTP" if r["type"] == "http" else None)
    if p and r["expect"] == "BLOCK":
        pp[p][r["status"]] += 1
if pp:
    ks = [k for k in ("HTTPS", "HTTP") if k in pp]
    fig, ax = plt.subplots(figsize=(5.6, 2.2))
    stacked(ax, ks, pp)
    ax.set_title(TX["https"], loc="left", fontsize=10); ax.legend(loc="lower right", frameon=False, fontsize=8)
    fig.tight_layout(); fig.savefig(f"{out}/https.png", dpi=170); plt.close(fig)
print("ok")
