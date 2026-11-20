#!/usr/bin/env python3
"""Charts for the comparison report.  compare_charts.py <tests.json> <outdir> <en|es> <run1.json> <run2.json> …"""
import json, sys, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compare_lib import load_runs, per_check

cat = json.load(open(sys.argv[1], encoding="utf-8")); out = sys.argv[2]; L = sys.argv[3]; runs = load_runs(sys.argv[4:])
os.makedirs(out, exist_ok=True)
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
PAL = ["#2563eb", "#e4002b", "#16a34a", "#9333ea", "#ea580c", "#0891b2"]
doms = [d for d in cat["domains"]]
dn = lambda d: d["name"].get(L, d["name"]["en"])
TX = {"en": ("Expected result (%)", "Expected result by domain"), "es": ("Resultado esperado (%)", "Resultado esperado por dominio")}[L]
data = []
for r in runs:
    pc = per_check(r)
    row = []
    for d in doms:
        st = [v for k, v in pc.items() if k.startswith(d["id"] + "-") and v in ("OK", "FAIL", "ERROR")]
        row.append(100 * sum(1 for v in st if v == "OK") / len(st) if st else None)
    data.append(row)
keep = [i for i in range(len(doms)) if any(row[i] is not None for row in data)]
labels = [f"{doms[i]['id']}" for i in keep]
w = 0.8 / len(runs)
fig, ax = plt.subplots(figsize=(7.6, 3.6))
for j, (r, row) in enumerate(zip(runs, data)):
    xs = [k + j * w - 0.4 + w / 2 for k in range(len(keep))]
    ax.bar(xs, [row[i] or 0 for i in keep], width=w * 0.95, color=PAL[j % len(PAL)], label=r["solution"])
ax.set_xticks(range(len(keep))); ax.set_xticklabels(labels); ax.set_ylim(0, 105); ax.set_ylabel(TX[0])
ax.set_title(TX[1], loc="left", fontsize=11); ax.legend(frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.1), ncol=min(len(runs), 4))
fig.tight_layout(); fig.savefig(f"{out}/compare_domains.png", dpi=170); plt.close(fig)
print("ok")
