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
# rounded DOWN to one decimal: 712/715 must not read "100 %" while there are unexpected results
okp = int(okp * 10) / 10
okt = f"{okp:.0f}" if okp == int(okp) else (f"{okp:.1f}".replace(".", ",") if L == "es" else f"{okp:.1f}")
ax.text(0, 0.08, f"{okt} %", ha="center", va="center", fontsize=22, fontweight="bold", color="#1f2937")
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

# 3. By capability
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
    p = "HTTPS" if "TLS inspection" in (r.get("blade") or "") else ("HTTP" if r["type"] == "http" else None)
    if p and r["expect"] == "BLOCK":
        pp[p][r["status"]] += 1
if pp:
    ks = [k for k in ("HTTPS", "HTTP") if k in pp]
    fig, ax = plt.subplots(figsize=(5.6, 2.2))
    stacked(ax, ks, pp)
    ax.set_title(TX["https"], loc="left", fontsize=10); ax.legend(loc="lower right", frameon=False, fontsize=8)
    fig.tight_layout(); fig.savefig(f"{out}/https.png", dpi=170); plt.close(fig)

# ------------------------------------------------------------------ 5. architecture (from the run configuration)
import re
from matplotlib.patches import FancyBboxPatch
AX = {"en": dict(sol="Solution under test", srv="test server + portal", cli="kit client", inet="Internet", ctl="Control agent\n(cloud + management APIs)",
                 note="Every check leaves from a client's workload IP and crosses the solution under test"),
      "es": dict(sol="Solución probada", srv="servidor + portal", cli="cliente del kit", inet="Internet", ctl="Agente de control\n(API de nube y de gestión)",
                 note="Cada comprobación sale de la IP de workload de un cliente y atraviesa la solución probada")}[L]
cfg = run.get("config") or {}
envs = cfg.get("environments") or []
if envs:
    def box(ax, x, y, w, h, txt, fc, ec, fs=9, bold=False):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12", fc=fc, ec=ec, lw=1.3))
        ax.text(x + w / 2, y + h / 2, txt, ha="center", va="center", fontsize=fs, color="#1f2937", weight="bold" if bold else "normal")
    n = len(envs); H = max(6.0, 1.6 * n + 1.2)
    fig, ax = plt.subplots(figsize=(11, H * 0.62)); ax.set_xlim(0, 22); ax.set_ylim(0, H); ax.axis("off")
    sol = (cfg.get("solution") or {}).get("name") or AX["sol"]
    sy = H / 2 - 1.3
    box(ax, 8.2, sy, 5.4, 2.6, f"{AX['sol']}\n{sol}", "#fef2f2", "#c8102e", 10, True)
    for i, e in enumerate(envs):
        y = H - 1.5 - i * ((H - 1.4) / max(1, n))
        srv = e.get("name") == cfg.get("server_env")
        txt = f"{e['name'].upper()}  {e.get('cidr') or e.get('ip', '')}" + (f" · AZ {e['az']}" if e.get("az") else "") + f"\n{AX['srv'] if srv else AX['cli']} ({e.get('ip', '')})"
        box(ax, 0.3, y, 5.6, 1.15, txt, "#eff6ff" if not srv else "#fefce8", "#2563eb" if not srv else "#ca8a04", 8.5)
        ax.annotate("", xy=(8.2, sy + 1.3), xytext=(5.9, y + 0.57), arrowprops=dict(arrowstyle="<|-|>", color="#2563eb", lw=1.2))
    box(ax, 16.0, sy + 0.4, 5.2, 1.8, AX["inet"], "#ffffff", "#9ca3af", 11, True)
    ax.annotate("", xy=(16.0, sy + 1.3), xytext=(13.6, sy + 1.3), arrowprops=dict(arrowstyle="-|>", color="#16a34a", lw=1.5))
    if "control" in run.get("agents", {}):
        box(ax, 16.0, H - 2.1, 5.2, 1.5, AX["ctl"], "#f5f3ff", "#7c3aed", 8.5)
        ax.annotate("", xy=(13.0, sy + 2.6), xytext=(16.0, H - 1.35), arrowprops=dict(arrowstyle="-|>", color="#7c3aed", lw=1.2, ls=":"))
    ax.text(11, 0.15, AX["note"], ha="center", fontsize=8.5, color="#6b7280")
    fig.tight_layout(); fig.savefig(f"{out}/architecture.png", dpi=170); plt.close(fig)

# ------------------------------------------------------------------ 6. performance (from the measurement details)
PX = {"en": dict(thr="Throughput through the solution (Mbit/s)", lat="Latency (ms)", udp="UDP: packets/s and loss by datagram size",
                 pps="thousand packets/s", loss="loss %"),
      "es": dict(thr="Caudal a través de la solución (Mbit/s)", lat="Latencia (ms)", udp="UDP: paquetes/s y pérdida por tamaño de datagrama",
                 pps="miles de paquetes/s", loss="pérdida %")}[L]
cname = {k["id"]: (k["name"].get(L) if isinstance(k["name"], dict) else k["name"]) for c_ in cat["cases"] for k in c_["checks"]}
perf = [r for r in res if r.get("status") == "INFO" and r.get("case", "").startswith("PERF-")]
num = lambda pat, t: float(re.search(pat, t).group(1)) if re.search(pat, t) else None
thr = [(cname.get(r["id"], r["id"]), num(r"(?:TCP|) ?(\d+) Mbit/s", r["detail"]), r["type"]) for r in perf if r["type"] in ("iperf", "dl_bench") and "UDP" not in r["detail"]]
thr = [t for t in thr if t[1]]
if thr:
    fig, ax = plt.subplots(figsize=(7.6, 0.36 * len(thr) + 1.2))
    ax.barh([f"{t[0]}" for t in thr][::-1], [t[1] for t in thr][::-1], color=["#c8102e" if t[2] == "dl_bench" else "#9ca3af" for t in thr][::-1])
    for i, t in enumerate(thr[::-1]):
        ax.text(t[1] * 1.01, i, f"{t[1]:.0f}", va="center", fontsize=8)
    ax.set_title(PX["thr"], loc="left", fontsize=10); fig.tight_layout(); fig.savefig(f"{out}/perf_throughput.png", dpi=170); plt.close(fig)
lat = [(cname.get(r["id"], r["id"]), [num(rf"{p} ([\d.]+) ms", r["detail"]) for p in ("p50", "p95", "p99")]) for r in perf if r["type"] == "latency"]
lat = [l for l in lat if all(v is not None for v in l[1])]
if lat:
    fig, ax = plt.subplots(figsize=(7.2, 3.2)); w = 0.26
    for i, (p, col) in enumerate(zip(("p50", "p95", "p99"), ("#16a34a", "#d97706", "#dc2626"))):
        ax.bar([k + (i - 1) * w for k in range(len(lat))], [l[1][i] for l in lat], w, color=col, label=p)
    ax.set_xticks(range(len(lat))); ax.set_xticklabels([l[0] for l in lat], fontsize=8); ax.legend(frameon=False)
    ax.set_title(PX["lat"], loc="left", fontsize=10); fig.tight_layout(); fig.savefig(f"{out}/perf_latency.png", dpi=170); plt.close(fig)
udp = [(re.search(r"\((\d+ B)", r["detail"]).group(1) if re.search(r"\((\d+ B)", r["detail"]) else r["id"], num(r"(\d+) packets/s", r["detail"]), num(r"loss ([\d.]+) %", r["detail"]))
       for r in perf if r["type"] == "iperf" and "UDP" in r["detail"]]
udp = [u for u in udp if u[1] is not None]
if udp:
    fig, ax = plt.subplots(figsize=(7.2, 3.2)); ax2 = ax.twinx()
    ax.bar([u[0] for u in udp], [u[1] / 1000 for u in udp], color="#2563eb", width=0.5); ax.set_ylabel(PX["pps"], color="#2563eb")
    ax2.plot([u[0] for u in udp], [u[2] or 0 for u in udp], "o-", color="#dc2626"); ax2.set_ylabel(PX["loss"], color="#dc2626"); ax2.spines["right"].set_visible(True)
    ax.set_title(PX["udp"], loc="left", fontsize=10); fig.tight_layout(); fig.savefig(f"{out}/perf_udp.png", dpi=170); plt.close(fig)

# ------------------------------------------------------------------ 7. high availability (control agent results)
HX = {"en": dict(out="Longest continuous interruption per client during the HA events (s)", thr="threshold", tl="Replacement of a failed gateway (minutes)",
                 ev=["Failure detected by the load balancer", "Replacement launched", "In service (group)", "Healthy target", "Registered with policy (management)", "Old object removed"]),
      "es": dict(out="Interrupción continua más larga por cliente durante los eventos de HA (s)", thr="umbral", tl="Sustitución de un gateway caído (minutos)",
                 ev=["El balanceador detecta el fallo", "Sustituto lanzado", "En servicio (grupo)", "Destino sano", "Registrado con política (gestión)", "Objeto antiguo retirado"])}[L]
ENVN = {(e.get("name") or "").upper() for e in envs}
ha = [r for r in res if r.get("case", "").startswith("HA-") and r.get("type") == "hook" and "interruption per client" in r.get("detail", "")]
rows = []
for r in ha:
    part = re.split(r"interruption per client[^:]*:", r["detail"])[-1]
    vals = {}
    for m in re.finditer(r"([A-Z0-9_-]+): ([^;.]+)", part):
        ns = [int(x) for x in re.findall(r"(\d+) s\b", m.group(2))]
        if ns and m.group(1) in ENVN:
            vals[m.group(1)] = max(ns)
    if vals:
        rows.append((r["case"], vals))
if rows:
    es_ = sorted({k for _, v in rows for k in v}); w = 0.8 / max(1, len(es_)); pal = ["#2563eb", "#16a34a", "#d97706", "#7c3aed", "#9ca3af", "#0891b2"]
    fig, ax = plt.subplots(figsize=(7.6, 3.2))
    for i, e in enumerate(es_):
        ax.bar([k + (i - (len(es_) - 1) / 2) * w for k in range(len(rows))], [v.get(e, 0) for _, v in rows], w, color=pal[i % len(pal)], label=e)
    lim = (cfg.get("ha") or {}).get("max_outage_s", 60)
    ax.axhline(lim, color="#dc2626", ls="--", lw=1); ax.text(len(rows) - 0.55, lim + 1, f"{HX['thr']} {lim} s", color="#dc2626", fontsize=8, ha="right")
    ax.set_xticks(range(len(rows))); ax.set_xticklabels([c_ for c_, _ in rows]); ax.legend(frameon=False, ncol=min(6, len(es_)), fontsize=8)
    ax.set_title(HX["out"], loc="left", fontsize=10); fig.tight_layout(); fig.savefig(f"{out}/ha_outage.png", dpi=170); plt.close(fig)
h1 = next((r["detail"] for r in res if r.get("case") == "HA-01" and r.get("type") == "hook"), "")
ev = [(lbl, num(p, h1)) for lbl, p in zip(HX["ev"], (r"unhealthy \+(\d+) s", r"launched \+(\d+) s", r"in service \+(\d+) s", r"healthy target \+(\d+) s",
                                                     r"management \+(\d+) s", r"removed \+(\d+) s"))]
ev = [e for e in ev if e[1] is not None]
if ev:
    fig, ax = plt.subplots(figsize=(7.6, 2.8))
    ax.barh([e[0] for e in ev][::-1], [e[1] / 60 for e in ev][::-1], color=["#dc2626", "#d97706", "#16a34a", "#2563eb", "#7c3aed", "#9ca3af"][:len(ev)][::-1])
    for i, e in enumerate(ev[::-1]):
        ax.text(e[1] / 60 + 0.05, i, f"{e[1] / 60:.1f}", va="center", fontsize=8)
    ax.set_title(HX["tl"], loc="left", fontsize=10); fig.tight_layout(); fig.savefig(f"{out}/ha_timeline.png", dpi=170); plt.close(fig)

# HA-05: scale-out and scale-in times
SX = {"en": dict(t="Horizontal scaling (minutes since the request)", o="Scale out", i="Scale in",
                 eo=["Instance launched", "In service (group)", "Registered with policy (management)", "Healthy target"],
                 ei=["Target deregistered", "Instance terminated", "Object removed (management)"]),
      "es": dict(t="Escalado horizontal (minutos desde la petición)", o="Escalado hacia arriba", i="Escalado hacia abajo",
                 eo=["Instancia lanzada", "En servicio (grupo)", "Registrado con política (gestión)", "Destino sano"],
                 ei=["Destino desregistrado", "Instancia terminada", "Objeto retirado (gestión)"])}[L]
h5 = next((r["detail"] for r in res if r.get("case") == "HA-05" and r.get("type") == "hook"), "")
so, si = (h5.split("Scale in", 1) + [""])[:2]
eo = [(l_, num(p_, so)) for l_, p_ in zip(SX["eo"], (r"launched \+(\d+) s", r"in service \+(\d+) s", r"management \+(\d+) s", r"healthy target \+(\d+) s"))]
ei = [(l_, num(p_, si)) for l_, p_ in zip(SX["ei"], (r"deregistered \+(\d+) s", r"terminated \+(\d+) s", r"removed from the management \+(\d+) s"))]
eo = [e for e in eo if e[1] is not None]; ei = [e for e in ei if e[1] is not None]
if eo or ei:
    fig, axs = plt.subplots(2, 1, figsize=(7.6, 0.42 * (len(eo) + len(ei)) + 1.6), sharex=True,
                            gridspec_kw={"height_ratios": [max(1, len(eo)), max(1, len(ei))]})
    for ax, evs, title, cols in ((axs[0], eo, SX["o"], ["#d97706", "#16a34a", "#7c3aed", "#2563eb"]), (axs[1], ei, SX["i"], ["#2563eb", "#dc2626", "#9ca3af"])):
        if evs:
            ax.barh([e[0] for e in evs][::-1], [e[1] / 60 for e in evs][::-1], color=cols[:len(evs)][::-1])
            for k, e in enumerate(evs[::-1]):
                ax.text(e[1] / 60 + 0.05, k, f"{e[1] / 60:.1f}", va="center", fontsize=8)
        ax.set_title(title, loc="left", fontsize=9, color="#374151")
    fig.suptitle(SX["t"], x=0.02, ha="left", fontsize=10); fig.tight_layout(); fig.savefig(f"{out}/ha_scale.png", dpi=170); plt.close(fig)

# PERF-05/06: new connections per second and request time; PERF-04: concurrent sessions; PERF-08: CPU under load
CX = {"en": dict(cps="New connections per second", rt="Request time (ms)", conc="concurrency", ses="Concurrent sessions",
                 so="opened", sa="answered", sl="alive after idle", cpu="Gateway CPU during the load (%)", avg="average", mx="maximum", cw="CloudWatch max (1 min)"),
      "es": dict(cps="Conexiones nuevas por segundo", rt="Tiempo de petición (ms)", conc="concurrencia", ses="Sesiones simultáneas",
                 so="abiertas", sa="respondidas", sl="vivas tras la espera", cpu="CPU de los gateways durante la carga (%)", avg="media", mx="máxima", cw="máx. CloudWatch (1 min)")}[L]
cps = [(cname.get(r["id"], r["id"]), num(r"(\d+) new connections/s", r["detail"]), num(r"concurrency (\d+)", r["detail"]),
        [num(rf"{p_} ([\d.]+) ms", r["detail"]) for p_ in ("p50", "p95", "p99")]) for r in perf if r["type"] == "cps"]
cps = [c_ for c_ in cps if c_[1]]
if cps:
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9.6, 3.0), gridspec_kw={"width_ratios": [1, 1.3]})
    lbl = [f"{c_[0]}" for c_ in cps]
    a1.barh(lbl[::-1], [c_[1] for c_ in cps][::-1], color="#2563eb")
    for k, c_ in enumerate(cps[::-1]):
        a1.text(c_[1] * 1.01, k, f"{c_[1]:.0f}/s" + (f" ({CX['conc']} {c_[2]:.0f})" if c_[2] else ""), va="center", fontsize=8)
    a1.set_xlim(0, max(c_[1] for c_ in cps) * 1.6); a1.set_title(CX["cps"], loc="left", fontsize=10); a1.tick_params(axis="y", labelsize=8)
    w = 0.26
    for i, (p_, col) in enumerate(zip(("p50", "p95", "p99"), ("#16a34a", "#d97706", "#dc2626"))):
        a2.bar([k + (i - 1) * w for k in range(len(cps))], [(c_[3][i] or 0) for c_ in cps], w, color=col, label=p_)
    a2.set_xticks(range(len(cps))); a2.set_xticklabels([f"{c_[1]:.0f}/s" for c_ in cps], fontsize=8); a2.legend(frameon=False, fontsize=8)
    a2.set_title(CX["rt"], loc="left", fontsize=10)
    fig.tight_layout(); fig.savefig(f"{out}/perf_cps.png", dpi=170); plt.close(fig)
ses = next((r for r in perf if r["type"] == "concurrent"), None)
if ses:
    m = re.search(r"(\d+)/(\d+) sessions open.*?(\d+) answered, (\d+) still alive after (\d+) s", ses["detail"])
    if m:
        got, n_, ans, alive, idle = (int(x) for x in m.groups())
        fig, ax = plt.subplots(figsize=(6.4, 2.0))
        vals = [(CX["so"], got), (CX["sa"], ans), (f"{CX['sl']} ({idle} s)", alive)]
        ax.barh([v[0] for v in vals][::-1], [v[1] for v in vals][::-1], color=["#2563eb", "#16a34a", "#7c3aed"][::-1])
        ax.axvline(n_, color="#6b7280", ls="--", lw=1)
        for k, v in enumerate(vals[::-1]):
            ax.text(v[1] * 0.98, k, f"{v[1]}/{n_}", va="center", ha="right", fontsize=8, color="white", weight="bold")
        ax.set_title(CX["ses"], loc="left", fontsize=10)
        fig.tight_layout(); fig.savefig(f"{out}/perf_sessions.png", dpi=170); plt.close(fig)
p8 = next((r["detail"] for r in res if r.get("case") == "PERF-08" and r.get("type") == "hook"), "")
gws = re.findall(r"([\w.-]+): CPU avg (\d+) %, max (\d+) %", p8)
if gws:
    cwm = {k: int(v) for k, v in re.findall(r"(i-[0-9a-f]+) max (\d+) %", p8.split("CloudWatch", 1)[-1])}
    short = [re.search(r"(i-[0-9a-f]+)", g[0]).group(1) if re.search(r"(i-[0-9a-f]+)", g[0]) else g[0] for g in gws]
    fig, ax = plt.subplots(figsize=(7.2, 2.9)); w = 0.36; xs = range(len(gws))
    ax.bar([x - w / 2 for x in xs], [int(g[1]) for g in gws], w, color="#2563eb", label=CX["avg"])
    ax.bar([x + w / 2 for x in xs], [int(g[2]) for g in gws], w, color="#dc2626", label=CX["mx"])
    cwv = [cwm.get(s_) for s_ in short]
    if any(v is not None for v in cwv):
        ax.scatter([x + w / 2 for x, v in zip(xs, cwv) if v is not None], [v for v in cwv if v is not None], marker="_", s=600, color="#111827", label=CX["cw"], zorder=3)
    for x, g in zip(xs, gws):
        ax.text(x - w / 2, int(g[1]) + 1.5, g[1], ha="center", fontsize=8); ax.text(x + w / 2, int(g[2]) + 1.5, g[2], ha="center", fontsize=8)
    ax.set_xticks(list(xs)); ax.set_xticklabels(short, fontsize=8); ax.set_ylim(0, 110); ax.legend(frameon=False, fontsize=8, ncol=3, loc="upper left")
    ax.set_title(CX["cpu"], loc="left", fontsize=10); fig.tight_layout(); fig.savefig(f"{out}/perf_cpu.png", dpi=170); plt.close(fig)
print("ok")
