#!/usr/bin/env python3
"""Firewall Testkit portal (Flask, behind nginx at /portal/).

- Shows the bilingual catalog with the explanation of every check.
- Runs single checks, cases, selections or the full batch on one or several agents (clients).
- Settings: solution under test, environments, server, segmentation matrix, roles, Internet targets and the TLS
  inspection CA (stored in /data/config.json). Clients get it with every job.
- Bootstrap: clients download the testkit CA and the client certificate from /api/bootstrap at start-up.
- Comparison: several runs (e.g. different security solutions) in one Word report.
- Agents long-poll /api/agent/poll through the firewall (HTTP to the server must be allowed); every agent exchange is
  zlib+base64 so the attack payloads inside results do not trigger the IPS.
- Generates the Word report of every run in English or Spanish (report/report.js + report/charts.py).
"""
import base64, json, os, subprocess, threading, time, uuid, zlib
from datetime import datetime, timezone
from flask import Flask, Response, jsonify, request, send_file, send_from_directory

BASE = os.path.dirname(os.path.abspath(__file__))
CATALOG = os.environ.get("CATALOG", "/opt/testkit/catalog/tests.json")
DATA = os.environ.get("DATA_DIR", "/data")
RUNS = os.path.join(DATA, "runs"); os.makedirs(RUNS, exist_ok=True)
REPORT = os.environ.get("REPORT_DIR", "/opt/testkit/server/report")
CONFIG_FILE = os.path.join(DATA, "config.json")
DEFAULT_CONFIG = os.environ.get("TESTKIT_CONFIG", "/opt/testkit/config/config.json")


CERT_DIR = os.environ.get("CERT_DIR", "/data/certs")


def load_config():
    cfg = None
    for p in (CONFIG_FILE, DEFAULT_CONFIG):
        try:
            with open(p, encoding="utf-8") as f:
                cfg = json.load(f); break
        except (OSError, ValueError):
            continue
    cfg = cfg or {"environments": [], "roles": {}, "internet": {}, "segmentation": {"allow": {}, "always": []}, "peers": {}}
    if not cfg.get("server_ip") and not cfg.get("server_env"):
        cfg["server_ip"] = os.environ.get("SERVER_IP", "")
    cfg.setdefault("solution", {"name": "", "vendor": ""})
    return cfg


def server_ip(cfg):
    return cfg.get("server_ip") or next((e["ip"] for e in cfg.get("environments", []) if e.get("name") == cfg.get("server_env")), "")

app = Flask(__name__, static_folder=os.path.join(BASE, "static"))
LOCK = threading.Lock()
AGENTS = {}          # name -> {env, src, last_seen, busy}
QUEUE = {}           # name -> [job]
CAT = json.load(open(CATALOG, encoding="utf-8"))


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def enc(obj):
    return base64.b64encode(zlib.compress(json.dumps(obj).encode()))


def dec(raw):
    return json.loads(zlib.decompress(base64.b64decode(raw))) if raw else {}


def run_path(rid):
    return os.path.join(RUNS, f"{rid}.json")


def load_run(rid):
    with open(run_path(rid), encoding="utf-8") as f:
        return json.load(f)


def save_run(run):
    tmp = run_path(run["id"]) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(run, f, ensure_ascii=False)
    os.replace(tmp, run_path(run["id"]))


# ------------------------------------------------------------------ UI and catalog
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/static/<path:p>")
def static_files(p):
    return send_from_directory(app.static_folder, p)


@app.get("/api/catalog")
def catalog():
    return jsonify(dict(domains=CAT["domains"], cases=CAT["cases"], title=CAT["title"]))


@app.get("/api/bootstrap")
def bootstrap():
    rd = lambda f: open(os.path.join(CERT_DIR, f), encoding="utf-8").read()
    try:
        return jsonify(testkit_ca=rd("testkit_ca.crt"), client_crt=rd("client.crt"), client_key=rd("client.key"))
    except OSError:
        return jsonify(error="certificates not available"), 503


@app.get("/api/config")
def get_config():
    c = load_config(); c["_server_ip"] = server_ip(c)
    return jsonify(c)


@app.put("/api/config")
def put_config():
    c = request.get_json(force=True)
    c.pop("_server_ip", None)
    names = [e.get("name") for e in c.get("environments", [])]
    if any(not n for n in names) or len(set(names)) != len(names):
        return jsonify(error="environments: unique, non-empty names are required"), 400
    if c.get("server_env") and c["server_env"] not in names:
        return jsonify(error="server_env must be one of the environments"), 400
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(c, f, ensure_ascii=False, indent=1)
    os.replace(tmp, CONFIG_FILE)
    return jsonify(ok=True)


@app.get("/api/agents")
def agents():
    t = time.time()
    with LOCK:
        return jsonify([dict(name=n, **{k: v for k, v in a.items()}, online=t - a["last_seen"] < 45) for n, a in sorted(AGENTS.items())])


# ------------------------------------------------------------------ runs
@app.post("/api/runs")
def new_run():
    body = request.get_json(force=True)
    names = body.get("agents") or []
    ids = body.get("ids") or []
    if not names:
        return jsonify(error="Select at least one client"), 400
    cfg = load_config()
    rid = datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]
    sol = (cfg.get("solution") or {}).get("name") or "Solution under test"
    run = dict(id=rid, label=body.get("label") or ("Full batch" if not ids else ", ".join(ids[:6]) + ("…" if len(ids) > 6 else "")),
               solution=sol, created=now(), ids=ids, config=cfg, agents={n: dict(status="queued", total=None, results=[], env=AGENTS.get(n, {}).get("env"),
                                                                   src=AGENTS.get(n, {}).get("src")) for n in names})
    save_run(run)
    with LOCK:
        for n in names:
            QUEUE.setdefault(n, []).append(dict(run_id=rid, ids=ids, config=cfg))
    return jsonify(run)


@app.get("/api/runs")
def list_runs():
    out = []
    for f in sorted(os.listdir(RUNS), reverse=True)[:100]:
        if f.endswith(".json"):
            r = json.load(open(os.path.join(RUNS, f), encoding="utf-8"))
            res = [x for a in r["agents"].values() for x in a["results"]]
            out.append(dict(id=r["id"], label=r["label"], solution=r.get("solution", ""), created=r["created"], agents=list(r["agents"]),
                            status={n: a["status"] for n, a in r["agents"].items()},
                            counts={s: sum(1 for x in res if x["status"] == s) for s in ("OK", "FAIL", "INFO", "SKIP", "ERROR")}))
    return jsonify(out)


@app.get("/api/runs/<rid>")
def get_run(rid):
    return jsonify(load_run(rid))


@app.delete("/api/runs/<rid>")
def del_run(rid):
    for ext in (".json", ".en.docx", ".es.docx", ".csv"):
        p = os.path.join(RUNS, rid + ext)
        if os.path.exists(p):
            os.remove(p)
    return jsonify(ok=True)


@app.get("/api/runs/<rid>/csv")
def run_csv(rid):
    r = load_run(rid)
    lines = ["agent,environment,source_ip,case,check,name,blade,expected,observed,status,detail,start,seconds"]
    q = lambda s: '"' + str(s).replace('"', '""') + '"'
    for n, a in r["agents"].items():
        for x in a["results"]:
            lines.append(",".join(q(v) for v in [n, x.get("env"), x.get("src"), x.get("case"), x["id"], x["name"], x.get("blade"), x["expect"],
                                                  x.get("observed"), x["status"], x.get("detail"), x.get("start"), x.get("seconds")]))
    return Response("\n".join(lines) + "\n", mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=testkit_results_{rid}.csv"})


@app.get("/api/runs/<rid>/report")
def run_report(rid):
    lang = "es" if request.args.get("lang") == "es" else "en"
    out = os.path.join(RUNS, f"{rid}.{lang}.docx")
    if not os.path.exists(out) or os.path.getmtime(out) < os.path.getmtime(run_path(rid)) or request.args.get("force"):
        work = os.path.join(DATA, "work", rid); os.makedirs(work, exist_ok=True)
        try:
            subprocess.run(["python3", os.path.join(REPORT, "charts.py"), run_path(rid), CATALOG, work, lang], check=True, capture_output=True, timeout=180)
            subprocess.run(["node", os.path.join(REPORT, "report.js"), run_path(rid), CATALOG, work, out, lang], check=True, capture_output=True, timeout=180, cwd=REPORT)
        except subprocess.CalledProcessError as e:
            return Response("Error generating the report:\n" + e.stderr.decode()[-3000:], status=500, mimetype="text/plain")
    name = "Informe_Pruebas_Seguridad" if lang == "es" else "Security_Test_Report"
    return send_file(out, as_attachment=True, download_name=f"{name}_{rid}.docx")


@app.get("/api/compare")
def compare_report():
    ids = [x for x in request.args.get("runs", "").split(",") if x]
    lang = "es" if request.args.get("lang") == "es" else "en"
    if len(ids) < 2:
        return Response("select at least two runs", status=400, mimetype="text/plain")
    for rid in ids:
        if not os.path.exists(run_path(rid)):
            return Response(f"unknown run {rid}", status=404, mimetype="text/plain")
    key = "_".join(sorted(ids))[:120]
    work = os.path.join(DATA, "work", "cmp_" + key); os.makedirs(work, exist_ok=True)
    out = os.path.join(work, f"compare.{lang}.docx")
    try:
        paths = [run_path(r) for r in ids]
        subprocess.run(["python3", os.path.join(REPORT, "compare_charts.py"), CATALOG, work, lang] + paths, check=True, capture_output=True, timeout=180)
        subprocess.run(["node", os.path.join(REPORT, "compare.js"), CATALOG, work, out, lang] + paths, check=True, capture_output=True, timeout=180, cwd=REPORT)
    except subprocess.CalledProcessError as e:
        return Response("Error generating the comparison:\n" + e.stderr.decode()[-3000:], status=500, mimetype="text/plain")
    name = "Comparativa_Soluciones" if lang == "es" else "Solution_Comparison"
    return send_file(out, as_attachment=True, download_name=f"{name}_{datetime.now().strftime('%Y%m%d-%H%M')}.docx")


# ------------------------------------------------------------------ agent API (zlib + base64 body)
def touch(body, busy=None):
    n = body.get("agent") or request.args.get("agent")
    with LOCK:
        a = AGENTS.setdefault(n, dict(env=None, src=None, busy=False))
        a.update(env=body.get("env", a["env"]) or request.args.get("env"), src=body.get("src", a["src"]) or request.args.get("src"), last_seen=time.time())
        if busy is not None:
            a["busy"] = busy
    return n


@app.post("/api/agent/poll")
def agent_poll():
    body = dec(request.get_data()); n = touch(body)
    t0 = time.time()
    while time.time() - t0 < 25:
        with LOCK:
            q = QUEUE.get(n) or []
            if q:
                job = q.pop(0); AGENTS[n]["busy"] = True
                return Response(enc(job), mimetype="application/octet-stream")
            AGENTS[n]["last_seen"] = time.time()
        time.sleep(0.5)
    return Response(enc({}), mimetype="application/octet-stream")


def update_run(rid, fn):
    with LOCK:
        r = load_run(rid); fn(r); save_run(r)


@app.post("/api/agent/start")
def agent_start():
    b = dec(request.get_data()); n = touch(b, True)
    update_run(b["run_id"], lambda r: r["agents"][n].update(status="running", total=b["total"], env=b["env"], src=b["src"], started=now()))
    return Response(enc({}), mimetype="application/octet-stream")


@app.post("/api/agent/result")
def agent_result():
    b = dec(request.get_data()); n = touch(b, True)
    update_run(b["run_id"], lambda r: r["agents"][n]["results"].append(b["result"]))
    return Response(enc({}), mimetype="application/octet-stream")


@app.post("/api/agent/done")
def agent_done():
    b = dec(request.get_data()); n = touch(b, False)
    update_run(b["run_id"], lambda r: r["agents"][n].update(status="done", finished=now()))
    return Response(enc({}), mimetype="application/octet-stream")


if __name__ == "__main__":
    from waitress import serve
    serve(app, host="127.0.0.1", port=8000, threads=32)
