#!/usr/bin/env python3
"""Firewall Testkit control agent: runs the operator-side checks of the catalog (runner = "control").

It runs where the cloud and management credentials are (an admin host, never inside a workload) and registers in the
portal as one more agent ("control"), so the portal and the reports treat its checks like any other:

  HA-*    fails over / isolates / scales the firewall tier while the traffic agents probe continuously
  OBS-*   generates traffic from a client and finds it in the firewall logs; health and alarms
  POL-*, OPS-*, IPS-03/10, THR-06, NET-06, PERF-08   management and cloud API checks

Hooks: control/aws_hooks.py (AWS) and <vendor>/control_hooks.py (e.g. checkpoint/). A check names its hook
("aws.instance_failure", "fw.unused_rules"…); "fw.*" hooks are resolved by the vendor of the solution under test.

  python3 control/agent.py            agent mode (PORTAL_URL, CONTROL_CONFIG)
  python3 control/agent.py run ID…    run checks once from the CLI (no portal run; tasks still go through the portal)

Environment: PORTAL_URL=http://<server>/portal  CONTROL_CONFIG=control.json  (+ cloud and management credentials,
see docs). Checks marked "disruptive" wait until every traffic agent of the run has finished.
"""
import base64, importlib, json, os, sys, time, traceback, urllib.request, zlib

H = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(H)
sys.path.insert(0, os.path.join(ROOT, "client")); sys.path.insert(0, ROOT)
os.environ.setdefault("CATALOG", os.path.join(ROOT, "catalog", "tests.json"))
import runner  # noqa: E402

URL = os.environ.get("PORTAL_URL", "").rstrip("/")
NAME = os.environ.get("AGENT_NAME", "control")
SETTINGS = json.load(open(os.environ["CONTROL_CONFIG"], encoding="utf-8")) if os.environ.get("CONTROL_CONFIG") else {}
HOOKS = {}
if __name__ == "__main__":   # the hook modules import control.agent: make it this same module (one HOOKS registry)
    sys.modules["control.agent"] = sys.modules["__main__"]


class Skip(Exception):
    """The check does not apply here (other cloud/vendor, not configured…): reported as N/A."""


def hook(name):
    def deco(fn):
        HOOKS[name] = fn; return fn
    return deco


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ------------------------------------------------------------------ portal
def _req(path, data=None, method=None, packed=False):
    body = None
    if data is not None:
        body = base64.b64encode(zlib.compress(json.dumps(data).encode())) if packed else json.dumps(data).encode()
    r = urllib.request.Request(URL + path, data=body, method=method, headers={"Content-Type": "application/octet-stream" if packed else "application/json"})
    with urllib.request.urlopen(r, timeout=40) as f:
        raw = f.read()
    return (json.loads(zlib.decompress(base64.b64decode(raw))) if raw else {}) if packed else json.loads(raw or b"{}")


class Ctx:
    """What a hook gets: portal configuration, control settings, task helpers and a memo shared by the checks of one job."""

    def __init__(self, conf, run_id=None):
        self.conf = conf; self.cfg = runner.norm_cfg(conf); self.s = SETTINGS; self.run_id = run_id; self.memo = {}

    def setting(self, path, default=None):
        v = self.s
        for k in path.split("."):
            v = v.get(k) if isinstance(v, dict) else None
        return default if v is None else v

    @property
    def vendor(self):
        return ((self.conf.get("solution") or {}).get("vendor") or "").lower().replace(" ", "")

    # traffic agents ---------------------------------------------------------------------------------------------
    def agents(self):
        return [a for a in _req("/api/agents") if a["online"] and a["name"] != NAME and a.get("env") != "control"]

    def agent_for(self, env=None, not_server=True):
        ags = self.agents()
        if env:
            ags = [a for a in ags if a.get("env") == env]
        if not_server:
            ags = [a for a in ags if a.get("env") != self.cfg["server_env"]] or ags
        if not ags:
            raise Skip("no traffic agent online")
        return ags[0]

    def task(self, agent, kind, params):
        return _req("/api/tasks", dict(agent=agent, task=dict(kind=kind, params=params)))["id"]

    def wait(self, tid, timeout=900):
        t0 = time.time()
        while time.time() - t0 < timeout:
            t = _req(f"/api/tasks/{tid}")
            if t.get("status") == "done":
                if not t.get("ok"):
                    raise RuntimeError(f"task failed on the agent: {t.get('error')}")
                return t["result"]
            time.sleep(3)
        self.stop(tid); raise RuntimeError("task timed out")

    def stop(self, tid):
        _req(f"/api/tasks/{tid}/stop", {})

    def checks(self, agent, checks, timeout=900):
        """Runs catalog-style checks on a traffic agent and returns their results."""
        return self.wait(self.task(agent, "checks", dict(checks=checks)), timeout)["results"]

    # continuous probes while something breaks ------------------------------------------------------------------
    def probe_targets(self, env):
        cfg = self.cfg; envs = cfg["envs"]; srv = cfg["server"]; m = cfg["segmentation"]; t = []
        if env != cfg["server_env"] and srv:
            t.append(dict(name="server", type="http", url=f"http://{srv}/index.html"))
        t.append(dict(name="internet", type="http", url="http://{NET:allowed_site}/"))
        # a flow the policy denies: it must never go through, not even while the firewall tier is failing
        for d, ip in envs.items():
            allowed = set(m.get("allow", {}).get(f"{env}>{d}", [])) | set(m.get("always", []))
            if d != env and "ssh" not in allowed:
                t.append(dict(name="denied", type="tcp", host=ip, port=22, expect="BLOCK", dest=d)); break
        return t

    def start_probes(self, duration, sessions=0):
        """Continuous probes on every traffic agent (+ N long HTTP sessions to the server from the non-server ones)."""
        ids = {}
        for a in self.agents():
            ids[a["name"]] = dict(env=a.get("env"), probe=self.task(a["name"], "probe", dict(targets=self.probe_targets(a.get("env")), duration=duration, interval=1)))
            if sessions and a.get("env") != self.cfg["server_env"]:
                ids[a["name"]]["sessions"] = self.task(a["name"], "sessions", dict(host=self.cfg["server"], port=80, n=sessions, interval=2, duration=duration))
        return ids

    def collect(self, ids):
        for v in ids.values():
            self.stop(v["probe"]); v.get("sessions") and self.stop(v["sessions"])
        out = {}
        for a, v in ids.items():
            out[a] = dict(env=v["env"], samples=self.wait(v["probe"], 300)["samples"])
            if v.get("sessions"):
                out[a]["sessions"] = self.wait(v["sessions"], 300)
        return out


# ------------------------------------------------------------------ analysis of the probes
def outages(samples, t0=None, t1=None):
    """Seconds without service per target: longest gap and total, inside [t0, t1]."""
    out = {}
    for name, ss in samples.items():
        ss = [s for s in ss if (t0 is None or s[0] >= t0) and (t1 is None or s[0] <= t1)]
        longest = cur = total = 0.0; start = None; prev = None
        for t, ok in ss:
            if not ok:
                start = t if start is None else start
                cur = t - start + 1; longest = max(longest, cur)
                total += (t - prev) if prev else 1
            else:
                start = None
            prev = t
        out[name] = dict(n=len(ss), ok=sum(1 for s in ss if s[1]), longest=round(longest), total=round(total))
    return out


def fmt_outages(res, t0, t1, denied_note=True):
    parts, worst, leaks = [], 0, 0
    for a, r in sorted(res.items()):
        o = outages(r["samples"], t0, t1)
        txt = []
        for name in ("server", "internet"):
            if name in o:
                fail = 100 * (o[name]["n"] - o[name]["ok"]) / max(1, o[name]["n"])
                txt.append(f"{name} {o[name]['longest']} s ({fail:.0f} % of probes failed)"); worst = max(worst, o[name]["longest"])
        if "denied" in o:
            leaks += o["denied"]["ok"]
        parts.append(f"{(r['env'] or a).upper()}: " + ", ".join(txt))
    det = "longest continuous interruption per client (and share of failed probes in the window): " + "; ".join(parts)
    if denied_note:
        det += f"; denied flow went through {leaks} times" if leaks else "; the denied flow never went through"
    return det, worst, leaks


def recovered(res, since):
    """True if every allowed target answered in all the samples after 'since'."""
    for r in res.values():
        for name, ss in r["samples"].items():
            if name != "denied" and any(not ok for t, ok in ss if t >= since):
                return False
    return True


# ------------------------------------------------------------------ execution
def load_hooks():
    for mod in ("control.aws_hooks", "checkpoint.control_hooks"):
        try:
            importlib.import_module(mod)
        except ImportError as e:
            log(f"hooks {mod} not loaded: {e}")


def resolve(c, ctx):
    name = c["hook"]
    if name.startswith("fw."):
        vendor_name = f"{ctx.vendor}.{name[3:]}"
        if vendor_name not in HOOKS:
            raise Skip(f"no implementation of {name} for the vendor '{ctx.vendor or '-'}' (Settings → solution)")
        return HOOKS[vendor_name]
    if name not in HOOKS:
        raise Skip(f"hook {name} not available on this control agent")
    return HOOKS[name]


def run_hook(c, ctx):
    t0 = time.time()
    r = dict(id=c["id"], name=runner.tr(c["name"]), type="hook", expect=c["expect"], blade=c.get("blade", ""), informative=bool(c.get("informative")),
             env="control", src="operator", start=runner.now(), case=c["case"])
    try:
        obs, det = resolve(c, ctx)(c, ctx)
    except Skip as e:
        obs, det = "SKIP", str(e)
    except Exception as e:  # noqa
        log(traceback.format_exc()); obs, det = "ERROR", f"{e.__class__.__name__}: {e}"[:600]
    r.update(observed="-" if obs == "SKIP" else obs, detail=det, seconds=round(time.time() - t0, 1))
    if obs == "SKIP":
        r["status"] = "SKIP"
    elif obs == "ERROR":
        r["status"] = "ERROR"
    elif c["expect"] == "MEASURE":
        r["status"] = "INFO" if obs == "MEASURE" else "FAIL"
    else:
        r["status"] = "OK" if obs == c["expect"] else ("INFO" if c.get("informative") else "FAIL")
    log(f"{r['id']} {r['status']} {det[:200]}")
    return r


def order(checks):
    return [c for c in checks if not c.get("disruptive")] + [c for c in checks if c.get("disruptive")]


def wait_traffic_agents(run_id):
    """Disruptive checks wait for the traffic agents of the run (their results must not be affected)."""
    while True:
        r = _req(f"/api/runs/{run_id}")
        pend = [n for n, a in r["agents"].items() if n != NAME and a["status"] != "done"]
        if not pend:
            return
        log("waiting for", ", ".join(pend)); time.sleep(20)


def agent():
    load_hooks(); cat = runner.load_catalog()
    log(f"control agent {NAME} → {URL}  hooks: {', '.join(sorted(HOOKS))}")
    me = dict(agent=NAME, env="control", src="operator")
    while True:
        try:
            job = _req(f"/api/agent/poll?agent={NAME}&env=control&src=operator", me, packed=True)
            if not job.get("run_id"):
                continue
            ctx = Ctx(job.get("config") or {}, job["run_id"])
            checks = order(runner.plan(cat, job.get("ids") or [], ctx.cfg, runner="control"))
            _req("/api/agent/start", dict(me, run_id=job["run_id"], total=len(checks)), packed=True)
            waited = False
            for c in checks:
                if c.get("disruptive") and not waited:
                    wait_traffic_agents(job["run_id"]); waited = True
                _req("/api/agent/result", dict(me, run_id=job["run_id"], result=run_hook(c, ctx)), packed=True)
            _req("/api/agent/done", dict(me, run_id=job["run_id"]), packed=True)
        except Exception as e:  # noqa
            log("agent:", e); time.sleep(5)


def cli(ids):
    load_hooks(); cat = runner.load_catalog(); ctx = Ctx(_req("/api/config"))
    for c in order(runner.plan(cat, ids, ctx.cfg, runner="control")):
        r = run_hook(c, ctx); print(f"{r['id']:<10} {r['status']:<6} {r['detail']}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "run":
        cli(sys.argv[2:])
    else:
        agent()
