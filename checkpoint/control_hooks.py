"""Check Point hooks of the control agent (Management API: Smart-1 Cloud or on-premises management).

Settings (CONTROL_CONFIG):  mgmt.url (…/web_api), mgmt.api_key_env (name of the variable with the API key, default
MGMT_API_KEY), mgmt.package (policy package, default FW_Testkit), mgmt.gateway_prefix (only these gateways are touched:
run-script and policy installation), mgmt.access_layer (default "<package> Network"), state_dir (policy baseline).

Changes made by a check (temporary rule, IoC, probe objects) are published and installed only on the gateways of the
prefix and always removed at the end. Nothing global is changed.
"""
import json, os, re, time, urllib.error, urllib.request
from control.agent import Skip, hook, log

PROTECTED_INSTALL_TRIES = 10


class Mgmt:
    def __init__(self, ctx):
        self.ctx = ctx
        self.url = (ctx.setting("mgmt.url") or os.environ.get("MGMT_URL") or "").rstrip("/")
        self.key = os.environ.get(ctx.setting("mgmt.api_key_env", "MGMT_API_KEY"), "")
        self.pkg = ctx.setting("mgmt.package", "FW_Testkit")
        self.prefix = ctx.setting("mgmt.gateway_prefix", "")
        if not self.url or not self.key:
            raise Skip("not configured: mgmt.url / management API key")
        self.sid = None

    def __enter__(self):
        r = self._post("login", {"api-key": self.key, "session-name": "testkit-control", "session-timeout": 3600})
        self.sid = r["sid"]; return self

    def __exit__(self, et, ev, tb):
        try:
            if et is not None:
                self._post("discard", {})
            self._post("logout", {})
        except Exception:  # noqa
            pass

    def _post(self, cmd, body):
        h = {"Content-Type": "application/json"}
        if self.sid:
            h["X-chkp-sid"] = self.sid
        req = urllib.request.Request(f"{self.url}/{cmd}", data=json.dumps(body).encode(), headers=h)
        for i in range(12):   # transient gateway errors of the management front end (502/503/504, timeouts): retry
            try:
                with urllib.request.urlopen(req, timeout=120) as f:
                    return json.loads(f.read() or b"{}")
            except urllib.error.HTTPError as e:
                if e.code in (502, 503, 504) and i < 11:
                    log(f"management {cmd}: HTTP {e.code}, retrying"); time.sleep(20); continue
                raise RuntimeError(f"{cmd}: HTTP {e.code} {e.read().decode(errors='replace')[:300]}") from None
            except (urllib.error.URLError, TimeoutError) as e:
                if i < 11:
                    log(f"management {cmd}: {e}, retrying"); time.sleep(20); continue
                raise RuntimeError(f"{cmd}: {e}") from None

    def call(self, cmd, body=None):
        return self._post(cmd, body or {})

    def wait(self, tid, timeout=900):
        t0 = time.time()
        while time.time() - t0 < timeout:
            t = self.call("show-task", {"task-id": tid, "details-level": "full"})["tasks"][0]
            if t["status"] != "in progress":
                return t
            time.sleep(5)
        raise RuntimeError(f"task {tid} timed out")

    def publish(self):
        r = self.call("publish")
        if r.get("task-id"):
            t = self.wait(r["task-id"])
            if t["status"] != "succeeded":
                raise RuntimeError(f"publish: {t['status']}")

    def gateways(self):
        objs = self.call("show-simple-gateways", {"limit": 200})["objects"]
        return [o["name"] for o in objs if o["name"].startswith(self.prefix)] if self.prefix else [o["name"] for o in objs]

    def run_script(self, script, timeout=600):
        gws = self.gateways()
        if not gws:
            raise Skip(f"no gateway with prefix '{self.prefix}'")
        r = self.call("run-script", {"script-name": "testkit-control", "script": script, "targets": gws})
        out = {}
        for t in r.get("tasks", []):
            d = self.wait(t["task-id"], timeout)
            msg = "".join(x.get("responseMessage", "") for x in d.get("task-details", []))
            try:
                import base64
                msg = base64.b64decode(msg).decode(errors="replace")
            except Exception:  # noqa
                pass
            out[t["target"]] = msg.strip()
        return out

    def install(self, access=False, threat=False):
        gws = self.gateways(); t0 = time.time()
        body = {"policy-package": self.pkg, "access": access, "threat-prevention": threat, "targets": gws}
        for i in range(PROTECTED_INSTALL_TRIES):
            r = self.call("install-policy", body)
            t = self.wait(r["task-id"], 1200)
            if t["status"] == "succeeded":
                return time.time() - t0
            log(f"install attempt {i + 1}: {t['status']} — retrying in 60 s"); time.sleep(60)
        raise RuntimeError("policy installation failed")

    def logs(self, flt, since=None, n=100):
        """Logs matching the filter since 'since' (epoch; custom time frame so the newest are not cut by the page size)."""
        q = {"filter": flt, "max-logs-per-request": n}
        if since:
            st = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(since - 60))
            q.update({"time-frame": "custom", "custom-start": st, "custom-end": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + 300))})
        else:
            q["time-frame"] = "last-hour"
        r = self.call("show-logs", {"new-query": q})
        return r.get("logs", [])

    def layers(self):
        p = self.call("show-package", {"name": self.pkg, "details-level": "full"})
        acc = [x["name"] for x in p.get("access-layers", [])]
        thr = [x["name"] for x in p.get("threat-layers", [])]
        https = ((p.get("https-inspection-layers") or {}).get("outbound-https-layer") or {}).get("name")
        return acc, thr, ([https] if https else [])

    def access_layers(self):
        """Ordered access layers of the package including inline layers (rules with «Apply Layer»)."""
        acc, out = self.layers()[0], []
        while acc:
            L = acc.pop(0)
            if L in out:
                continue
            out.append(L)
            for r, names in self.rulebase("access", L):
                il = r.get("inline-layer")
                if il:
                    acc.append(il.get("name") if isinstance(il, dict) else names.get(il, il))
        return out

    def rulebase(self, kind, layer, **kw):
        items, off = [], 0
        while True:
            r = self.call(f"show-{kind}-rulebase", dict({"name": layer, "limit": 200, "offset": off, "use-object-dictionary": True, "details-level": "standard"}, **kw))
            names = {o["uid"]: o.get("name", o["uid"]) for o in r.get("objects-dictionary", [])}
            for it in r.get("rulebase", []):
                for x in (it.get("rulebase") if it.get("type", "").endswith("section") else [it]) or []:
                    x["_section"] = it.get("name") if it.get("type", "").endswith("section") else ""
                    items.append((x, names))
            off = r.get("to", 0)
            if off >= r.get("total", 0):
                return items


def nm(v, names):
    if isinstance(v, list):
        return sorted(nm(x, names) for x in v)
    if isinstance(v, dict):
        return v.get("name") or names.get(v.get("uid"), v.get("uid"))
    return names.get(v, v)


# ------------------------------------------------------------------ adapters used by the AWS hooks
@hook("checkpoint._gateways")
def gateways(ctx):
    with Mgmt(ctx) as m:
        objs = m.call("show-gateways-and-servers", {"details-level": "full", "limit": 200}).get("objects", [])
    out = {}
    for o in objs:
        mm = re.search(r"(i-[0-9a-f]{8,})", o.get("name", ""))
        if mm and o["name"].startswith(m.prefix):
            out[mm.group(1)] = dict(name=o["name"], policy=bool((o.get("policy") or {}).get("access-policy-installed") or (o.get("policy") or {}).get("access-policy-name")))
    return out


CPU = r"""N={n}; p=($(awk '/^cpu /{{print $2+$3+$4+$5+$6+$7+$8+$9, $5+$6}}' /proc/stat))
for i in $(seq $N); do sleep 5; c=($(awk '/^cpu /{{print $2+$3+$4+$5+$6+$7+$8+$9, $5+$6}}' /proc/stat))
  echo $(( 100*((c[0]-p[0])-(c[1]-p[1]))/(c[0]-p[0]) )); p=(${{c[@]}}); done | awk '{{s+=$1; if($1>m)m=$1; k++}} END{{printf "CPU avg %.0f %%, max %.0f %% (%d samples of 5 s)", s/k, m, k}}'
fw tab -t connections -s 2>/dev/null | tail -1 | awk '{{printf ", connections %s (peak %s)", $4, $5}}'"""


@hook("checkpoint._cpu_sample")
def cpu_sample(ctx, seconds):
    with Mgmt(ctx) as m:
        return m.run_script(CPU.format(n=max(1, int(seconds / 5))), timeout=seconds + 300)


# ------------------------------------------------------------------ POL-14
@hook("checkpoint.unused_rules")
def unused_rules(c, ctx):
    with Mgmt(ctx) as m:
        acc = m.access_layers(); tot, zero, off = 0, [], []
        for L in acc:
            for r, names in m.rulebase("access", L, **{"show-hits": True}):
                if r.get("type") != "access-rule":
                    continue
                tot += 1
                if not r.get("enabled", True):
                    off.append(f"{L}: {r.get('name') or r['rule-number']}")
                elif (r.get("hits") or {}).get("value", 0) == 0:
                    zero.append(f"{r.get('name') or 'rule ' + str(r.get('rule-number'))}")
    det = (f"{tot} access rules in {len(acc)} layers of {m.pkg}; {len(zero)} without hits since the counters started"
           + (f": {', '.join(zero[:25])}{' …' if len(zero) > 25 else ''}" if zero else "") + (f"; disabled: {', '.join(off)}" if off else "")
           + ". Candidates for review/cleanup (a rule without hits may still be needed for rare flows: confirm with the owner).")
    return "MEASURE", det


# ------------------------------------------------------------------ POL-16
def snapshot(m):
    _, thr, https = m.layers(); acc = m.access_layers(); out = {}
    for kind, layers in (("access", acc), ("threat", thr), ("https", https)):
        for L in layers:
            rows = []
            for r, names in m.rulebase(kind, L):
                if not r.get("type", "").endswith("rule"):
                    continue
                rows.append(dict(name=r.get("name", ""), section=r.get("_section", ""), enabled=r.get("enabled", True), action=nm(r.get("action"), names),
                                 source=nm(r.get("source", []), names), destination=nm(r.get("destination", []), names),
                                 service=nm(r.get("service", []), names), negate=[r.get("source-negate"), r.get("destination-negate"), r.get("service-negate")],
                                 extra=nm(r.get("site-category", r.get("protected-scope", [])), names)))
            out[f"{kind}:{L}"] = rows
    return out


def diff(a, b):
    d = []
    for k in sorted(set(a) | set(b)):
        ra, rb = {json.dumps(x, sort_keys=True) for x in a.get(k, [])}, {json.dumps(x, sort_keys=True) for x in b.get(k, [])}
        add = [json.loads(x)["name"] or "(unnamed)" for x in rb - ra]; rem = [json.loads(x)["name"] or "(unnamed)" for x in ra - rb]
        order = [x["name"] for x in a.get(k, [])] != [x["name"] for x in b.get(k, [])] and not add and not rem
        if add or rem or order:
            d.append(f"{k.split(':', 1)[1]}: " + ", ".join(filter(None, [f"added/changed {add}" if add else "", f"removed/changed {rem}" if rem else "", "order changed" if order else ""])))
    return d


@hook("checkpoint.policy_drift")
def policy_drift(c, ctx):
    sd = os.path.expanduser(ctx.setting("state_dir", "~/.testkit-control")); os.makedirs(sd, exist_ok=True)
    with Mgmt(ctx) as m:
        base_f = os.path.join(sd, f"policy-baseline-{m.pkg}.json")
        cur = snapshot(m); first = not os.path.exists(base_f)
        if first:
            json.dump(cur, open(base_f, "w"), indent=1)
        base = json.load(open(base_f))
        d0 = diff(base, cur)
        layer = ctx.setting("mgmt.access_layer", f"{m.pkg} Network")
        m.call("add-access-rule", {"layer": layer, "position": "bottom", "name": "TK drift probe", "enabled": False, "action": "Drop", "comments": "temporary: POL-16 drift test"})
        m.publish()
        try:
            d1 = diff(base, snapshot(m))
        finally:
            m.call("delete-access-rule", {"layer": layer, "name": "TK drift probe"}); m.publish()
        d2 = diff(base, snapshot(m))
    detected = any("TK drift probe" in x for x in d1); back = d2 == d0
    det = (("Baseline captured now (first run). " if first else f"Baseline: {base_f}. ") + f"Current policy vs baseline: {'; '.join(d0) or 'no drift'}. "
           f"Out-of-band change (disabled rule added through the API and published): {'detected — ' + '; '.join(x for x in d1 if 'drift' in x) if detected else 'NOT detected'}; "
           f"after removing it the comparison {'returns to the previous state' if back else 'does not return to the previous state: ' + '; '.join(d2)}.")
    return ("PASS" if detected and back else "NOT_MET"), det


# ------------------------------------------------------------------ IPS-03
@hook("checkpoint.ips_status")
def ips_status(c, ctx):
    with Mgmt(ctx) as m:
        s = m.call("show-ips-status")
        try:
            sch = m.call("show-ips-update-schedule")
        except RuntimeError:
            sch = {}
        prof = m.call("show-threat-profiles", {"details-level": "full", "limit": 50}).get("profiles", [])
    inst = (s.get("installed-version-creation-time") or {}).get("posix", 0) / 1000
    age = (time.time() - inst) / 86400 if inst else None
    tk = [p for p in prof if p.get("name", "").startswith("TK_")] or prof[:3]
    pr = "; ".join(f"{p['name']}: IPS {'on' if p.get('ips') else 'off'}, active-protections {p.get('active-protections-performance-impact', '?')} impact / "
                   f"{p.get('active-protections-severity', '?')} severity / {p.get('confidence-level-high', '?')} on high confidence" for p in tk)
    det = (f"IPS package installed {s.get('installed-version')} ({(s.get('installed-version-creation-time') or {}).get('iso-8601', '?')}"
           f"{f', {age:.1f} days old' if age is not None else ''}); latest {s.get('latest-version')}; update available: {s.get('update-available')}; "
           f"last update {(s.get('last-updated') or {}).get('iso-8601', '?')}; scheduled update: {sch.get('enabled', 'managed by the service') if sch else 'managed by the service'}. Profiles: {pr}")
    ok = (not s.get("update-available")) or (age is not None and age <= 7)
    return ("PASS" if ok else "NOT_MET"), det + ". Criterion: signatures not older than 7 days."


# ------------------------------------------------------------------ IPS-10
@hook("checkpoint.ioc_reaction")
def ioc_reaction(c, ctx):
    dom = ctx.cfg["internet"].get("ioc_test_domain") or "ioc-test.testkit.invalid"
    site = ctx.cfg["internet"].get("allowed_site", "www.example.com")
    ag = ctx.agent_for(); name = "TK IoC reaction test"
    probe = [dict(type="http", url=f"http://{dom}/beacon", args=["--resolve", f"{dom}:80:{{RESOLVE:{site}}}"], expect="BLOCK", name="IoC domain")]
    pre = ctx.checks(ag["name"], probe)[0]
    if pre["observed"] == "BLOCK":
        return "NOT_MET", f"precondition: {dom} is already blocked before loading the indicator ({pre['detail']})"
    t_inst = None
    with Mgmt(ctx) as m:
        t0 = time.time()
        m.call("add-threat-indicator", {"name": name, "action": "Prevent", "ignore-warnings": True, "observables": [
            {"name": f"{name} domain", "domain": dom, "confidence": "high", "severity": "critical", "product": "AB", "comments": "Firewall Testkit IPS-10"}]})
        m.publish(); t_pub = time.time()
        try:
            t_inst = m.install(threat=True); t_after = time.time(); blocked = None
            while time.time() - t_after < 900:
                r = ctx.checks(ag["name"], probe)[0]
                if r["observed"] == "BLOCK":
                    blocked = time.time(); break
                time.sleep(10)
        finally:
            m.call("delete-threat-indicator", {"name": name}); m.publish(); m.install(threat=True)
    det = (f"Indicator (domain {dom}, Prevent) created and published in {t_pub - t0:.0f} s, threat prevention installed in {t_inst:.0f} s; "
           + (f"traffic from {(ag.get('env') or '').upper()} blocked {blocked - t0:.0f} s after creating the indicator ({r['detail']})" if blocked
              else "traffic NOT blocked within 15 min after the installation") + ". Indicator removed and policy reinstalled.")
    return ("PASS" if blocked else "NOT_MET"), det


# ------------------------------------------------------------------ THR-06
UPD = r"""for b in antimalware urlf appi; do cpstat $b -f update_status 2>/dev/null | grep -iE 'status|version|update' | sed "s/^/$b: /"; done
f=$FWDIR/log/updatable_objects/online_services_package_status.elg; [ -f $f ] && grep -i 'Load Status' $f | tail -1 | sed 's/^/updatable objects: /'"""


@hook("checkpoint.tp_updates")
def tp_updates(c, ctx):
    with Mgmt(ctx) as m:
        out = m.run_script(UPD)
    bad, per = [], []
    for g, txt in out.items():
        lines = [re.sub(r"\s+", " ", x).strip() for x in txt.splitlines() if x.strip()]
        st = [x for x in lines if re.search(r"status", x, re.I)]
        if not st:
            bad.append(f"{g}: no update information")
        bad += [f"{g}: {x}" for x in st if re.search(r"fail|error|not up|never", x, re.I)]
        per.append(f"{g}: " + "; ".join(lines[:10]))
    det = " | ".join(per)
    return ("NOT_MET", "Problems: " + "; ".join(bad) + ". " + det) if bad else ("PASS", det)


# ------------------------------------------------------------------ OBS-01 / OBS-02
FIELD = dict(time=["time"], action=["action"], rule=["rule_name", "rule_uid", "rule"], layer=["layer_name", "layer_uuid", "policy_name"],
             source=["src"], destination=["dst"], service=["service", "service_id", "s_port"], gateway=["origin", "orig", "originsicname", "origin_sic_name"])
TFIELD = dict(protection=["protection_name", "malware_rule_name", "attack", "matched_category", "appi_name"], severity=["severity"],
              confidence=["confidence_level"], action=["action"], profile=["smartdefense_profile", "policy_name", "layer_name", "rule_name"])


def has(l, keys):
    return next((str(l[k]) for k in keys if l.get(k) not in (None, "", [])), None)


def find_logs(m, flt, since, want, timeout=600):
    t0 = time.time(); found = {}
    while time.time() - t0 < timeout:
        for l in m.logs(flt, since):
            ts = (l.get("time") or "").replace("Z", "+00:00")
            try:
                from datetime import datetime
                tl = datetime.fromisoformat(ts).timestamp()
            except ValueError:
                tl = since
            if tl < since - 5:
                continue
            for k, pred in want.items():
                if k not in found and pred(l):
                    found[k] = (l, time.time())
        if len(found) == len(want):
            break
        time.sleep(10)
    return found


@hook("checkpoint.logs_connection")
def logs_connection(c, ctx):
    ag = ctx.agent_for(); src, srv = ag.get("src"), ctx.cfg["server"]
    t0 = time.time()
    rs = ctx.checks(ag["name"], [dict(type="http", url=f"http://{srv}/index.html?obs01", expect="ALLOW", name="allowed"), dict(type="tcp", host=srv, port=22, expect="BLOCK", name="denied")])
    with Mgmt(ctx) as m:
        f = find_logs(m, f"src:{src} AND dst:{srv}", t0, {
            "allowed": lambda l: (l.get("action") or "").lower() == "accept" and ("80" in str(l.get("service")) or l.get("service_id") == "http")
            and not str(l.get("rule_name", "")).startswith("CPNotEnoughData"),
            "denied": lambda l: (l.get("action") or "").lower() in ("drop", "reject") and ("22" in str(l.get("service")) or l.get("service_id") == "ssh")})
    parts, ok = [], True
    for k in ("allowed", "denied"):
        if k not in f:
            parts.append(f"{k} connection: log NOT found"); ok = False; continue
        l, seen = f[k]; miss = [n for n, keys in FIELD.items() if not has(l, keys)]
        ok &= not miss
        parts.append(f"{k}: {l.get('action')} by rule '{has(l, FIELD['rule'])}' ({has(l, FIELD['layer'])}) on {has(l, FIELD['gateway'])}, "
                     f"visible {seen - t0:.0f} s after the connection" + (f", missing fields: {miss}" if miss else ""))
    det = (f"From {(ag.get('env') or '').upper()} ({src}) to {srv}: {rs[0]['observed']} http and {rs[1]['observed']} tcp/22. " + "; ".join(parts) +
           ". Each log carries time, action, rule, layer, source, destination, service and gateway.")
    return ("PASS" if ok else "NOT_MET"), det


@hook("checkpoint.logs_threat")
def logs_threat(c, ctx):
    ag = ctx.agent_for(); src, srv = ag.get("src"), ctx.cfg["server"]
    blocked = ctx.cfg["internet"].get("blocked_fqdn", "www.example.org")
    t0 = time.time()
    ctx.checks(ag["name"], [dict(type="http", url=f"http://{srv}/index.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--", expect="BLOCK", name="IPS"),
                            dict(type="http", url=f"http://{srv}/demo/eicar.com", expect="BLOCK", name="AV"),
                            dict(type="http", url=f"https://{blocked}/", expect="BLOCK", name="URL")])
    with Mgmt(ctx) as m:
        f = find_logs(m, f"src:{src}", t0, {
            "IPS": lambda l: "IPS" in str(l.get("product")) and "EICAR" not in str(l.get("protection_name")),
            "Anti-malware": lambda l: "Anti-Virus" in str(l.get("product")) or "EICAR" in str(l.get("protection_name") or l.get("malware_rule_name") or ""),
            "URL/App": lambda l: re.search(r"URL Filtering|Application Control", str(l.get("product") or l.get("blade"))) is not None})
    parts, ok = [], True
    for k in ("IPS", "Anti-malware", "URL/App"):
        if k not in f:
            parts.append(f"{k}: log NOT found"); ok = False; continue
        l, seen = f[k]
        need = ["protection", "action"] + (["severity", "confidence"] if k != "URL/App" else [])
        miss = [n for n in need if not has(l, TFIELD[n])]; ok &= not miss
        parts.append(f"{k}: '{has(l, TFIELD['protection'])}' {l.get('action')}, severity {has(l, TFIELD['severity']) or '-'}, confidence "
                     f"{has(l, TFIELD['confidence']) or '-'}, profile/rule '{has(l, TFIELD['profile'])}', visible {seen - t0:.0f} s later" + (f" (missing {miss})" if miss else ""))
    return ("PASS" if ok else "NOT_MET"), f"Events generated from {(ag.get('env') or '').upper()} ({src}): " + "; ".join(parts)


# ------------------------------------------------------------------ OBS-08 (gateway side)
HEALTH = r"""C=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8+$9, $5+$6}' /proc/stat); sleep 3; D=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8+$9, $5+$6}' /proc/stat)
echo "$C $D" | awk '{printf "cpu %.0f%%; ", 100*(($3-$1)-($4-$2))/($3-$1)}'
free -m | awk '/^Mem/{printf "memory %.0f%% of %d MB; ", $3/$2*100, $2}'
fw tab -t connections -s 2>/dev/null | tail -1 | awk '{printf "connections %s (peak %s); ", $4, $5}'
df -P / /var/log 2>/dev/null | awk 'NR>1{printf "disk %s %s; ", $6, $5}'
cpwd_admin list 2>/dev/null | awk 'NR>1 && NF>3 && $3!="E"{d=d" "$1} END{printf "processes down:%s", (d==""?" none":d)}'"""


@hook("checkpoint.health")
def fw_health(c, ctx):
    with Mgmt(ctx) as m:
        out = m.run_script(HEALTH)
        objs = {o["name"]: o for o in m.call("show-gateways-and-servers", {"details-level": "full", "limit": 200}).get("objects", []) if o["name"] in out}
    bad = [g for g, t in out.items() if "processes down: none" not in t]
    det = " | ".join(f"{g}: {t}; policy {((objs.get(g) or {}).get('policy') or {}).get('access-policy-name', '?')}" for g, t in out.items())
    return ("NOT_MET", "Processes down on " + ", ".join(bad) + ". " + det) if bad else ("PASS", det)


# ------------------------------------------------------------------ OPS-03
@hook("checkpoint.api_pipeline")
def api_pipeline(c, ctx):
    ag = ctx.agent_for(); src, srv = ag["src"], ctx.cfg["server"]
    # HTTPS, not HTTP: the agents talk to the portal over http on the same server, blocking it would cut them off
    probe = [dict(type="tcp", host=srv, port=443, expect="ALLOW", name="https to the server")]
    pre = ctx.checks(ag["name"], probe)[0]
    if pre["observed"] != "ALLOW":
        return "NOT_MET", f"precondition: https to the server is not allowed from {ag.get('env')} ({pre['detail']})"
    rule, ev = "TK pipeline probe", {}
    with Mgmt(ctx) as m:
        layer = ctx.setting("mgmt.access_layer", f"{m.pkg} Network")
        t0 = time.time()
        try:
            m.call("add-host", {"name": "TK_pipeline_src", "ip-address": src, "ignore-warnings": True, "tags": ["firewall-testkit"]})
            m.call("add-host", {"name": "TK_pipeline_dst", "ip-address": srv, "ignore-warnings": True, "tags": ["firewall-testkit"]})
            m.call("add-access-rule", {"layer": layer, "position": "top", "name": rule, "source": ["TK_pipeline_src"], "destination": ["TK_pipeline_dst"],
                                       "service": ["https"], "action": "Drop", "track": {"type": "Log"}, "comments": "temporary: OPS-03 change pipeline test"})
            m.publish(); ev["published"] = time.time()
            ev["install1"] = m.install(access=True); t1 = time.time()
            while time.time() - t1 < 300:
                if ctx.checks(ag["name"], probe)[0]["observed"] == "BLOCK":
                    ev["blocked"] = time.time(); break
                time.sleep(5)
        finally:
            for cmd, body in (("delete-access-rule", {"layer": layer, "name": rule}), ("delete-host", {"name": "TK_pipeline_src"}), ("delete-host", {"name": "TK_pipeline_dst"})):
                try:
                    m.call(cmd, body)
                except RuntimeError:
                    pass
            m.publish(); t2 = time.time(); ev["install2"] = m.install(access=True); t3 = time.time()
            while time.time() - t3 < 300:
                if ctx.checks(ag["name"], probe)[0]["observed"] == "ALLOW":
                    ev["restored"] = time.time(); break
                time.sleep(5)
    blk = f"{ev['blocked'] - t0:.0f} s after the API call" if ev.get("blocked") else "NOT observed"
    rst = f"{ev['restored'] - t2:.0f} s after the rollback" if ev.get("restored") else "NOT observed"
    det = (f"Rule added through the API (Drop {(ag.get('env') or '').upper()} → server https) and published in {ev['published'] - t0:.0f} s, access policy installed "
           f"in {ev['install1']:.0f} s, traffic blocked {blk}; rule removed, reinstalled in {ev['install2']:.0f} s, traffic allowed again {rst}. "
           "The same calls are what a pipeline (Terraform provider, Ansible, CI/CD) uses.")
    return ("PASS" if ev.get("blocked") and ev.get("restored") else "NOT_MET"), det
