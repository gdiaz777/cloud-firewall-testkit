#!/usr/bin/env python3
"""Firewall testkit client: runs the catalog checks from the workload IP of this host.

  runner.py list                  list cases and checks
  runner.py run [ID ...]          run checks (case IDs such as "IPS-01" or check IDs such as "IPS-01.3"; none = all)
  runner.py agent                 agent mode: takes jobs from the portal and posts results back

Environment (.env):
  TESTKIT_ENV     name of this client's environment (must exist in the portal configuration)
  SRC_IP          source IP for the tests (workload IP). Empty = the one routed to the server
  PORTAL_URL      http://<server>/portal (agent mode)          AGENT_NAME (default TESTKIT_ENV)
  TESTKIT_CONFIG  JSON configuration for CLI mode (default /opt/testkit/config/config.json)
  LANG_TESTKIT    en | es (CLI output)
"""
import base64, json, os, random, re, socket, ssl, statistics, string, subprocess, sys, tempfile, time, urllib.request, zlib
from datetime import datetime, timezone

CATALOG = os.environ.get("CATALOG", "/opt/testkit/catalog/tests.json")
ENV = os.environ.get("TESTKIT_ENV", "client")
LANG = os.environ.get("LANG_TESTKIT", "en")
TIMEOUT = int(os.environ.get("TIMEOUT", "8"))
CERTS = "/opt/testkit/certs"
PUBLIC_BUNDLE = "/opt/testkit/public-ca-bundle.crt"     # public CAs without the inspection CA
# Block pages of different vendors (Check Point UserCheck, FortiGuard, PAN-OS, Zscaler, Netskope, generic proxies)
BLOCK_MARKERS = re.compile(r"usercheck|access to this (web ?site|application|page) (is|has been) blocked|this (web ?site|page|url) (is|has been) blocked|"
                           r"blocked by (your|the) (organization|organisation|administrator|security policy)|web page blocked|fortiguard|"
                           r"application blocked|request (was|has been) blocked|access denied by policy", re.I)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def norm_cfg(conf):
    """Normalizes the portal configuration into what the checks need."""
    envs = {e["name"]: e["ip"] for e in conf.get("environments", []) if e.get("name") and e.get("ip")}
    srv_env = conf.get("server_env", "")
    return dict(server=conf.get("server_ip") or envs.get(srv_env, ""), server_env=srv_env, envs=envs,
                roles=conf.get("roles", {}), peers=conf.get("peers", {}), internet=conf.get("internet", {}),
                segmentation=conf.get("segmentation", {}), inspection_ca_match=conf.get("inspection_ca_match") or ca_cn(conf.get("inspection_ca_pem", "")),
                inspection_ca_pem=conf.get("inspection_ca_pem", ""))


def ca_cn(pem):
    """CN of the TLS inspection CA configured in the portal (empty if none)."""
    if not pem.strip():
        return ""
    p = subprocess.run(["openssl", "x509", "-noout", "-subject", "-nameopt", "multiline"], input=pem.encode(), capture_output=True)
    m = re.search(rb"commonName\s*=\s*(.+)", p.stdout)
    return m.group(1).decode().strip() if m else ""


_PUBLIC_CNS = None


def public_issuer(issuer):
    """True if the issuer is a public CA (in the bundle without the inspection CA) or the testkit CA."""
    global _PUBLIC_CNS
    if _PUBLIC_CNS is None:
        _PUBLIC_CNS = set()
        try:
            pems = re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", open(PUBLIC_BUNDLE).read(), re.S)
            for pem in pems:
                cn = ca_cn(pem)
                if cn:
                    _PUBLIC_CNS.add(cn)
        except OSError:
            pass
    if "Firewall Testkit CA" in issuer:
        return True
    m = re.search(r"CN\s*=\s*([^,/]+)", issuer)
    cn = m.group(1).strip() if m else issuer
    # Public intermediates are not in the bundle: treat well-known public issuers by organisation as public
    return cn in _PUBLIC_CNS or bool(re.search(r"O\s*=\s*(DigiCert|Let's Encrypt|Sectigo|GlobalSign|Amazon|Google Trust Services|Entrust|GoDaddy|Microsoft|Cloudflare|ZeroSSL|Certum|IdenTrust|Buypass|HARICA|SSL\.com)", issuer))


INSTALLED_CA = None


def install_inspection_ca(pem):
    """Adds the TLS inspection CA from the portal configuration to the container trust store (TLS-02)."""
    global INSTALLED_CA
    if not pem.strip() or pem == INSTALLED_CA:
        return
    with open("/usr/local/share/ca-certificates/testkit_inspection_ca.crt", "w") as f:
        f.write(pem)
    subprocess.run(["update-ca-certificates"], capture_output=True)
    INSTALLED_CA = pem


def load_cfg():
    """CLI mode: configuration from the portal (PORTAL_URL) or, if unreachable, from TESTKIT_CONFIG."""
    url = os.environ.get("PORTAL_URL")
    if url:
        try:
            with urllib.request.urlopen(url.rstrip("/") + "/api/config", timeout=10) as r:
                conf = json.load(r)
            c = norm_cfg(conf); install_inspection_ca(c["inspection_ca_pem"]); return c
        except Exception:  # noqa
            pass
    path = os.environ.get("TESTKIT_CONFIG", "/opt/testkit/config/config.json")
    try:
        return norm_cfg(json.load(open(path, encoding="utf-8")))
    except (OSError, ValueError):
        return norm_cfg({})


def tr(x):
    return x.get(LANG) or x.get("en") if isinstance(x, dict) else x


def src_ip():
    if os.environ.get("SRC_IP"):
        return os.environ["SRC_IP"]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((os.environ.get("SERVER_IP") or "10.255.255.255", 9)); return s.getsockname()[0]
    finally:
        s.close()


SRC = src_ip()


def iface_of(ip):
    out = subprocess.run(["ip", "-o", "-4", "addr"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        p = line.split()
        if p[3].split("/")[0] == ip:
            return p[1]
    return None


def role_envs(cfg, role):
    v = cfg["roles"].get(role)
    return [v] if isinstance(v, str) and v else list(v or [])


def subst(v, cfg):
    if isinstance(v, list):
        return [subst(x, cfg) for x in v]
    if not isinstance(v, str):
        return v
    v = v.replace("{SERVER}", cfg["server"])
    v = v.replace("{PEER}", cfg["envs"].get(cfg["peers"].get(ENV, ""), ""))

    def env(m):
        e = role_envs(cfg, m.group(1))
        return cfg["envs"].get(e[0], "") if e else ""

    def net(m):
        key, op = m.group(1), m.group(2)
        val = cfg["internet"].get(key, "")
        return str(int(val) + int(op)) if op and str(val).isdigit() else str(val)

    def res(m):
        try:
            return socket.gethostbyname(m.group(1))
        except OSError:
            return m.group(1)
    v = re.sub(r"\{ENV:([a-z0-9_]+)\}", env, v)
    v = re.sub(r"\{NET:([a-z0-9_]+)([+-]\d+)?\}", net, v)
    return re.sub(r"\{RESOLVE:([^}]+)\}", res, v)


def sh(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


# ------------------------------------------------------------------ check types
def t_http(c, cfg):
    obs, det = _http_once(c, cfg)
    if c.get("warmup") and obs == "ALLOW":
        # URL categorization runs in background mode: the very first request to an uncached site may pass
        time.sleep(5); obs, det = _http_once(dict(c, warmup=False), cfg); det += " (after categorization retry)"
    elif c.get("expect") == "ALLOW" and "rc=28" in det:
        # a control that should pass must not fail on one lost packet on the Internet path: retry a timeout once
        time.sleep(3); obs, det2 = _http_once(c, cfg); det = f"{det2} (retry after: {det})"
    return obs, det


def _http_once(c, cfg):
    url = subst(c["url"], cfg); args = subst(c.get("args", []), cfg)
    if c.get("warmup"):
        sh(["curl", "-s", "-o", "/dev/null", "-k", "--max-time", "4", "--interface", SRC, url], 6); time.sleep(2)
    body = tempfile.NamedTemporaryFile(delete=False).name
    cmd = ["curl", "-sS", "-k", "-o", body, "-w", "%{http_code} %{time_total} %{redirect_url}", "--max-time", str(TIMEOUT),
           "--interface", SRC] + args + [url]
    rc, out, err = sh(cmd, TIMEOUT + 5)
    data = open(body, "rb").read(200000); os.unlink(body)
    parts = (out or "000 0").split(" ", 2); code = parts[0]; ttot = parts[1] if len(parts) > 1 else "0"; loc = parts[2] if len(parts) > 2 else ""
    text = data.decode("utf-8", "replace")
    if rc == 0:
        if "UserCheck" in loc or "usercheck" in loc.lower():
            return "BLOCK", f"HTTP {code} → redirect to UserCheck (Check Point block page)"
        if BLOCK_MARKERS.search(text) and "FW-TESTKIT-OK" not in text:
            return "BLOCK", f"HTTP {code}: Check Point block page"
        return "ALLOW", f"HTTP {code}, {len(data)} bytes in {float(ttot):.2f} s"
    m = {28: "no answer (dropped)", 35: "TLS handshake cut", 52: "connection closed without response", 56: "connection reset",
         16: "HTTP/2 error (stream cut)", 92: "HTTP/2 stream reset", 7: "connection refused/unreachable", 18: "transfer cut",
         60: "invalid certificate", 6: "DNS resolution failed"}
    if rc == 6 and c.get("dns_fail_block"):
        return "BLOCK", "resolution blocked"
    if rc in m and rc != 6:
        return "BLOCK", f"curl rc={rc}: {m[rc]}"
    return "ERROR", f"curl rc={rc} {err.strip()[:120]}"


def t_tcp(c, cfg):
    host, port = subst(c["host"], cfg), int(subst(c["port"], cfg))
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return "ERROR", f"cannot resolve {host}"
    s = socket.socket(); s.settimeout(4); s.bind((SRC, 0))
    try:
        s.connect((ip, port)); return "ALLOW", f"tcp/{port} open ({ip})"
    except ConnectionRefusedError:
        return "ALLOW", f"tcp/{port} refused by the host (the firewall let it through)"
    except (socket.timeout, TimeoutError):
        return "BLOCK", f"tcp/{port} no answer (dropped)"
    except OSError as e:
        return "BLOCK", f"tcp/{port}: {e.strerror}"
    finally:
        s.close()


def t_icmp(c, cfg):
    host = subst(c["host"], cfg)
    rc, out, _ = sh(["ping", "-I", SRC, "-c", "3", "-W", "2", host], 15)
    m = re.search(r"rtt [^=]+= [\d.]+/([\d.]+)", out)
    return ("ALLOW", f"echo-reply, avg rtt {m.group(1)} ms" if m else "echo-reply") if rc == 0 else ("BLOCK", "no answer")


def t_dns(c, cfg):
    rc, out, err = sh(["dig", "+time=3", "+tries=1", "+short", "-b", SRC, "@" + subst(c["server"], cfg), subst(c["qname"], cfg)], 10)
    ans = out.strip().splitlines()
    return ("ALLOW", f"answer: {', '.join(ans[:2])}") if rc == 0 and ans else ("BLOCK", "no DNS answer")


def t_ntp(c, cfg):
    try:
        ip = socket.gethostbyname(c["host"])
    except OSError:
        return "ERROR", "no resuelve"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4); s.bind((SRC, 0))
    try:
        s.sendto(b"\x1b" + 47 * b"\0", (ip, 123)); s.recvfrom(64); return "ALLOW", f"NTP answer from {ip}"
    except OSError:
        return "BLOCK", f"no NTP answer from {ip}"
    finally:
        s.close()


def t_quic(c, cfg):
    try:
        ip = socket.gethostbyname(c["host"])
    except OSError:
        return "ERROR", "no resuelve"
    # Long header with an unknown version → any QUIC server answers with Version Negotiation
    dcid = os.urandom(8); pkt = bytes([0xC0]) + b"\x1a\x2a\x3a\x4a" + bytes([8]) + dcid + bytes([8]) + os.urandom(8)
    pkt += os.urandom(1200 - len(pkt))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4); s.bind((SRC, 0))
    try:
        s.sendto(pkt, (ip, 443)); s.recvfrom(2048); return "ALLOW", f"QUIC answer from {ip}"
    except OSError:
        return "BLOCK", f"no QUIC answer from {ip} (UDP/443 dropped)"
    finally:
        s.close()


def t_egress_ip(c, cfg):
    rc, out, _ = sh(["curl", "-sS", "--max-time", str(TIMEOUT), "--interface", SRC, "https://checkip.amazonaws.com"], 15)
    return ("ALLOW", f"public egress IP {out.strip()}") if rc == 0 and out.strip() else ("BLOCK", "no answer")


def peer_cert(host, sni, tls=None, port=443):
    ip = socket.gethostbyname(host)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    if tls == "1.2":
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    elif tls == "1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection((ip, port), timeout=TIMEOUT, source_address=(SRC, 0)) as s:
        with ctx.wrap_socket(s, server_hostname=sni) as t:
            der = t.getpeercert(binary_form=True); ver = t.version()
    p = subprocess.run(["openssl", "x509", "-inform", "der", "-noout", "-issuer"], input=der, capture_output=True)
    return p.stdout.decode().strip().replace("issuer=", "").strip(), ver


def t_tls_issuer(c, cfg):
    try:
        issuer, ver = peer_cert(subst(c["host"], cfg), subst(c["sni"], cfg), c.get("tls"))
    except Exception as e:  # noqa
        return "BLOCK", f"handshake failed: {e}"
    match = cfg.get("inspection_ca_match")
    insp = (match in issuer) if match else not public_issuer(issuer)
    return ("INSPECTED" if insp else "NOT_INSPECTED"), f"{ver}; issuer: {issuer}"


def t_tls_verify(c, cfg):
    bundle = {"system": "/etc/ssl/certs/ca-certificates.crt", "public": PUBLIC_BUNDLE, "testkit": f"{CERTS}/testkit_ca.crt"}[c["bundle"]]
    rc, out, err = sh(["curl", "-sS", "-o", "/dev/null", "--max-time", str(TIMEOUT), "--interface", SRC, "--cacert", bundle, "--capath", "/opt/testkit/empty-capath"] + subst(c.get("args", []), cfg) + [subst(c["url"], cfg)], 15)
    if rc == 0:
        return "VALID", "certificate chain valid for this client"
    if rc == 60 or "certificate" in err:
        return "INVALID", f"client rejects the certificate: {err.strip()[:100]}"
    return "ERROR", f"curl rc={rc} {err.strip()[:100]}"


def t_echo_ip(c, cfg):
    rc, out, err = sh(["curl", "-sS", "-k", "--max-time", str(TIMEOUT), "--interface", SRC] + subst(c.get("args", []), cfg) + [subst(c["url"], cfg)], 15)
    if rc != 0:
        return "ERROR", f"curl rc={rc}"
    proxy = re.findall(r"(via|xff)=(\S+)", out)
    ok = f"remote_addr={SRC}" in out and not proxy
    return ("PRESERVED" if ok else "CHANGED"), f"server sees: {out.strip().splitlines()[0][:80]}" + (f"; proxy headers: {proxy}" if proxy else "")


def t_segmented(c, cfg):
    host, port = subst(c["host"], cfg), int(c["port"]); data = c["payload"].encode(); n = int(c.get("chunk", 4))
    s = socket.socket(); s.settimeout(TIMEOUT); s.bind((SRC, 0)); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        s.connect((host, port))
        for i in range(0, len(data), n):
            s.send(data[i:i + n]); time.sleep(0.02)
        resp = s.recv(4096)
        if not resp:
            return "BLOCK", f"{len(data)} bytes in {len(data)//n+1} segments: connection closed without response"
        line = resp.split(b"\r\n", 1)[0].decode("latin1")
        return "ALLOW", f"{len(data)//n+1} segments of {n} bytes; response: {line}"
    except (ConnectionResetError, BrokenPipeError):
        return "BLOCK", "connection reset after sending the segments"
    except (socket.timeout, TimeoutError):
        return "BLOCK", "no answer (dropped)"
    finally:
        s.close()


def t_tcp_hold(c, cfg):
    host, port = subst(c["host"], cfg), int(c.get("port", 80))
    s = socket.socket(); s.settimeout(5); s.bind((SRC, 0)); ok = 0
    try:
        s.connect((host, port))
        for i in range(10):
            s.send(f"GET /index.html?n={i} HTTP/1.1\r\nHost: testkit\r\nConnection: keep-alive\r\n\r\n".encode())
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += s.recv(4096)
            hdr, _, rest = buf.partition(b"\r\n\r\n")
            ln = int(re.search(rb"Content-Length: (\d+)", hdr, re.I).group(1)) if re.search(rb"Content-Length", hdr, re.I) else 0
            while len(rest) < ln:
                rest += s.recv(4096)
            ok += 1; time.sleep(2)
        return "ALLOW", f"10/10 responses on the same TCP session over 20 s ({host})"
    except Exception as e:  # noqa
        return "BLOCK", f"session broken after {ok} responses: {e}"
    finally:
        s.close()


def t_nmap(c, cfg):
    host = subst(c["host"], cfg); ifc = iface_of(SRC)
    allowed = [int(subst(p, cfg)) for p in c["allowed"]]
    rc, out, err = sh(["nmap", "-Pn", "-n", "-T4", "--max-retries", "1", "-e", ifc, "-S", SRC, "-p", "1-1024,3389,5200-5202,8080", "-oG", "-", host], 240)
    opn = sorted(int(p.split("/")[0]) for p in re.findall(r"(\d+)/open", out))
    extra = [p for p in opn if p not in allowed]
    return ("LIMITED" if not extra else "EXPOSED"), f"visible ports: {opn or 'none'}" + (f"; NOT authorized: {extra}" if extra else " (authorized only)")


def t_pmtu(c, cfg):
    host = subst(c["host"], cfg); best = 0
    for size in [1472, 1500, 2000, 4000, 8000, 8472]:
        rc, _, _ = sh(["ping", "-I", SRC, "-M", "do", "-c", "2", "-W", "2", "-s", str(size), host], 10)
        if rc == 0:
            best = size
    return ("MEASURE" if best >= 1472 else "FAIL"), f"largest unfragmented ICMP payload: {best} bytes (IP packet {best + 28})"


def t_banner(c, cfg):
    host, port = subst(c["host"], cfg), int(c["port"])
    s = socket.socket(); s.settimeout(6); s.bind((SRC, 0))
    try:
        s.connect((socket.gethostbyname(host), port)); b = s.recv(256)
        return ("ALLOW", f"banner received: {b[:40]!r}") if b else ("BLOCK", "connection closed without banner")
    except Exception as e:  # noqa
        return "BLOCK", f"no banner ({e.__class__.__name__})"
    finally:
        s.close()


def t_dns_fail(c, cfg):
    name = "testkit-" + "".join(random.choice(string.ascii_lowercase) for _ in range(10)) + ".invalid"
    rc, _, _ = sh(["curl", "-sS", "--max-time", "5", "--interface", SRC, f"http://{name}/"], 10)
    return ("NO_FLOW", f"{name}: does not resolve (curl rc={rc}), no connection opened") if rc == 6 else ("FLOW", f"curl rc={rc}")


def t_https_bench(c, cfg):
    n = int(c.get("n", 100)); res = {}
    for label, sni in [("inspected", "inspect.testkit.lab"), ("not decrypted", "nodecrypt.testkit.lab")]:
        hs, tt = [], []
        for _ in range(n):
            rc, out, _ = sh(["curl", "-sS", "-k", "-o", "/dev/null", "-w", "%{time_connect} %{time_appconnect} %{time_total}", "--max-time", "5",
                             "--interface", SRC, "--resolve", f"{sni}:443:{cfg['server']}", f"https://{sni}/"], 8)
            if rc == 0:
                a, b, t = map(float, out.split()); hs.append((b - a) * 1000); tt.append(t * 1000)
        if not hs:
            return "ERROR", f"no responses ({label})"
        q = lambda v, p: statistics.quantiles(v, n=100)[p - 1] if len(v) > 2 else v[0]
        res[label] = (statistics.median(hs), q(hs, 95), statistics.median(tt), q(tt, 95), len(hs))
    i, b = res["inspected"], res["not decrypted"]
    det = (f"TLS handshake p50/p95: {i[0]:.1f}/{i[1]:.1f} ms inspected vs {b[0]:.1f}/{b[1]:.1f} ms not decrypted; "
           f"total response p50/p95: {i[2]:.1f}/{i[3]:.1f} vs {b[2]:.1f}/{b[3]:.1f} ms ({i[4]}+{b[4]} connections)")
    return "MEASURE", det


# ------------------------------------------------------------------ performance (PERF-*): measurements, run from one client
def pct(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, max(0, int(round(p / 100 * (len(v) - 1)))))] if v else 0.0


def t_iperf(c, cfg):
    """iperf3 against the test server (TCP or UDP). Retries while the server is busy with another test."""
    host, port, secs = subst(c.get("host", "{SERVER}"), cfg), int(subst(str(c.get("port", 5201)), cfg)), int(c.get("seconds", 15))
    cmd = ["iperf3", "-c", host, "-p", str(port), "-B", SRC, "-J", "-t", str(secs), "-i", str(c.get("interval", 1)), "-P", str(c.get("streams", 1))] + c.get("args", [])
    for _ in range(6):
        rc, out, err = sh(cmd, secs + 40)
        try:
            j = json.loads(out)
        except ValueError:
            return "ERROR", f"iperf3 rc={rc} {err.strip()[:120]}"
        if "busy" in str(j.get("error", "")):
            time.sleep(10); continue
        break
    if j.get("error"):
        return "ERROR", f"iperf3: {j['error'][:150]}"
    end = j["end"]; ivals = [i["sum"]["bits_per_second"] / 1e6 for i in j.get("intervals", []) if not i["sum"].get("omitted")]
    if "-u" in c.get("args", []):
        s = end["sum"]; pps = s.get("packets", 0) / max(s.get("seconds", secs), 1)
        return "MEASURE", (f"UDP {s['bits_per_second'] / 1e6:.0f} Mbit/s received, {pps:,.0f} packets/s, loss {s.get('lost_percent', 0):.2f} %, "
                           f"jitter {s.get('jitter_ms', 0):.3f} ms ({c.get('label', '')}{secs} s)").replace(",", ".")
    rx, tx = end["sum_received"]["bits_per_second"] / 1e6, end["sum_sent"]
    det = f"TCP {rx:.0f} Mbit/s ({'download' if '-R' in c.get('args', []) else 'upload'}, {c.get('streams', 1)} streams, {secs} s)"
    if ivals:
        det += f"; per second min/avg/max {min(ivals):.0f}/{statistics.mean(ivals):.0f}/{max(ivals):.0f}"
    if "retransmits" in tx:
        det += f"; retransmissions {tx['retransmits']}"
    return "MEASURE", det


def t_latency(c, cfg):
    """Latency and jitter p50/p95/p99 (ICMP echo, TCP handshake or full HTTP request)."""
    host, n, mode = subst(c.get("host", "{SERVER}"), cfg), int(c.get("n", 200)), c.get("mode", "icmp")
    v = []
    if mode == "icmp":
        rc, out, _ = sh(["ping", "-I", SRC, "-c", str(n), "-i", "0.05", "-W", "1", host], n * 0.2 + 20)
        v = [float(x) for x in re.findall(r"time=([\d.]+)", out)]
    elif mode == "tcp":
        for _ in range(n):
            s = socket.socket(); s.settimeout(2); s.bind((SRC, 0)); t0 = time.perf_counter()
            try:
                s.connect((host, int(c.get("port", 80)))); v.append((time.perf_counter() - t0) * 1000)
            except OSError:
                pass
            finally:
                s.close()
    else:
        for _ in range(n):
            rc, out, _ = sh(["curl", "-s", "-o", "/dev/null", "-w", "%{time_total}", "--max-time", "3", "--interface", SRC, f"http://{host}/index.html"], 6)
            if rc == 0:
                v.append(float(out) * 1000)
    if not v:
        return "ERROR", f"no answers ({mode})"
    jit = statistics.mean(abs(a - b) for a, b in zip(v, v[1:])) if len(v) > 1 else 0
    return "MEASURE", (f"{mode.upper()}: p50 {pct(v, 50):.2f} ms, p95 {pct(v, 95):.2f} ms, p99 {pct(v, 99):.2f} ms, max {max(v):.2f} ms, "
                       f"jitter {jit:.2f} ms; {len(v)}/{n} answers ({100 * (n - len(v)) / n:.1f} % lost)")


def _http_req(s, i):
    s.sendall(f"GET /index.html?c={i} HTTP/1.1\r\nHost: testkit\r\nConnection: keep-alive\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            raise ConnectionError("closed")
        buf += d
    hdr, _, rest = buf.partition(b"\r\n\r\n")
    m = re.search(rb"Content-Length: (\d+)", hdr, re.I); ln = int(m.group(1)) if m else 0
    while len(rest) < ln:
        d = s.recv(65536)
        if not d:
            raise ConnectionError("closed")
        rest += d
    return hdr.split(b"\r\n", 1)[0].decode("latin1")


def raise_nofile():
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE); resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    except (ValueError, OSError, ImportError):
        pass


def t_concurrent(c, cfg):
    """Opens N simultaneous TCP sessions, uses each one, holds them and checks they are still alive (state table capacity)."""
    raise_nofile()
    host, port, n, hold = subst(c.get("host", "{SERVER}"), cfg), int(c.get("port", 80)), int(c.get("n", 2000)), int(c.get("hold", 30))
    socks, t0 = [], time.time()
    for _ in range(n):
        s = socket.socket(); s.settimeout(3); s.bind((SRC, 0))
        try:
            s.connect((host, port)); socks.append(s)
        except OSError:
            s.close()
    est, t_open = len(socks), time.time() - t0
    first = 0
    for i, s in enumerate(socks):
        try:
            _http_req(s, i); first += 1
        except OSError:
            pass
    time.sleep(hold)
    alive = 0
    for i, s in enumerate(socks):
        try:
            _http_req(s, i); alive += 1
        except OSError:
            pass
        finally:
            s.close()
    if not est:
        return "ERROR", "no session could be opened"
    return "MEASURE", (f"{est}/{n} sessions open at the same time (opened in {t_open:.1f} s), {first} answered, "
                       f"{alive} still alive after {hold} s idle ({100 * alive / n:.1f} %)")


def t_cps(c, cfg):
    """New connections per second: short HTTP requests (connect, GET, close) with fixed concurrency during N seconds."""
    import asyncio
    host, port, secs, conc = subst(c.get("host", "{SERVER}"), cfg), int(c.get("port", 80)), int(c.get("seconds", 20)), int(c.get("concurrency", 64))
    lat, err = [], [0]
    # The client closes first (like a browser or API client): TIME_WAIT stays on the client, which then never reuses
    # a 5-tuple the firewall still tracks as closing (a server-side close would make that happen and drop SYNs).
    req = b"GET /index.html HTTP/1.1\r\nHost: testkit\r\n\r\n"

    async def one(r, w):
        w.write(req); await w.drain()
        hdr = await r.readuntil(b"\r\n\r\n")
        m = re.search(rb"Content-Length: (\d+)", hdr, re.I)
        if m:
            await r.readexactly(int(m.group(1)))

    async def worker(stop):
        while time.time() < stop:
            t0 = time.perf_counter(); w = None
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(host, port, local_addr=(SRC, 0)), 3)
                await asyncio.wait_for(one(r, w), 3)
                lat.append((time.perf_counter() - t0) * 1000)
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                err[0] += 1
            finally:
                if w:
                    w.close()

    async def main():
        stop = time.time() + secs
        await asyncio.gather(*[worker(stop) for _ in range(conc)])
    raise_nofile(); t0 = time.time(); asyncio.run(main()); el = time.time() - t0
    if not lat:
        return "ERROR", f"no connection completed ({err[0]} errors)"
    return "MEASURE", (f"{len(lat) / el:.0f} new connections/s sustained for {el:.0f} s ({len(lat)} OK, {err[0]} errors, concurrency {conc}); "
                       f"request time p50 {pct(lat, 50):.1f} ms, p95 {pct(lat, 95):.1f} ms, p99 {pct(lat, 99):.1f} ms")


def t_dl_bench(c, cfg):
    """Aggregate throughput of P parallel downloads of a large file (HTTP, inspected HTTPS or not decrypted HTTPS)."""
    url, args, par, secs = subst(c["url"], cfg), subst(c.get("args", []), cfg), int(c.get("parallel", 4)), int(c.get("seconds", 30))
    stop, tot, n, errs, t0 = time.time() + secs, 0, 0, 0, time.time()
    while time.time() < stop:
        ps = [subprocess.Popen(["curl", "-s", "-k", "-o", "/dev/null", "-w", "%{size_download} %{http_code}", "--max-time", str(secs + 30), "--interface", SRC] + args + [url],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) for _ in range(par)]
        for p in ps:
            out = (p.communicate()[0] or "0 000").split()
            if out[-1].startswith("2"):
                tot += int(float(out[0])); n += 1
            else:
                errs += 1
    el = time.time() - t0
    if not n:
        return "ERROR", f"no download completed ({errs} errors)"
    return "MEASURE", f"{tot * 8 / el / 1e6:.0f} Mbit/s aggregate ({par} parallel downloads, {n} files of {tot / n / 1e6:.0f} MB in {el:.0f} s, {errs} errors)"


# ------------------------------------------------------------------ tasks requested by the control agent (HA-*, OBS-*, IPS-10…)
def _quick(t, cfg):
    """One fast probe for the continuous probes (2 s timeout). True = the flow went through."""
    if t["type"] == "tcp":
        s = socket.socket(); s.settimeout(2); s.bind((SRC, 0))
        try:
            s.connect((subst(t["host"], cfg), int(t["port"]))); return True
        except ConnectionRefusedError:
            return True
        except OSError:
            return False
        finally:
            s.close()
    if t["type"] == "http":
        rc, out, _ = sh(["curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "2", "--interface", SRC] + subst(t.get("args", []), cfg) + [subst(t["url"], cfg)], 5)
        return rc == 0 and not out.startswith("000")
    rc, _, _ = sh(["ping", "-I", SRC, "-c", "1", "-W", "1", subst(t["host"], cfg)], 4)
    return rc == 0


def task_probe(p, cfg, stopped):
    """Continuous probes (one per target and second) until 'duration' or until the control agent stops them."""
    import threading
    targets, iv, end = p["targets"], float(p.get("interval", 1)), time.time() + float(p.get("duration", 600))
    res = {t["name"]: [] for t in targets}

    def loop(t):
        while time.time() < end and not stop_flag[0]:
            t0 = time.time(); res[t["name"]].append([round(t0, 1), _quick(t, cfg)])
            time.sleep(max(0, iv - (time.time() - t0)))
    stop_flag = [False]
    th = [threading.Thread(target=loop, args=(t,), daemon=True) for t in targets]
    [x.start() for x in th]
    while time.time() < end and any(x.is_alive() for x in th):
        time.sleep(3)
        if stopped():
            stop_flag[0] = True
    [x.join(10) for x in th]
    return dict(samples=res)


def task_sessions(p, cfg, stopped):
    """N long-lived HTTP keep-alive sessions; each one sends a request every 'interval' s. Records when each one breaks."""
    raise_nofile()
    host, port, n, iv, end = subst(p.get("host", "{SERVER}"), cfg), int(p.get("port", 80)), int(p.get("n", 20)), float(p.get("interval", 2)), time.time() + float(p.get("duration", 600))
    ss, broken = [], {}
    for i in range(n):
        s = socket.socket(); s.settimeout(3); s.bind((SRC, 0))
        try:
            s.connect((host, port)); ss.append(s)
        except OSError:
            broken[i] = round(time.time(), 1); ss.append(None)
    t_open = round(time.time(), 1); k = 0
    while time.time() < end and len(broken) < n:
        for i, s in enumerate(ss):
            if i in broken:
                continue
            try:
                _http_req(s, k)
            except OSError:
                broken[i] = round(time.time(), 1)
        k += 1; time.sleep(iv)
        if k % 3 == 0 and stopped():
            break
    for s in ss:
        if s:
            s.close()
    return dict(n=n, opened=t_open, ended=round(time.time(), 1), broken={str(i): t for i, t in broken.items()})


def run_task(task, cfg, stopped):
    kind, p = task["kind"], task.get("params", {})
    if kind == "probe":
        return task_probe(p, cfg, stopped)
    if kind == "sessions":
        return task_sessions(p, cfg, stopped)
    if kind == "checks":   # catalog-style checks (traffic generation for logs, IoC, load…)
        out = []
        for c in p["checks"]:
            r = run_check(dict(c, id=c.get("id", "task"), name=c.get("name", c["type"]), expect=c.get("expect", "MEASURE")), cfg); out.append(r)
        return dict(results=out)
    raise ValueError(f"unknown task {kind}")


SEG_SERVICES = [["icmp", None], ["http", 80], ["https", 443], ["ssh", 22], ["rdp", 3389], ["tcp8080", 8080], ["iperf3", 5201]]


def expand_segmatrix(c, cfg):
    m = cfg["segmentation"]; envs = list(cfg["envs"])
    if c.get("scope") == "prod_nonprod":
        envs = role_envs(cfg, "prod_envs") + role_envs(cfg, "nonprod_envs")
    if ENV not in envs:
        return []
    out = []
    for d in envs:
        if d == ENV or d not in cfg["envs"]:
            continue
        allowed = set(m.get("allow", {}).get(f"{ENV}>{d}", [])) | set(m.get("always", []))
        for svc, port in SEG_SERVICES:
            sub = dict(id=f"{c['id']}.{ENV}-{d}-{svc}", name=f"{ENV.upper()} → {d.upper()} {svc}", blade="Firewall",
                       expect="ALLOW" if svc in allowed else "BLOCK", explain=c["explain"], host=cfg["envs"][d])
            sub.update(type="icmp") if port is None else sub.update(type="tcp", port=port)
            out.append(sub)
    return out


TYPES = dict(http=t_http, tcp=t_tcp, icmp=t_icmp, dns=t_dns, ntp=t_ntp, quic=t_quic, egress_ip=t_egress_ip, tls_issuer=t_tls_issuer,
             tls_verify=t_tls_verify, echo_ip=t_echo_ip, segmented=t_segmented, tcp_hold=t_tcp_hold, nmap=t_nmap, pmtu=t_pmtu,
             banner=t_banner, dns_fail=t_dns_fail, https_bench=t_https_bench, iperf=t_iperf, latency=t_latency, concurrent=t_concurrent,
             cps=t_cps, dl_bench=t_dl_bench)


def applicable(c, cfg):
    for k in c.get("needs", []):
        if k == "peer":
            if not cfg["envs"].get(cfg["peers"].get(ENV, "")):
                return "not configured: no cross-AZ peer for this environment"
            continue
        sect, key = k.split(".", 1)
        if not cfg.get(sect, {}).get(key):
            return f"not configured: {k}"
    if c.get("roles") and not any(ENV in role_envs(cfg, r) for r in c["roles"]):
        return f"only from: {', '.join(e.upper() for r in c['roles'] for e in role_envs(cfg, r)) or '-'}"
    if c.get("skip_roles") and any(ENV in role_envs(cfg, r) for r in c["skip_roles"]):
        return f"not from {ENV.upper()} (policy exception for this environment)"
    if c.get("skip_if_server") and (ENV == cfg["server_env"] or SRC == cfg["server"]):
        return "client in the same environment as the server (does not cross the firewall)"
    return None


def run_check(c, cfg):
    t0 = time.time(); r = dict(id=c["id"], name=tr(c["name"]), type=c["type"], expect=c["expect"], blade=c.get("blade", ""),
                               informative=bool(c.get("informative")), env=ENV, src=SRC, start=now())
    why = applicable(c, cfg)
    if why:
        r.update(observed="-", status="SKIP", detail=why)
    else:
        try:
            obs, det = TYPES[c["type"]](c, cfg)
        except Exception as e:  # noqa
            obs, det = "ERROR", f"{e.__class__.__name__}: {e}"
        r.update(observed=obs, detail=det)
        if obs == "SKIP":
            r["status"] = "SKIP"
        elif c["expect"] == "MEASURE":
            r["status"] = "INFO" if obs == "MEASURE" else "FAIL"
        elif obs == "ERROR":
            r["status"] = "ERROR"
        else:
            r["status"] = "OK" if obs == c["expect"] else ("INFO" if c.get("informative") else "FAIL")
    r["seconds"] = round(time.time() - t0, 2)
    return r


def plan(catalog, ids, cfg, runner="client"):
    """Checks of the selection that this kind of agent runs: 'client' (traffic from a workload) or 'control' (operator side)."""
    sel = []
    for case in catalog["cases"]:
        for c in case.get("checks", []):
            if ids and not any(c["id"] == i or case["id"] == i or c["id"].startswith(i + ".") for i in ids):
                continue
            if c.get("runner", "client") != runner:
                continue
            c = dict(c, case=case["id"])
            if c["type"] == "segmatrix":
                sel += [dict(s_, case=case["id"]) for s_ in expand_segmatrix(c, cfg)]
            else:
                sel.append(c)
    return sel


def load_catalog():
    return json.load(open(CATALOG, encoding="utf-8"))


def cli_run(ids):
    cat = load_catalog(); cfg = load_cfg(); G, R, Y, N = "\033[32m", "\033[31m", "\033[33m", "\033[0m"
    print(f"Firewall testkit · client {ENV.upper()} ({SRC}) → server {cfg['server'] or '?'}")
    tot = {}
    for c in plan(cat, ids, cfg):
        r = run_check(c, cfg); tot[r["status"]] = tot.get(r["status"], 0) + 1
        col = {"OK": G, "FAIL": R, "ERROR": R}.get(r["status"], Y)
        print(f"  {r['id']:<26} {tr(c['name'])[:50]:<50} esp={r['expect']:<13} obs={r['observed']:<13} {col}{r['status']}{N}  {r['detail'][:90]}")
    print("Summary:", tot)


def agent():
    url = os.environ.get("PORTAL_URL", f"http://{os.environ.get('SERVER_IP')}/portal").rstrip("/")
    name = os.environ.get("AGENT_NAME", ENV); cat = load_catalog()
    print(f"agent {name} ({ENV}, {SRC}) → {url}", flush=True)

    def call(path, payload=None):
        # Everything sent to the portal is zlib+base64: attack payloads inside results must not trigger the IPS
        data = None if payload is None else base64.b64encode(zlib.compress(json.dumps(payload).encode()))
        req = urllib.request.Request(url + path, data=data, headers={"Content-Type": "application/octet-stream"})
        with urllib.request.urlopen(req, timeout=40) as r:
            raw = r.read()
        return json.loads(zlib.decompress(base64.b64decode(raw))) if raw else {}

    while True:
        try:
            job = call(f"/api/agent/poll?agent={name}&env={ENV}&src={SRC}", dict(agent=name, env=ENV, src=SRC))
            if job.get("task_id"):   # tasks run in parallel (e.g. continuous probes + long sessions during a failover)
                import threading

                def do_task(job=job):
                    tid = job["task_id"]; cfg = norm_cfg(job.get("config") or {})

                    def stopped():
                        try:
                            return bool(call("/api/agent/task_state", dict(task_id=tid, agent=name)).get("stop"))
                        except Exception:  # noqa  (portal unreachable during a failover: keep going)
                            return False
                    try:
                        res = dict(ok=True, result=run_task(job["task"], cfg, stopped))
                    except Exception as e:  # noqa
                        res = dict(ok=False, error=f"{e.__class__.__name__}: {e}")
                    for _ in range(60):
                        try:
                            call("/api/agent/task_result", dict(task_id=tid, agent=name, **res)); break
                        except Exception:  # noqa
                            time.sleep(10)
                threading.Thread(target=do_task, daemon=True).start()
                continue
            if not job.get("run_id"):
                continue
            cfg = norm_cfg(job.get("config") or {}); install_inspection_ca(cfg["inspection_ca_pem"])
            checks = plan(cat, job.get("ids") or [], cfg)
            call("/api/agent/start", dict(run_id=job["run_id"], agent=name, total=len(checks), env=ENV, src=SRC))
            for c in checks:
                r = run_check(c, cfg); r["case"] = c["case"]
                call("/api/agent/result", dict(run_id=job["run_id"], agent=name, result=r))
            call("/api/agent/done", dict(run_id=job["run_id"], agent=name))
        except Exception as e:  # noqa
            print("agent:", e, flush=True); time.sleep(5)


if __name__ == "__main__":
    a = sys.argv[1:] or ["run"]
    if a[0] == "list":
        for case in load_catalog()["cases"]:
            print(f"{case['id']:<8} {tr(case['title'])}")
            for c in case.get("checks", []):
                print(f"   {c['id']:<10} {tr(c['name'])}")
    elif a[0] == "run":
        cli_run(a[1:])
    elif a[0] == "agent":
        agent()
