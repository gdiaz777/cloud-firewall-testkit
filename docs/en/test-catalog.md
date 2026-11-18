# Test catalog

_Español: [catalogo-pruebas.md](../es/catalogo-pruebas.md)_

Generated from `catalog/tests.json`. Every case lists its objective, how Check Point Cloud Firewall handles it, the policy prerequisites and the automated checks.

## Summary

| Domain | Cases | Checks |
|---|---:|---:|
| [NET · Architecture and routing](#net) | 5 | 16 |
| [POL · Policy and segmentation](#pol) | 8 | 20 |
| [IPS · Intrusion prevention](#ips) | 9 | 40 |
| [THR · Malware and threats](#thr) | 4 | 27 |
| [TLS · TLS inspection](#tls) | 10 | 38 |
| [APP · L7 control and anomalies](#app) | 5 | 28 |
| [DLP · Data loss prevention](#dlp) | 3 | 13 |
| [WAF · Complementary web protection](#waf) | 1 | 4 |

<a id="net"></a>
## NET · Architecture and routing

### NET-01 · East-west inspection between VPCs

**Priority:** Critical  
**Objective:** Traffic between environments crosses the firewall in both directions and is allowed or denied according to the matrix.  
**How Check Point Cloud Firewall handles it:** Traffic between VPCs goes through the Transit Gateway to the inspection VPC (GWLBe) and the Gateway Load Balancer hands it to Check Point Cloud Firewall. Every decision is logged with the rule that made it.  
**Policy prerequisites:** Rule allowing ICMP, HTTP and HTTPS to the server environment and denying everything else.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| NET-01.1 | ICMP echo to the server | Ping from the workload IP. | Allowed | Firewall |
| NET-01.2 | HTTP tcp/80 to the server | Published service. | Allowed | Firewall |
| NET-01.3 | HTTPS tcp/443 to the server | Published and inspected service. | Allowed | Firewall |
| NET-01.4 | SSH tcp/22 to the server | The server listens, but the policy does not allow it. | Blocked | Firewall |
| NET-01.5 | Telnet tcp/23 to the server | Insecure protocol with a listening service. | Blocked | Firewall |
| NET-01.6 | tcp/8080 to the server | Unauthorized alternate HTTP. | Blocked | Firewall |
| NET-01.7 | RDP tcp/3389 to the server | Unauthorized remote administration. | Blocked | Firewall |

### NET-03 · North-south egress to the Internet

**Priority:** Critical  
**Objective:** Internet egress is inspected centrally; only the expected traffic passes.  
**How Check Point Cloud Firewall handles it:** Centralized egress (spoke → TGW → inspection → egress VPC with NAT Gateway). On the firewall an inline layer allows HTTP/HTTPS (protocol signature) and DNS and denies the rest.  
**Policy prerequisites:** Egress layer allowing only HTTP, HTTPS and DNS.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| NET-03.1 | HTTP to the Internet | Control: legitimate traffic, must not be blocked. | Allowed | Firewall |
| NET-03.2 | HTTPS to the Internet | Control: legitimate traffic, must not be blocked. | Allowed | Firewall / HTTPSi |
| NET-03.3 | DNS UDP to a public resolver | Direct DNS query: allowed service. | Allowed | Firewall |
| NET-03.4 | SMTP tcp/25 to the Internet | Non-web port to the Internet. | Blocked | Firewall |
| NET-03.5 | NTP UDP/123 to the Internet | UDP other than DNS is not allowed. | Blocked | Firewall |
| NET-03.6 | Public egress IP | Shows the public egress IP (centralized NAT). | Allowed | Architecture |

### NET-05 · Stateful routing symmetry across AZs

**Priority:** Critical  
**Objective:** Both directions of a cross-AZ flow reach the same stateful context.  
**How Check Point Cloud Firewall handles it:** With the inspection attachment in appliance mode both directions use the same GWLBe and the GWLB delivers them to the same gateway; the session is not broken.  
**Policy prerequisites:** Environment pairs in different AZs (configuration) with HTTP allowed between them.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| NET-05.1 | 20 s TCP session with the cross-AZ peer | Persistent HTTP connection with 10 requests in 20 s: with asymmetry the firewall would drop the return traffic. | Allowed | Architecture |

### NET-07 · Production vs non-production segmentation

**Priority:** Critical  
**Objective:** No traffic between production and non-production except approved exceptions.  
**How Check Point Cloud Firewall handles it:** Environments are defined by CIDR and explicit rules block production ↔ non-production in both directions.  
**Policy prerequisites:** prod_envs and nonprod_envs roles and the segmentation matrix.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| NET-07.1 | Production ↔ non-production matrix | Configured segmentation matrix: from this environment to the others it tests ICMP, HTTP, HTTPS, SSH, RDP, tcp/8080 and iperf3 and compares with what is allowed. | Per matrix | Firewall |

### NET-13 · MTU, fragmentation and GENEVE

**Priority:** High  
**Objective:** No MTU black holes; the maximum usable size is measured.  
**How Check Point Cloud Firewall handles it:** GWLB encapsulates in GENEVE and supports an 8,500-byte MTU. The largest unfragmented packet is measured.  
**Policy prerequisites:** ICMP allowed to the server.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| NET-13.1 | Effective MTU to the server | DF ping from 1,472 to 8,472 bytes. Criterion: ≥ 1,472. | Measure | Architecture |

<a id="pol"></a>
## POL · Policy and segmentation

### POL-01 · Stateful allow/deny and default deny

**Priority:** Critical  
**Objective:** Only authorized 5-tuples pass; everything else is dropped and logged.  
**How Check Point Cloud Firewall handles it:** Stateful allow-list policy with a final cleanup rule (Drop + Log).  
**Policy prerequisites:** Allow-list to the server and cleanup rule.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| POL-01.1 | Authorized tcp/80 | Authorized 5-tuple. | Allowed | Firewall |
| POL-01.2 | Authorized tcp/443 | Authorized 5-tuple. | Allowed | Firewall |
| POL-01.3 | Unauthorized tcp/22 | Same source and destination, unauthorized port. | Blocked | Firewall |
| POL-01.4 | Unauthorized tcp/5202 | Port next to an exception. | Blocked | Firewall |

### POL-02 · Granular 5-tuple exceptions

**Priority:** Critical  
**Objective:** An exception opens only the given flow; neighbouring ports stay blocked.  
**How Check Point Cloud Firewall handles it:** Exception rule for a single port (iperf3 tcp/5201 by default) between environments.  
**Policy prerequisites:** Rule allowing only the configured exception port.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| POL-02.1 | Excepted port | Excepted flow. | Allowed | Firewall |
| POL-02.2 | Lower neighbouring port | Must not be open. | Blocked | Firewall |
| POL-02.3 | Upper neighbouring port | Must not be open. | Blocked | Firewall |

### POL-05 · FQDN rules

**Priority:** Critical  
**Objective:** The decision is made by domain, not by IP.  
**How Check Point Cloud Firewall handles it:** URL Filtering custom site: decided by Host (HTTP) and SNI/certificate (HTTPS). By default www.example.org (blocked) and www.example.com (allowed) share the same IP.  
**Policy prerequisites:** Custom site with the configured blocked FQDN.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| POL-05.1 | Allowed FQDN | Control: legitimate traffic, must not be blocked. | Allowed | URL Filtering |
| POL-05.2 | Blocked FQDN (HTTP) | Same hosting and IP: blocked only if the decision is by name. | Blocked | URL Filtering |
| POL-05.3 | Blocked FQDN (HTTPS) | Over HTTPS the decision uses SNI/certificate. | Blocked | URL Filtering / HTTPSi |

### POL-07 · DNS failures

**Priority:** Critical  
**Objective:** A resolution failure never opens connectivity.  
**How Check Point Cloud Firewall handles it:** Without resolution there is no flow and the policy stays default-deny.  
**Policy prerequisites:** None.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| POL-07.1 | Non-existent name (NXDOMAIN) | curl to a .invalid name. | No flow | Firewall |

### POL-10 · Rule precedence

**Priority:** Critical  
**Objective:** Evaluation order is deterministic and the matching rule is logged.  
**How Check Point Cloud Firewall handles it:** The rulebase is evaluated top-down: an exception rule above the segmentation rule wins for its service; the rest is decided by segmentation.  
**Policy prerequisites:** precedence_clients and precedence_target roles, and the exception rule above the blocking rule.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| POL-10.1 | Excepted service to the blocked target (only from role `precedence_clients`) | The exception rule is above the blocking rule. | Allowed | Firewall |
| POL-10.2 | HTTP to the blocked target (only from role `precedence_clients`) | No earlier rule allows it, so the blocking rule decides. | Blocked | Firewall |

### POL-11 · Micro-segmentation by service and environment

**Priority:** Critical  
**Objective:** No lateral movement outside the approved matrix.  
**How Check Point Cloud Firewall handles it:** The full matrix is run from every environment (batch over all clients).  
**Policy prerequisites:** Segmentation matrix in the configuration.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| POL-11.1 | Full environment matrix | Configured segmentation matrix: from this environment to the others it tests ICMP, HTTP, HTTPS, SSH, RDP, tcp/8080 and iperf3 and compares with what is allowed. | Per matrix | Firewall |

### POL-12 · Combined profiles

**Priority:** High  
**Objective:** Several controls on the same flow, each one traceable.  
**How Check Point Cloud Firewall handles it:** Internet egress combines Firewall, App Control, URL Filtering, IPS, Anti-Bot and Anti-Virus; the log shows which blade acted.  
**Policy prerequisites:** Full profile on the egress rule and HTTPS Inspection.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| POL-12.1 | EICAR from the Internet over HTTPS | Anti-Virus on decrypted HTTPS. | Blocked | Anti-Virus / HTTPSi |
| POL-12.2 | Anti-Bot test page | C&C reputation. | Blocked | Anti-Bot |
| POL-12.3 | Gambling category | URL Filtering by category. | Blocked | URL Filtering |
| POL-12.4 | Legitimate site | Control: legitimate traffic, must not be blocked. | Allowed | All |

### POL-15 · Detect vs prevent mode

**Priority:** High  
**Objective:** The same stimulus is only detected on one target and blocked on another.  
**How Check Point Cloud Firewall handles it:** Threat Prevention rule with a Detect profile towards the ids_target environment and a Prevent profile towards the server.  
**Policy prerequisites:** ids_target and ids_clients roles; TP rule with a Detect profile to ids_target; HTTP allowed from ids_clients.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| POL-15.1 | SQLi to the Detect target (only from role `ids_clients`) | Reaches the server and is logged as Detect. | Allowed | IPS |
| POL-15.2 | SQLi to the Prevent server (only from role `ids_clients`) | Blocked and logged as Prevent. | Blocked | IPS |

<a id="ips"></a>
## IPS · Intrusion prevention

### IPS-01 · Known attack prevention

**Priority:** Critical  
**Objective:** Signatures detect and block; the log includes protection, severity and action.  
**How Check Point Cloud Firewall handles it:** IPS in Prevent for all east-west and Internet traffic.  
**Policy prerequisites:** Threat Prevention profile with IPS in Prevent on the east-west rule.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| IPS-01.1 | Clean request (control) | Control: legitimate traffic, must not be blocked. | Allowed | IPS |
| IPS-01.2 | SQL injection (UNION SELECT) | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-01.3 | Cross-site scripting | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-01.4 | Path traversal | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-01.5 | Path traversal in parameter | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-01.6 | Shellshock (User-Agent) | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-01.7 | Log4Shell (JNDI header) | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-01.8 | Command injection | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |

### IPS-02 · Scanning and reconnaissance

**Priority:** High  
**Objective:** A scan only sees authorized services.  
**How Check Point Cloud Firewall handles it:** The firewall drops unauthorized ports even if the server listens; attempts are logged.  
**Policy prerequisites:** Only 80, 443 and the exception port allowed to the server.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| IPS-02.1 | Port scan of the server | nmap over 1-1024, 3389, 5201 and 8080: only authorized ports must be visible. | Authorized only | Firewall / IPS |

### IPS-04 · Per-asset signature exception

**Priority:** Critical  
**Objective:** Only the authorized combination is excepted; everything else stays protected.  
**How Check Point Cloud Firewall handles it:** Threat Prevention exception with a single protection (TP-Link Archer AX21, CVE-2023-1389), source ips_exception_client and the server as destination, in Detect.  
**Policy prerequisites:** Exception on the east-west rule: protection 'TP-Link Archer AX21 Command Injection (CVE-2023-1389)', source = ips_exception_client environment, action Detect.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| IPS-04.1 | CVE-2023-1389 from the excepted asset (only from role `ips_exception_client`) | In scope: Detect. | Allowed | IPS |
| IPS-04.2 | CVE-2023-1389 from another asset | Out of scope: still blocked. | Blocked | IPS |
| IPS-04.3 | Another protection from the excepted asset (only from role `ips_exception_client`) | All other protections stay active. | Blocked | IPS |

### IPS-05 · False positives

**Priority:** High  
**Objective:** Legitimate traffic resembling signatures is not blocked.  
**How Check Point Cloud Firewall handles it:** Profiles by confidence and impact; fine tuning uses per-asset exceptions without disabling detections globally.  
**Policy prerequisites:** None.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| IPS-05.1 | Text with 'select' and 'union' | Control: legitimate traffic, must not be blocked. | Allowed | IPS |
| IPS-05.2 | Surname with apostrophe | Control: legitimate traffic, must not be blocked. | Allowed | IPS |
| IPS-05.3 | Filter with comparators | Control: legitimate traffic, must not be blocked. | Allowed | IPS |
| IPS-05.4 | JSON with legitimate HTML | Control: legitimate traffic, must not be blocked. | Allowed | IPS |
| IPS-05.5 | Legitimate shell script | Control: legitimate traffic, must not be blocked. | Allowed | IPS / AV |

### IPS-06 · Virtual patching of published CVEs

**Priority:** High  
**Objective:** Exploitation patterns are blocked without touching the server.  
**How Check Point Cloud Firewall handles it:** IPS blocks exploitation of known CVEs; the test server is not vulnerable, it only receives the pattern.  
**Policy prerequisites:** IPS in Prevent.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| IPS-06.1 | CVE-2021-41773 Apache path traversal | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-06.2 | CVE-2022-22965 Spring4Shell | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-06.3 | CVE-2022-26134 Confluence OGNL | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-06.4 | CVE-2017-9841 PHPUnit eval-stdin | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-06.5 | CVE-2019-19781 Citrix ADC traversal | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-06.6 | CVE-2022-1388 F5 BIG-IP iControl | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-06.7 | CVE-2021-44228 Log4Shell User-Agent | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |

### IPS-07 · Evasions and fragmentation

**Priority:** High  
**Objective:** Obfuscated and segmented variants are detected like the original attack.  
**How Check Point Cloud Firewall handles it:** IPS reassembles the TCP stream and normalizes encoding before pattern matching.  
**Policy prerequisites:** IPS in Prevent.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| IPS-07.1 | SQLi mixed case | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-07.2 | SQLi with inline comments | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-07.3 | SQLi UNION in POST body | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-07.4 | Double-encoded traversal | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-07.5 | XSS in Referer header | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-07.6 | Obfuscated Log4Shell | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| IPS-07.7 | SQLi split into 4-byte TCP segments | IPS must reassemble the stream before inspecting. | Blocked | IPS |
| IPS-07.8 | Control: clean segmented request | Control: legitimate traffic, must not be blocked. | Allowed | IPS |

### IPS-08 · Geo-blocking

**Priority:** High  
**Objective:** Destinations in blocked countries are dropped.  
**How Check Point Cloud Firewall handles it:** GEO updatable objects in the egress layer.  
**Policy prerequisites:** Egress rule with the blocked countries and a test URL in one of them (config.internet.geo_blocked_url).

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| IPS-08.1 | Destination in a blocked country | Destination IP in a blocked country. | Blocked | Firewall (GEO) |
| IPS-08.2 | Destination in an allowed country | Control: legitimate traffic, must not be blocked. | Allowed | Firewall (GEO) |

### IPS-09 · C&C and botnets

**Priority:** High  
**Objective:** Traffic to C&C indicators is blocked.  
**How Check Point Cloud Firewall handles it:** Anti-Bot blocks by domain, IP and URL reputation (ThreatCloud) and by communication patterns.  
**Policy prerequisites:** Anti-Bot in the egress profile.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| IPS-09.1 | Check Point Anti-Bot test page | Test URL classified as C&C. | Blocked | Anti-Bot |
| IPS-09.2 | Control: www.checkpoint.com | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Bot |

### IPS-11 · IDS vs IPS differentiated policy

**Priority:** High  
**Objective:** Detect mode does not block; prevent mode does; both log.  
**How Check Point Cloud Firewall handles it:** Same stimulus against the Detect target (ids_target) and the Prevent server.  
**Policy prerequisites:** Same as POL-15.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| IPS-11.1 | XSS to the IDS target (only from role `ids_clients`) | Detect profile. | Allowed | IPS |
| IPS-11.2 | XSS to the IPS server (only from role `ids_clients`) | Prevent profile. | Blocked | IPS |
| IPS-11.3 | Log4Shell to the IDS target (only from role `ids_clients`) | Detect profile. | Allowed | IPS |
| IPS-11.4 | Log4Shell to the IPS server (only from role `ids_clients`) | Prevent profile. | Blocked | IPS |

<a id="thr"></a>
## THR · Malware and threats

### THR-01 · Anti-malware over HTTP

**Priority:** High  
**Objective:** The EICAR test file is detected and blocked.  
**How Check Point Cloud Firewall handles it:** Anti-Virus (signatures + ThreatCloud) over HTTP/HTTPS including nested archives and uploads.  
**Policy prerequisites:** Anti-Virus inspecting both directions and archives.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| THR-01.1 | EICAR (.com) | Download from the server; Anti-Virus inspects files in both directions and inside archives. | Blocked | Anti-Virus |
| THR-01.2 | EICAR (.txt) | Download from the server; Anti-Virus inspects files in both directions and inside archives. | Blocked | Anti-Virus |
| THR-01.3 | EICAR in zip | Download from the server; Anti-Virus inspects files in both directions and inside archives. | Blocked | Anti-Virus |
| THR-01.4 | EICAR in nested zip | Download from the server; Anti-Virus inspects files in both directions and inside archives. | Blocked | Anti-Virus |
| THR-01.5 | EICAR upload in request body (POST) | API-style upload: the file travels in the request body. | Blocked | IPS / Anti-Virus |
| THR-01.6 | Benign zip (control) | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Virus |

### THR-02 · Anti-malware over HTTPS with and without decryption

**Priority:** High  
**Objective:** Quantifies what TLS inspection adds.  
**How Check Point Cloud Firewall handles it:** Same EICAR over HTTPS to the same server with two names: inspect.testkit.lab (decrypted) and nodecrypt.testkit.lab (bypassed).  
**Policy prerequisites:** HTTPS Inspection with bypass for nodecrypt.testkit.lab and mtls.testkit.lab.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| THR-02.1 | EICAR over HTTP | Download from the server; Anti-Virus inspects files in both directions and inside archives. | Blocked | Anti-Virus |
| THR-02.2 | EICAR over decrypted HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | Anti-Virus / HTTPSi |
| THR-02.3 | EICAR over non-decrypted HTTPS | Without decryption there is no content visibility (expected result). | Allowed | HTTPSi (bypass) |
| THR-02.4 | EICAR from the Internet over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | Anti-Virus / HTTPSi |

### THR-03 · Benign files without false positives

**Priority:** High  
**Objective:** Clean files of several formats and sizes are not blocked.  
**How Check Point Cloud Firewall handles it:** Downloads over HTTP and HTTPS.  
**Policy prerequisites:** None.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| THR-03.1 | benign.pdf over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Virus |
| THR-03.2 | benign.pdf over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Virus |
| THR-03.3 | benign.docx over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Virus |
| THR-03.4 | benign.docx over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Virus |
| THR-03.5 | benign.xlsx over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Virus |
| THR-03.6 | benign.xlsx over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Virus |
| THR-03.7 | benign.png over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Virus |
| THR-03.8 | benign.png over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Virus |
| THR-03.9 | benign.json over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Virus |
| THR-03.10 | benign.json over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Virus |
| THR-03.11 | benign.csv over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Virus |
| THR-03.12 | benign.csv over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Virus |
| THR-03.13 | benign_10m.bin over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Virus |
| THR-03.14 | benign_10m.bin over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | Anti-Virus |

### THR-05 · Combined AV, Anti-Bot and IPS

**Priority:** High  
**Objective:** Combined controls do not cancel each other and show who acted.  
**How Check Point Cloud Firewall handles it:** Several blades in the same profile.  
**Policy prerequisites:** Full profile and HTTPS Inspection.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| THR-05.1 | EICAR zip over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | Anti-Virus / HTTPSi |
| THR-05.2 | SQLi over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | IPS / HTTPSi |
| THR-05.3 | C&C over HTTP | Anti-Bot. | Blocked | Anti-Bot |

<a id="tls"></a>
## TLS · TLS inspection

### TLS-01 · TLS 1.2 and 1.3 inspection

**Priority:** Critical  
**Objective:** Documents which versions are inspected and blocks patterns inside them.  
**How Check Point Cloud Firewall handles it:** HTTPS Inspection inspects TLS 1.2 and 1.3 re-signing with the inspection CA.  
**Policy prerequisites:** Outbound HTTPS Inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| TLS-01.1 | TLS 1.2 decrypted | The received certificate is issued by the inspection CA. | Decrypted | HTTPSi |
| TLS-01.2 | TLS 1.3 decrypted | Same with TLS 1.3. | Decrypted | HTTPSi |
| TLS-01.3 | SQLi over TLS 1.2 | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | IPS / HTTPSi |
| TLS-01.4 | SQLi over TLS 1.3 | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | IPS / HTTPSi |
| TLS-01.5 | Clean request over TLS 1.3 | Control: legitimate traffic, must not be blocked. | Allowed | HTTPSi |

### TLS-02 · Inspection CA and trust chain

**Priority:** High  
**Objective:** Only clients trusting the CA work; there is no hidden bypass.  
**How Check Point Cloud Firewall handles it:** The inspection CA is distributed to clients; a client without it gets a certificate error.  
**Policy prerequisites:** Outbound HTTPS Inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| TLS-02.1 | Certificate replaced on the Internet | The site arrives signed by the inspection CA. | Decrypted | HTTPSi |
| TLS-02.2 | Client with the inspection CA | Validates with the Check Point CA in its store. | Cert. valid | HTTPSi |
| TLS-02.3 | Client without the inspection CA | Public CAs only: fails. | Cert. rejected | HTTPSi |

### TLS-03 · Expired, revoked or untrusted certificates

**Priority:** High  
**Objective:** The response matches the validation policy and is logged.  
**How Check Point Cloud Firewall handles it:** HTTPS Inspection validates the original certificate and blocks untrusted, expired and revoked ones.  
**Policy prerequisites:** HTTPS advanced settings: block untrusted, expired and revoked.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| TLS-03.1 | Expired certificate | Server certificate validation. | Blocked | HTTPSi |
| TLS-03.2 | Self-signed certificate | Untrusted CA. | Blocked | HTTPSi |
| TLS-03.3 | Untrusted root | Chain to an unknown root. | Blocked | HTTPSi |
| TLS-03.4 | Revoked certificate | Revoked. | Blocked | HTTPSi |
| TLS-03.5 | Control: valid certificate | Control: legitimate traffic, must not be blocked. | Allowed | HTTPSi |

### TLS-04 · mTLS and certificate pinning

**Priority:** High  
**Objective:** Incompatibilities are solved with a minimal bypass.  
**How Check Point Cloud Firewall handles it:** mTLS and pinning do not accept a man-in-the-middle: only those FQDNs are bypassed.  
**Policy prerequisites:** Outbound HTTPS Inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| TLS-04.1 | mTLS with client certificate (bypassed) | The server requires a client certificate. | Allowed | HTTPSi (bypass) |
| TLS-04.2 | CA pinning (bypassed) | Client trusting only the service CA. | Cert. valid | HTTPSi (bypass) |
| TLS-04.3 | CA pinning (inspected) | Against the inspected FQDN it fails: pinning needs a bypass. | Cert. rejected | HTTPSi |

### TLS-05 · Decryption bypass by FQDN and category

**Priority:** Critical  
**Objective:** Only the approved scope is not decrypted.  
**How Check Point Cloud Firewall handles it:** Bypass by FQDN, sensitive categories (finance, health, government) and the Check Point recommended list.  
**Policy prerequisites:** Outbound HTTPS Inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| TLS-05.1 | Bypassed FQDN | Not decrypted. | Not decrypted | HTTPSi |
| TLS-05.2 | Inspected FQDN | Decrypted. | Decrypted | HTTPSi |
| TLS-05.3 | Banking (Financial category) | Sensitive category bypassed. | Not decrypted | HTTPSi |
| TLS-05.4 | General website | Decrypted. | Decrypted | HTTPSi |

### TLS-06 · HTTP/2, QUIC and ECH

**Priority:** High  
**Objective:** Effective visibility is known and there is no silent bypass.  
**How Check Point Cloud Firewall handles it:** HTTP/2 is inspected like HTTP/1.1; QUIC (UDP/443) is denied to force inspected TCP.  
**Policy prerequisites:** Outbound HTTPS Inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| TLS-06.1 | SQLi over HTTP/2 | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | IPS / HTTPSi |
| TLS-06.2 | EICAR over HTTP/2 | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | Anti-Virus / HTTPSi |
| TLS-06.3 | Clean request over HTTP/2 | Control: legitimate traffic, must not be blocked. | Allowed | HTTPSi |
| TLS-06.4 | QUIC (UDP/443) to the Internet | QUIC Initial packet: no answer. | Blocked | Firewall |

### TLS-07 · Transparent mode and observability

**Priority:** Medium  
**Objective:** The impact on the source IP is known.  
**How Check Point Cloud Firewall handles it:** Behind GWLB the firewall is transparent: it keeps the original IP and adds no proxy headers.  
**Policy prerequisites:** Outbound HTTPS Inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| TLS-07.1 | Source IP preserved (inspected HTTPS) | The server returns the IP and headers it sees. | IP preserved | HTTPSi |

### TLS-08 · TLS inspection overhead

**Priority:** Critical  
**Objective:** The real handshake and latency overhead is measured.  
**How Check Point Cloud Firewall handles it:** 100 new HTTPS connections with and without decryption to the same server; percentiles are compared.  
**Policy prerequisites:** Outbound HTTPS Inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| TLS-08.1 | HTTPS Inspection overhead | inspect.testkit.lab vs nodecrypt.testkit.lab. | Measure | HTTPSi |

### TLS-09 · Threats inside HTTPS (east-west)

**Priority:** High  
**Objective:** IPS and AV payloads inside HTTPS are blocked as in HTTP.  
**How Check Point Cloud Firewall handles it:** East-west HTTPS Inspection restores visibility for IPS, AV and DLP.  
**Policy prerequisites:** Outbound HTTPS Inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| TLS-09.1 | XSS over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | IPS / HTTPSi |
| TLS-09.2 | Path traversal over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | IPS / HTTPSi |
| TLS-09.3 | Log4Shell over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | IPS / HTTPSi |
| TLS-09.4 | Shellshock over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | IPS / HTTPSi |
| TLS-09.5 | EICAR over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | Anti-Virus / HTTPSi |
| TLS-09.6 | Clean request over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | HTTPSi |

### TLS-10 · Evasion and obfuscation over HTTPS

**Priority:** High  
**Objective:** No technique bypasses the controls.  
**How Check Point Cloud Firewall handles it:** With HTTPS Inspection the gateway sees the real Host, decompresses gzip, reassembles chunked/multipart and validates the protocol per port.  
**Policy prerequisites:** Outbound HTTPS Inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| TLS-10.1 | Domain fronting (allowed SNI, blocked Host) | With decryption the real Host is visible. | Blocked | App Control / HTTPSi |
| TLS-10.2 | EICAR with Content-Encoding gzip | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | Anti-Virus / HTTPSi |
| TLS-10.3 | EICAR multipart upload (HTTPS) | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | Anti-Virus / HTTPSi |
| TLS-10.4 | SQLi in chunked body (HTTP/1.1 over TLS) | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | IPS / HTTPSi |
| TLS-10.5 | HTTPS to non-standard port (8443) | TLS outside 443. | Blocked | Firewall |
| TLS-10.6 | Card data in JSON over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: HTTPS Inspection decrypts and the blades inspect the content. | Blocked | Content Awareness / HTTPSi |

<a id="app"></a>
## APP · L7 control and anomalies

### APP-01 · Port-independent application control

**Priority:** High  
**Objective:** The application is identified by protocol, not by port.  
**How Check Point Cloud Firewall handles it:** App Control identifies applications on any port and egress only allows HTTP/HTTPS with protocol signature.  
**Policy prerequisites:** HTTP/HTTPS services with 'match by protocol signature' and SSH blocked as an application.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| APP-01.1 | SSH tcp/22 to the Internet | Port and application not allowed. | Blocked | Firewall |
| APP-01.2 | SSH over tcp/443 | SSH over the HTTPS port (ssh.github.com). | Blocked | App Control |
| APP-01.3 | HTTP on tcp/8080 | Unauthorized port. | Blocked | Firewall |
| APP-01.4 | HTTP on tcp/8443 | Unauthorized port. | Blocked | Firewall |
| APP-01.5 | Cleartext HTTP on tcp/443 | Not TLS: does not match the HTTPS service with signature. | Blocked | Firewall |
| APP-01.6 | Control: HTTP on tcp/80 | Control: legitimate traffic, must not be blocked. | Allowed | Firewall |

### APP-02 · URL Filtering and App Control by category

**Priority:** High  
**Objective:** Category and action are logged.  
**How Check Point Cloud Firewall handles it:** URL Filtering by category and App Control by application, over HTTP and HTTPS.  
**Policy prerequisites:** Gambling and Anonymizer categories and Facebook, TikTok, Dropbox and WeTransfer applications blocked; LinkedIn allowed.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| APP-02.1 | Business site (allowed) | Control: legitimate traffic, must not be blocked. | Allowed | URL Filtering |
| APP-02.2 | bet365 (Gambling) over HTTP | Forbidden category. | Blocked | URL Filtering |
| APP-02.3 | pokerstars (Gambling) over HTTPS | Forbidden category. | Blocked | URL Filtering / HTTPSi |
| APP-02.4 | hidemyass (Anonymizer) | Anonymizer. | Blocked | URL Filtering |
| APP-02.5 | Facebook | Blocked application. | Blocked | App Control |
| APP-02.6 | TikTok | Blocked application. | Blocked | App Control |
| APP-02.7 | Dropbox | File sharing. | Blocked | App Control |
| APP-02.8 | WeTransfer | File sharing. | Blocked | App Control |
| APP-02.9 | LinkedIn (allowed) | Control: legitimate traffic, must not be blocked. | Allowed | App Control |

### APP-03 · Full URL vs domain/SNI

**Priority:** High  
**Objective:** Shows when the path is distinguished from the domain.  
**How Check Point Cloud Firewall handles it:** With HTTPS Inspection the full URL is visible and a path can be blocked; without decryption only the domain.  
**Policy prerequisites:** Custom site with the configured blocked path (config.internet.blocked_path).

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| APP-03.1 | Allowed path over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | URL Filtering |
| APP-03.2 | Blocked path over HTTP | Path matches. | Blocked | URL Filtering |
| APP-03.3 | Allowed path over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | URL Filtering / HTTPSi |
| APP-03.4 | Blocked path over HTTPS | Only possible with decryption. | Blocked | URL Filtering / HTTPSi |

### APP-04 · DNS-independent filtering

**Priority:** High  
**Objective:** Covered surface is known: direct IP, no SNI, DoH and DoT.  
**How Check Point Cloud Firewall handles it:** Identification by Host, SNI and certificate; DoH blocked as an application and DoT by port.  
**Policy prerequisites:** DoH application blocked; only DNS/HTTP/HTTPS on egress.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| APP-04.1 | Facebook by IP with Host header | No DNS query. | Blocked | App Control |
| APP-04.2 | Facebook by IP without SNI (HTTPS) | Classified by the certificate. | Blocked | App Control / HTTPSi |
| APP-04.3 | DNS over HTTPS | DoH application. | Blocked | App Control |
| APP-04.4 | DNS over TLS (tcp/853) | DoT on its standard port. | Blocked | Firewall |

### APP-07 · Unexpected outbound connections

**Priority:** High  
**Objective:** A server cannot open connections to unexpected destinations and ports.  
**How Check Point Cloud Firewall handles it:** Default-deny egress; every attempt is logged.  
**Policy prerequisites:** Egress layer with a Drop cleanup.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| APP-07.1 | SQL Server tcp/1433 to the Internet | Unexpected port to the Internet. | Blocked | Firewall |
| APP-07.2 | MySQL tcp/3306 to the Internet | Unexpected port to the Internet. | Blocked | Firewall |
| APP-07.3 | PostgreSQL tcp/5432 to the Internet | Unexpected port to the Internet. | Blocked | Firewall |
| APP-07.4 | SMTP tcp/25 to the Internet | Unexpected port to the Internet. | Blocked | Firewall |
| APP-07.5 | SMB tcp/445 to the Internet | Unexpected port to the Internet. | Blocked | Firewall |

<a id="dlp"></a>
## DLP · Data loss prevention

### DLP-01 · Sensitive data transfer

**Priority:** Medium  
**Objective:** Synthetic sensitive patterns are detected and blocked.  
**How Check Point Cloud Firewall handles it:** Content Awareness with PCI and IBAN data types and executable file type.  
**Policy prerequisites:** Content Awareness rules (PCI, IBAN, executables) between environments over HTTP and HTTPS.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| DLP-01.1 | Benign file upload | Control: legitimate traffic, must not be blocked. | Allowed | Content Awareness |
| DLP-01.2 | Card numbers upload (PCI) | Content Awareness inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | Content Awareness |
| DLP-01.3 | IBAN upload | Content Awareness inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | Content Awareness |
| DLP-01.4 | Card numbers download (PCI) | Content Awareness inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | Content Awareness |
| DLP-01.5 | Executable download | Executable file type. | Blocked | Content Awareness |

### DLP-02 · Minimal-scope DLP exceptions

**Priority:** Medium  
**Objective:** The exception applies only to the approved asset and direction.  
**How Check Point Cloud Firewall handles it:** Exception rule (upload only, from dlp_exception_client to the server) above the blocking rule.  
**Policy prerequisites:** dlp_exception_client role and exception rule with direction 'up'.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| DLP-02.1 | PCI upload from the excepted asset (only from role `dlp_exception_client`) | In scope. | Allowed | Content Awareness |
| DLP-02.2 | PCI upload from another asset | Same file and destination from another asset. | Blocked | Content Awareness |
| DLP-02.3 | PCI download to the excepted asset (only from role `dlp_exception_client`) | The exception only covers uploads. | Blocked | Content Awareness |

### DLP-03 · DLP on encrypted traffic and object sizes

**Priority:** Medium  
**Objective:** Limits by format, encryption and size are documented.  
**How Check Point Cloud Firewall handles it:** Content Awareness on decrypted HTTPS, large files and Office.  
**Policy prerequisites:** Content Awareness rules (PCI, IBAN, executables) between environments over HTTP and HTTPS.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| DLP-03.1 | PCI upload over HTTPS | Content Awareness inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | Content Awareness / HTTPSi |
| DLP-03.2 | PCI download over HTTPS | Content Awareness inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | Content Awareness / HTTPSi |
| DLP-03.3 | PCI at the end of a 2 MB file | Content Awareness inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | Content Awareness |
| DLP-03.4 | PCI inside a .docx | Content Awareness inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | Content Awareness |
| DLP-03.5 | Executable over HTTPS | Content Awareness inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | Content Awareness / HTTPSi |

<a id="waf"></a>
## WAF · Complementary web protection

### WAF-01 · SQLi and XSS (WAF coverage)

**Priority:** Medium  
**Objective:** Documents what the IPS covers and what needs a WAF.  
**How Check Point Cloud Firewall handles it:** IPS covers common web attack classes. Full application and API protection (including tautologies in forms and JSON) belongs to Check Point CloudGuard WAF.  
**Policy prerequisites:** IPS in Prevent.

| ID | Check | What it does | Expected | Blade |
|---|---|---|---|---|
| WAF-01.1 | SQLi in GET parameter | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| WAF-01.2 | Reflected XSS | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| WAF-01.3 | SQL tautology in POST form (informative) | WAF-specific class: informative. | Blocked | IPS → CloudGuard WAF |
| WAF-01.4 | SQL tautology in JSON (API) (informative) | WAF-specific class: informative. | Blocked | IPS → CloudGuard WAF |
