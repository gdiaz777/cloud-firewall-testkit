# Test catalog

_Español: [catalogo-pruebas.md](../es/catalogo-pruebas.md)_

Generated from `catalog/tests.json`. Every case lists its objective, the policy prerequisites, the automated checks and, separately, notes on how Check Point handles it (shown in the portal and reports only when the solution under test is Check Point).

## Summary

| Domain | Cases | Manual | Checks |
|---|---:|---:|---:|
| [NET · Architecture and routing](#net) | 13 | 7 | 17 |
| [POL · Policy and segmentation](#pol) | 16 | 6 | 22 |
| [IPS · Intrusion prevention](#ips) | 11 | 0 | 42 |
| [THR · Malware and threats](#thr) | 6 | 1 | 28 |
| [TLS · TLS inspection](#tls) | 10 | 0 | 38 |
| [APP · L7 control and anomalies](#app) | 8 | 3 | 28 |
| [DLP · Data loss prevention](#dlp) | 3 | 0 | 13 |
| [WAF · Complementary web protection](#waf) | 3 | 2 | 4 |
| [OBS · Visibility and audit](#obs) | 11 | 8 | 4 |
| [HA · Availability and resilience](#ha) | 8 | 3 | 5 |
| [PERF · Performance and capacity](#perf) | 8 | 0 | 19 |
| [OPS · Operations and governance](#ops) | 9 | 7 | 2 |
| [INT · Integrations](#int) | 6 | 6 | 0 |
| [COST · Cost and efficiency](#cost) | 5 | 5 | 0 |

## Firewall configuration for the tests

1. Architecture: all traffic between environments and to the Internet crosses the firewall (Transit Gateway with appliance mode on the inspection attachment and firewall load balancer endpoints). No alternative routes (NET-06).
2. Objects: one network object per environment (CIDR from the portal settings) and a group with all of them; one object with the internal range.
3. Segmentation: one Accept rule per source→destination pair of the matrix with its services, a logged Drop for the rest between environments and a logged Drop cleanup rule.
4. Exception port (5201 by default, TCP and UDP): allowed between all environments and excluded from threat prevention (POL-02 and performance measurements PERF-01/06/07).
5. Internet egress: only HTTP/HTTPS identified by protocol and DNS; application and URL control (risk categories, blocked FQDN and path from the settings), geo-blocking of the configured countries and anti-bot.
6. Threat prevention in Prevent: IPS, anti-malware (both directions and inside archives) and anti-bot; an east-west profile, an Internet profile and a Detect profile for the «ids_target» environment; one IPS exception for the «ips_exception_client» asset.
7. DLP: block card numbers, IBAN and executables between environments (HTTP and HTTPS), with an upload exception for the «dlp_exception_client» asset.
8. TLS inspection: outbound and east-west decryption with the inspection CA (its PEM is loaded in the portal); the kit CA as trusted CA; decryption bypass for the mTLS/pinning FQDN, the vendor list and sensitive categories (financial, health, government); server certificate validation.
9. Logging: every rule logs (threat rules with packet capture); time synchronized with NTP.
10. Control agent: Management API key (read, publish and install only on the test gateways; it creates temporary TK_ objects and removes them) and a cloud role to read the deployment and run the HA checks (Auto Scaling group, network ACLs, CloudWatch, IAM read).

### Check Point recommended baseline

- Threat profile based on «Optimized» (or «Strict» on Internet egress) in Prevent with IPS, Anti-Bot, Anti-Virus, Threat Emulation and Threat Extraction; new protections in Prevent by confidence and performance impact.
- Autonomous Threat Prevention or automatic IPS and ThreatCloud updates; check THR-06 after every new gateway.
- Outbound HTTPS Inspection with the corporate CA distributed by GPO/MDM, bypass of the «HTTPS services - recommended bypass» updatable object (sk163595) and sensitive categories; server certificate validation and block of invalid certificates.
- Layers organized in sections (exceptions, matrix, egress, cleanup), no Accept rules with «Any» as service or destination, logged Drop cleanup rule and dynamic/updatable objects instead of fixed IPs.
- Services with «match by protocol signature» for HTTP/HTTPS on egress (blocks tunnels over web ports).
- Geo Policy / country updatable objects on egress and published ingress.
- High availability: Auto Scaling group in at least 2 AZs with an n+1 minimum, GWLB with cross-zone enabled, appliance mode on the TGW and CME with template and policy assigned.
- Performance: c5/c6i/c7i instances sized with PERF-02 (real profile), SecureXL and CoreXL enabled (default) and Dynamic Balancing.
- Management: Smart-1 Cloud with SSO+MFA, one API key per automation, approval sessions for changes and policy as code (Terraform/API).
- Gateway hardening: IMDSv2, encrypted volumes, administrative access only from the management and authorized ranges, and cloud connector with a read-only STS role with ExternalId.
- Logs: Log Exporter to the SIEM, retention per regulation and Infinity Events/SmartEvent for correlation.

<a id="net"></a>
## NET · Architecture and routing

### NET-01 · East-west inspection between VPCs

**Priority:** Critical  
**Objective:** Traffic between environments crosses the firewall in both directions and is allowed or denied according to the matrix.  
**Firewall configuration needed:** Rule allowing ICMP, HTTP and HTTPS to the server environment and denying everything else.  
_Check Point notes: Traffic between VPCs goes through the Transit Gateway to the inspection VPC (GWLBe) and the Gateway Load Balancer hands it to Check Point Cloud Firewall. Every decision is logged with the rule that made it._  
_Check Point best practice: One rule per environment pair and service; no «Any» as service._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| NET-01.1 | ICMP echo to the server | Ping from the workload IP. | Allowed | Firewall |
| NET-01.2 | HTTP tcp/80 to the server | Published service. | Allowed | Firewall |
| NET-01.3 | HTTPS tcp/443 to the server | Published and inspected service. | Allowed | Firewall |
| NET-01.4 | SSH tcp/22 to the server | The server listens, but the policy does not allow it. | Blocked | Firewall |
| NET-01.5 | Telnet tcp/23 to the server | Insecure protocol with a listening service. | Blocked | Firewall |
| NET-01.6 | tcp/8080 to the server | Unauthorized alternate HTTP. | Blocked | Firewall |
| NET-01.7 | RDP tcp/3389 to the server | Unauthorized remote administration. | Blocked | Firewall |

### NET-02 · Intra-VPC isolation and control

**Priority:** Critical · _Manual_  
**Objective:** Identifies which traffic inside one VPC goes through the firewall and which stays outside.  
**Firewall configuration needed:** Two instances in different subnets of the same VPC.  
_Check Point notes: With GWLB, endpoints can be inserted between subnets of the same VPC with routes more specific than the local one._  
_Check Point best practice: GWLB with appliance mode on the TGW inspection attachment and cross-zone enabled; instance MTU compatible with GENEVE (8500 in the firewall VPC)._

**Procedure:**

1. Deploy two instances in different subnets of the same VPC.
2. Generate traffic between them (ICMP, tcp/22, tcp/443) and look for those connections in the firewall logs.
3. If they do not show up, traffic uses the VPC local route: document the control with security groups/NACLs.
4. If intra-VPC inspection is needed, add more specific routes (subnet to subnet) to the firewall endpoint and repeat.

**Expected result:** Explicit inventory of inspected and uninspected intra-VPC flows; no assumed coverage.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### NET-03 · North-south egress to the Internet

**Priority:** Critical  
**Objective:** Internet egress is inspected centrally; only the expected traffic passes.  
**Firewall configuration needed:** Egress layer allowing only HTTP, HTTPS and DNS.  
_Check Point notes: Centralized egress (spoke → TGW → inspection → egress VPC with NAT Gateway). On the firewall an inline layer allows HTTP/HTTPS (protocol signature) and DNS and denies the rest._  
_Check Point best practice: Centralized NAT in the egress VPC; the firewall sees the real workload IP._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| NET-03.1 | HTTP to the Internet | Control: legitimate traffic, must not be blocked. | Allowed | Firewall |
| NET-03.2 | HTTPS to the Internet | Control: legitimate traffic, must not be blocked. | Allowed | Firewall / TLS inspection |
| NET-03.3 | DNS UDP to a public resolver | Direct DNS query: allowed service. | Allowed | Firewall |
| NET-03.4 | SMTP tcp/25 to the Internet | Non-web port to the Internet. | Blocked | Firewall |
| NET-03.5 | NTP UDP/123 to the Internet | UDP other than DNS is not allowed. | Blocked | Firewall |
| NET-03.6 | Public egress IP | Shows the public egress IP (centralized NAT). | Allowed | Architecture |

### NET-04 · North-south ingress to published services

**Priority:** High · _Manual_ · _needs extra infrastructure_  
**Objective:** Inbound traffic from the Internet to published services is inspected.  
**Firewall configuration needed:** Outside the reference lab: needs a published service (ALB/NLB) with the ingress route through the firewall.  
_Check Point notes: Check Point recommends GWLB ingress (preserves the source IP) and CloudGuard WAF in front of web apps and APIs._  
_Check Point best practice: GWLB with appliance mode on the TGW inspection attachment and cross-zone enabled; instance MTU compatible with GENEVE (8500 in the firewall VPC)._

**Procedure:**

1. Publish a test service behind a load balancer in an ingress VPC.
2. Route ingress (IGW edge association or ingress VPC) through the firewall endpoints.
3. From the Internet send legitimate requests and attacks (SQLi, XSS, scan) and check blocking and logs with the real client IP.

**Expected result:** Attacks blocked, legitimate traffic allowed and logs with the real source IP.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### NET-05 · Stateful routing symmetry across AZs

**Priority:** Critical  
**Objective:** Both directions of a cross-AZ flow reach the same stateful context.  
**Firewall configuration needed:** Environment pairs in different AZs (configuration) with HTTP allowed between them.  
_Check Point notes: With the inspection attachment in appliance mode both directions use the same GWLBe and the GWLB delivers them to the same gateway; the session is not broken._  
_Check Point best practice: Appliance mode on the inspection attachment (required for cross-AZ symmetry)._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| NET-05.1 | 20 s TCP session with the cross-AZ peer | Persistent HTTP connection with 10 requests in 20 s: with asymmetry the firewall would drop the return traffic. | Allowed | Architecture |

### NET-06 · Alternative paths and bypass

**Priority:** Critical · _control agent_  
**Objective:** No network path lets workload traffic avoid the firewall.  
**Firewall configuration needed:** Control agent running with cloud credentials (read; HA checks change the Auto Scaling group and network ACLs) and Management API credentials.  
_Check Point notes: Audits the route tables of the workload subnets (no IGW, NAT, peering, VGW or gateway endpoints), the Transit Gateway route table of the spokes (everything to the inspection attachment with appliance mode) and peerings._  
_Check Point best practice: GWLB with appliance mode on the TGW inspection attachment and cross-zone enabled; instance MTU compatible with GENEVE (8500 in the firewall VPC)._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| NET-06.1 | Workload and TGW route audit | Reads the actual routes of the account: any route that skips inspection is a failure. | Criterion met | Architecture |

### NET-07 · Production vs non-production segmentation

**Priority:** Critical  
**Objective:** No traffic between production and non-production except approved exceptions.  
**Firewall configuration needed:** prod_envs and nonprod_envs roles and the segmentation matrix.  
_Check Point notes: Environments are defined by CIDR and explicit rules block production ↔ non-production in both directions._  
_Check Point best practice: GWLB with appliance mode on the TGW inspection attachment and cross-zone enabled; instance MTU compatible with GENEVE (8500 in the firewall VPC)._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| NET-07.1 | Production ↔ non-production matrix | Configured segmentation matrix: from this environment to the others it tests ICMP, HTTP, HTTPS, SSH, RDP, tcp/8080 and iperf3 and compares with what is allowed. | Per matrix | Firewall |

### NET-08 · Selective routing / service chaining

**Priority:** High · _Manual_  
**Objective:** Only the selected traffic is sent to inspection and the rest keeps working.  
**Firewall configuration needed:** Editable Transit Gateway route tables.  
_Check Point notes: Prefer excluding by policy (access rule + threat exception) rather than by routes: keeps logging and visibility._  
_Check Point best practice: GWLB with appliance mode on the TGW inspection attachment and cross-zone enabled; instance MTU compatible with GENEVE (8500 in the firewall VPC)._

**Procedure:**

1. Define which destinations must go through inspection and which not (e.g. traffic to a trusted internal service).
2. Adjust TGW/VPC routes to exclude only that destination and check in the logs that the rest is still inspected.
3. Check symmetry: both directions of the excluded flow avoid the firewall (otherwise the session breaks).

**Expected result:** The exclusion affects only the defined destination, is symmetric and is documented.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### NET-09 · Topology or route change without degrading security

**Priority:** High · _Manual_  
**Objective:** A route or VPC change does not open uninspected paths.  
**Firewall configuration needed:** Test environment where VPCs and routes can be added.  
_Check Point notes: Use data center objects (CloudGuard Controller) or tags so new spokes inherit the policy._  
_Check Point best practice: GWLB with appliance mode on the TGW inspection attachment and cross-zone enabled; instance MTU compatible with GENEVE (8500 in the firewall VPC)._

**Procedure:**

1. Add a new spoke or change a TGW route (as in a real operation).
2. Run NET-06 (route audit) and the segmentation matrix (NET-01/NET-07) before and after.
3. Check that the policy picks up the new spoke through a dynamic object/tag without editing rules.

**Expected result:** No bypass routes and the same matrix results after the change.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### NET-10 · IPv6 egress and routing

**Priority:** High · _Manual_ · _needs extra infrastructure_  
**Objective:** IPv6 traffic is inspected like IPv4.  
**Firewall configuration needed:** Outside the reference lab: needs dual-stack VPCs and an egress-only IGW routed through the firewall.  
_Check Point notes: Confirm IPv6 support of the deployed version and GWLB mode and build the rules with IPv6 objects._  
_Check Point best practice: GWLB with appliance mode on the TGW inspection attachment and cross-zone enabled; instance MTU compatible with GENEVE (8500 in the firewall VPC)._

**Procedure:**

1. Enable IPv6 on a spoke and on the inspection VPC.
2. Route ::/0 to the firewall endpoint and go out to the Internet over IPv6.
3. Repeat the NET-03 and APP-02 checks over IPv6 and compare the logs.

**Expected result:** Same decisions and logs over IPv4 and IPv6.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### NET-11 · Hybrid AWS–on-prem connectivity

**Priority:** Medium · _Manual_ · _needs extra infrastructure_  
**Objective:** Traffic between the cloud and the data center goes through inspection.  
**Firewall configuration needed:** Outside the reference lab: needs a VPN or Direct Connect to the TGW.  
_Check Point notes: Same TGW table design as for spokes; appliance mode on the inspection attachment._  
_Check Point best practice: GWLB with appliance mode on the TGW inspection attachment and cross-zone enabled; instance MTU compatible with GENEVE (8500 in the firewall VPC)._

**Procedure:**

1. Connect a VPN/Direct Connect to the TGW and associate its attachment with the table that sends to inspection.
2. Generate on-prem ↔ spoke traffic and check in the logs that it is inspected both ways.

**Expected result:** Hybrid traffic inspected and symmetric.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### NET-12 · AWS–Azure intercloud connectivity

**Priority:** Medium · _Manual_ · _needs extra infrastructure_  
**Objective:** Traffic between clouds is inspected with the same policy.  
**Firewall configuration needed:** Outside the reference lab: needs a connected Azure environment (VPN/ExpressRoute).  
_Check Point notes: A single management (Smart-1 Cloud) for AWS and Azure gateways: same objects, layers and logs._  
_Check Point best practice: GWLB with appliance mode on the TGW inspection attachment and cross-zone enabled; instance MTU compatible with GENEVE (8500 in the firewall VPC)._

**Procedure:**

1. Connect AWS and Azure (VPN between the TGW and Virtual WAN/VNet).
2. Deploy a kit client in Azure and run the segmentation matrix across clouds.
3. Compare policy and logs in both clouds from the same console.

**Expected result:** Same policy and unified visibility in both clouds.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### NET-13 · MTU, fragmentation and GENEVE

**Priority:** High  
**Objective:** No MTU black holes; the maximum usable size is measured.  
**Firewall configuration needed:** ICMP allowed to the server.  
_Check Point notes: GWLB encapsulates in GENEVE and supports an 8,500-byte MTU. The largest unfragmented packet is measured._  
_Check Point best practice: Jumbo frames in the firewall VPC; MSS clamping where there are 1500-MTU hops._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| NET-13.1 | Effective MTU to the server | DF ping from 1,472 to 8,472 bytes. Criterion: ≥ 1,472. | Measure | Architecture |

<a id="pol"></a>
## POL · Policy and segmentation

### POL-01 · Stateful allow/deny and default deny

**Priority:** Critical  
**Objective:** Only authorized 5-tuples pass; everything else is dropped and logged.  
**Firewall configuration needed:** Allow-list to the server and cleanup rule.  
_Check Point notes: Stateful allow-list policy with a final cleanup rule (Drop + Log)._  
_Check Point best practice: Layers in sections, dynamic objects (CloudGuard Controller) instead of IPs, logged rules and expiry for exceptions._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| POL-01.1 | Authorized tcp/80 | Authorized 5-tuple. | Allowed | Firewall |
| POL-01.2 | Authorized tcp/443 | Authorized 5-tuple. | Allowed | Firewall |
| POL-01.3 | Unauthorized tcp/22 | Same source and destination, unauthorized port. | Blocked | Firewall |
| POL-01.4 | Unauthorized tcp/5202 | Port next to an exception. | Blocked | Firewall |

### POL-02 · Granular 5-tuple exceptions

**Priority:** Critical  
**Objective:** An exception opens only the given flow; neighbouring ports stay blocked.  
**Firewall configuration needed:** Rule allowing only the configured exception port.  
_Check Point notes: Exception rule for a single port (iperf3 tcp/5201 by default) between environments._  
_Check Point best practice: Layers in sections, dynamic objects (CloudGuard Controller) instead of IPs, logged rules and expiry for exceptions._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| POL-02.1 | Excepted port | Excepted flow. | Allowed | Firewall |
| POL-02.2 | Lower neighbouring port | Must not be open. | Blocked | Firewall |
| POL-02.3 | Upper neighbouring port | Must not be open. | Blocked | Firewall |

### POL-03 · Granularity by application, identity or tag

**Priority:** Critical · _Manual_  
**Objective:** Rules can use application, identity and cloud tags, not just IP/port.  
**Firewall configuration needed:** Cloud connector (tag reading) and, for identity, an identity provider.  
_Check Point notes: CloudGuard Controller (AWS data center objects by tag) and Identity Awareness; rules use objects, never fixed workload IPs._  
_Check Point best practice: Layers in sections, dynamic objects (CloudGuard Controller) instead of IPs, logged rules and expiry for exceptions._

**Procedure:**

1. Create a rule using an application (e.g. block a given application) and verify it with the kit (APP-01).
2. Create a dynamic object by instance tag and use it as source of a rule; change an instance tag and check the rule follows it.
3. If applicable, create a rule by identity group and verify the log shows the user.

**Expected result:** Application, tag and identity rules effective and logged.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### POL-04 · Expiry, approval and rollback of exceptions

**Priority:** High · _Manual_  
**Objective:** Exceptions have an owner, an approval and an expiry date, and can be rolled back.  
**Firewall configuration needed:** Change workflow with approval (sessions with approval or ITSM).  
_Check Point notes: Rule «Time» field (time object with end date), session approval workflow and policy revisions (Installation History)._  
_Check Point best practice: Layers in sections, dynamic objects (CloudGuard Controller) instead of IPs, logged rules and expiry for exceptions._

**Procedure:**

1. Create an exception rule with an expiry date and a comment with the change number.
2. Publish with approval of a second administrator.
3. Check the rule stops applying when it expires and revert to the previous revision.

**Expected result:** Exception approved, expired automatically and revertible with traceability.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### POL-05 · FQDN rules

**Priority:** Critical  
**Objective:** The decision is made by domain, not by IP.  
**Firewall configuration needed:** Custom site with the configured blocked FQDN.  
_Check Point notes: URL Filtering custom site: decided by Host (HTTP) and SNI/certificate (HTTPS). By default www.example.org (blocked) and www.example.com (allowed) share the same IP._  
_Check Point best practice: Non-wildcard domain objects for specific FQDNs; Application Control/URL Filtering for categories._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| POL-05.1 | Allowed FQDN | Control: legitimate traffic, must not be blocked. | Allowed | URL Filtering |
| POL-05.2 | Blocked FQDN (HTTP) | Same hosting and IP: blocked only if the decision is by name. | Blocked | URL Filtering |
| POL-05.3 | Blocked FQDN (HTTPS) | Over HTTPS the decision uses SNI/certificate. | Blocked | URL Filtering / TLS inspection |

### POL-06 · FQDN rules: IP rotation, TTL and multiple A/AAAA

**Priority:** High · _Manual_  
**Objective:** FQDN rules follow the changing IPs of cloud services.  
**Firewall configuration needed:** Rule with a domain object (non-wildcard) and a destination with several IPs and low TTL.  
_Check Point notes: FQDN domain objects (non-wildcard) resolve on the gateway; for known SaaS prefer vendor Updatable Objects._  
_Check Point best practice: Layers in sections, dynamic objects (CloudGuard Controller) instead of IPs, logged rules and expiry for exceptions._

**Procedure:**

1. Create a rule allowing an FQDN with several A/AAAA records and low TTL (e.g. a SaaS service).
2. From a client resolve and connect repeatedly for 30 min; note the returned IPs.
3. Check that every connection is allowed and the logs show the domain.

**Expected result:** No legitimate connection denied because of an IP change.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### POL-07 · DNS failures

**Priority:** Critical  
**Objective:** A resolution failure never opens connectivity.  
**Firewall configuration needed:** None.  
_Check Point notes: Without resolution there is no flow and the policy stays default-deny._  
_Check Point best practice: Layers in sections, dynamic objects (CloudGuard Controller) instead of IPs, logged rules and expiry for exceptions._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| POL-07.1 | Non-existent name (NXDOMAIN) | curl to a .invalid name. | No flow | Firewall |

### POL-08 · Dynamic AWS tags: add, change and remove

**Priority:** Critical · _Manual_  
**Objective:** The policy follows instances by tag in near real time.  
**Firewall configuration needed:** Cloud connector with EC2 read access and a rule with a dynamic tag object.  
_Check Point notes: CloudGuard Controller updates data center objects without a policy install (configurable scan interval, 30 s by default)._  
_Check Point best practice: Layers in sections, dynamic objects (CloudGuard Controller) instead of IPs, logged rules and expiry for exceptions._

**Procedure:**

1. Create a dynamic object «Environment=pro» and use it in a rule allowing a service.
2. Launch an instance with that tag and measure how long until it is allowed.
3. Change the tag and measure how long until it stops being allowed; terminate the instance and check its IP leaves the object.

**Expected result:** Add, change and remove reflected without reinstalling the policy, with measured times.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### POL-09 · Tags across accounts, regions and environments

**Priority:** High · _Manual_  
**Objective:** Tag-based objects work across several accounts and regions.  
**Firewall configuration needed:** Cloud connector with roles in several accounts (AssumeRole).  
_Check Point notes: One AWS data center object per account (STS role) and groups combining them._  
_Check Point best practice: Layers in sections, dynamic objects (CloudGuard Controller) instead of IPs, logged rules and expiry for exceptions._

**Procedure:**

1. Register two accounts (or one account in two regions) in the cloud connector with read-only roles.
2. Create a tag object including instances of both and use it in a rule.
3. Check that the object contains the IPs of both accounts and the rule applies.

**Expected result:** The same object covers accounts and regions.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### POL-10 · Rule precedence

**Priority:** Critical  
**Objective:** Evaluation order is deterministic and the matching rule is logged.  
**Firewall configuration needed:** precedence_clients and precedence_target roles, and the exception rule above the blocking rule.  
_Check Point notes: The rulebase is evaluated top-down: an exception rule above the segmentation rule wins for its service; the rest is decided by segmentation._  
_Check Point best practice: Layers in sections, dynamic objects (CloudGuard Controller) instead of IPs, logged rules and expiry for exceptions._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| POL-10.1 | Excepted service to the blocked target (only from role `precedence_clients`) | The exception rule is above the blocking rule. | Allowed | Firewall |
| POL-10.2 | HTTP to the blocked target (only from role `precedence_clients`) | No earlier rule allows it, so the blocking rule decides. | Blocked | Firewall |

### POL-11 · Micro-segmentation by service and environment

**Priority:** Critical  
**Objective:** No lateral movement outside the approved matrix.  
**Firewall configuration needed:** Segmentation matrix in the configuration.  
_Check Point notes: The full matrix is run from every environment (batch over all clients)._  
_Check Point best practice: Layers in sections, dynamic objects (CloudGuard Controller) instead of IPs, logged rules and expiry for exceptions._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| POL-11.1 | Full environment matrix | Configured segmentation matrix: from this environment to the others it tests ICMP, HTTP, HTTPS, SSH, RDP, tcp/8080 and iperf3 and compares with what is allowed. | Per matrix | Firewall |

### POL-12 · Combined profiles

**Priority:** High  
**Objective:** Several controls on the same flow, each one traceable.  
**Firewall configuration needed:** Full profile on the egress rule and TLS inspection.  
_Check Point notes: Internet egress combines Firewall, App Control, URL Filtering, IPS, Anti-Bot and Anti-Virus; the log shows which blade acted._  
_Check Point best practice: Layers in sections, dynamic objects (CloudGuard Controller) instead of IPs, logged rules and expiry for exceptions._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| POL-12.1 | EICAR from the Internet over HTTPS | Anti-Virus on decrypted HTTPS. | Blocked | Anti-malware / TLS inspection |
| POL-12.2 | Anti-Bot test page | C&C reputation. | Blocked | Anti-bot (C&C) |
| POL-12.3 | Gambling category | URL Filtering by category. | Blocked | URL Filtering |
| POL-12.4 | Legitimate site | Control: legitimate traffic, must not be blocked. | Allowed | All |

### POL-13 · Redundant, shadowed and overly broad rules

**Priority:** High · _Manual_  
**Objective:** Rules that never apply or allow too much are detected.  
**Firewall configuration needed:** Policy package with traffic history.  
_Check Point notes: Policy Insights / Compliance blade (Best Practices) and hit count; avoid Any as service or destination in Accept rules._  
_Check Point best practice: Layers in sections, dynamic objects (CloudGuard Controller) instead of IPs, logged rules and expiry for exceptions._

**Procedure:**

1. Run the vendor policy analysis (shadowed, redundant, «any any» rules).
2. Cross-check with POL-14 (rules without hits).
3. Document actions: remove, narrow or justify.

**Expected result:** List of findings with a decided action for each one.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### POL-14 · Unused rules

**Priority:** Medium · _control agent_  
**Objective:** Rules without traffic are identified for review or removal.  
**Firewall configuration needed:** Hit counters enabled on the gateways.  
_Check Point notes: Hit counters of every rule of the access layers of the policy package, through the Management API._  
_Check Point best practice: Layers in sections, dynamic objects (CloudGuard Controller) instead of IPs, logged rules and expiry for exceptions._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| POL-14.1 | Rules without hits and disabled rules | List of cleanup candidates. | Measure | Management |

### POL-15 · Detect vs prevent mode

**Priority:** High  
**Objective:** The same stimulus is only detected on one target and blocked on another.  
**Firewall configuration needed:** ids_target and ids_clients roles; TP rule with a Detect profile to ids_target; HTTP allowed from ids_clients.  
_Check Point notes: Threat Prevention rule with a Detect profile towards the ids_target environment and a Prevent profile towards the server._  
_Check Point best practice: Detect only temporarily (learning period) and per environment; move to Prevent on a set date._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| POL-15.1 | SQLi to the Detect target (only from role `ids_clients`) | Reaches the server and is logged as Detect. | Allowed | IPS |
| POL-15.2 | SQLi to the Prevent server (only from role `ids_clients`) | Blocked and logged as Prevent. | Blocked | IPS |

### POL-16 · Declarative policy and drift control

**Priority:** High · _control agent_  
**Objective:** Changes made outside the declarative flow are detected.  
**Firewall configuration needed:** The policy is built as code (kit scripts or Terraform). Baseline stored by the control agent.  
_Check Point notes: The published policy is compared with a baseline (normalized snapshot of the access, threat and HTTPS inspection layers). To prove detection, a disabled rule is added through the API and published, it must show up as drift, and it is removed._  
_Check Point best practice: Layers in sections, dynamic objects (CloudGuard Controller) instead of IPs, logged rules and expiry for exceptions._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| POL-16.1 | Detection of an out-of-band change | A temporary change (disabled rule) is published and removed. | Criterion met | Management |

<a id="ips"></a>
## IPS · Intrusion prevention

### IPS-01 · Known attack prevention

**Priority:** Critical  
**Objective:** Signatures detect and block; the log includes protection, severity and action.  
**Firewall configuration needed:** threat prevention profile with IPS in Prevent on the east-west rule.  
_Check Point notes: IPS in Prevent for all east-west and Internet traffic._  
_Check Point best practice: Optimized/Strict in Prevent with «Protections activation» by severity and confidence._

| ID | Check | What it does | Expected | Capability |
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
**Firewall configuration needed:** Only 80, 443 and the exception port allowed to the server.  
_Check Point notes: The firewall drops unauthorized ports even if the server listens; attempts are logged._  
_Check Point best practice: Optimized/Strict profile in Prevent, automatic updates, exceptions scoped by asset and protection (never global) and Inactive only for absent technologies (e.g. OT/SCADA by tag)._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| IPS-02.1 | Port scan of the server | nmap over 1-1024, 3389, 5201 and 8080: only authorized ports must be visible. | Authorized only | Firewall / IPS |

### IPS-03 · IPS signature configuration and updates

**Priority:** High · _control agent_  
**Objective:** Signatures are up to date and profiles activate protections on explicit criteria.  
**Firewall configuration needed:** Automatic IPS updates on the management.  
_Check Point notes: IPS package status (installed and latest version, date) and activation criteria of the prevention profiles (impact, severity, confidence)._  
_Check Point best practice: Optimized/Strict profile in Prevent, automatic updates, exceptions scoped by asset and protection (never global) and Inactive only for absent technologies (e.g. OT/SCADA by tag)._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| IPS-03.1 | Signature version and profiles | Signatures newer than 7 days or no pending update. | Criterion met | IPS |

### IPS-04 · Per-asset signature exception

**Priority:** Critical  
**Objective:** Only the authorized combination is excepted; everything else stays protected.  
**Firewall configuration needed:** Exception on the east-west rule: protection 'TP-Link Archer AX21 Command Injection (CVE-2023-1389)', source = ips_exception_client environment, action Detect.  
_Check Point notes: Threat Prevention exception with a single protection (TP-Link Archer AX21, CVE-2023-1389), source ips_exception_client and the server as destination, in Detect._  
_Check Point best practice: Exception per specific protection and asset with expiry; never disable the protection globally._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| IPS-04.1 | CVE-2023-1389 from the excepted asset (only from role `ips_exception_client`) | In scope: Detect. | Allowed | IPS |
| IPS-04.2 | CVE-2023-1389 from another asset | Out of scope: still blocked. | Blocked | IPS |
| IPS-04.3 | Another protection from the excepted asset (only from role `ips_exception_client`) | All other protections stay active. | Blocked | IPS |

### IPS-05 · False positives

**Priority:** High  
**Objective:** Legitimate traffic resembling signatures is not blocked.  
**Firewall configuration needed:** None.  
_Check Point notes: Profiles by confidence and impact; fine tuning uses per-asset exceptions without disabling detections globally._  
_Check Point best practice: Optimized/Strict profile in Prevent, automatic updates, exceptions scoped by asset and protection (never global) and Inactive only for absent technologies (e.g. OT/SCADA by tag)._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| IPS-05.1 | Text with 'select' and 'union' | Control: legitimate traffic, must not be blocked. | Allowed | IPS |
| IPS-05.2 | Surname with apostrophe | Control: legitimate traffic, must not be blocked. | Allowed | IPS |
| IPS-05.3 | Filter with comparators | Control: legitimate traffic, must not be blocked. | Allowed | IPS |
| IPS-05.4 | JSON with legitimate HTML | Control: legitimate traffic, must not be blocked. | Allowed | IPS |
| IPS-05.5 | Legitimate shell script | Control: legitimate traffic, must not be blocked. | Allowed | IPS / Anti-malware |

### IPS-06 · Virtual patching of published CVEs

**Priority:** High  
**Objective:** Exploitation patterns are blocked without touching the server.  
**Firewall configuration needed:** IPS in Prevent.  
_Check Point notes: IPS blocks exploitation of known CVEs; the test server is not vulnerable, it only receives the pattern._  
_Check Point best practice: Review new protections in Detect weekly and promote them to Prevent._

| ID | Check | What it does | Expected | Capability |
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
**Firewall configuration needed:** IPS in Prevent.  
_Check Point notes: IPS reassembles the TCP stream and normalizes encoding before pattern matching._  
_Check Point best practice: Keep TCP/IP evasion and fragmentation protections enabled (Inspection Settings)._

| ID | Check | What it does | Expected | Capability |
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
**Firewall configuration needed:** Egress rule with the blocked countries and a test URL in one of them (config.internet.geo_blocked_url).  
_Check Point notes: GEO updatable objects in the egress layer._  
_Check Point best practice: Geo Policy or a rule with updatable country objects at the top of the egress layer._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| IPS-08.1 | Destination in a blocked country | Destination IP in a blocked country. | Blocked | Firewall (GEO) |
| IPS-08.2 | Destination in an allowed country | Control: legitimate traffic, must not be blocked. | Allowed | Firewall (GEO) |

### IPS-09 · C&C and botnets

**Priority:** High  
**Objective:** Traffic to C&C indicators is blocked.  
**Firewall configuration needed:** Anti-Bot in the egress profile.  
_Check Point notes: Anti-Bot blocks by domain, IP and URL reputation (ThreatCloud) and by communication patterns._  
_Check Point best practice: Optimized/Strict profile in Prevent, automatic updates, exceptions scoped by asset and protection (never global) and Inactive only for absent technologies (e.g. OT/SCADA by tag)._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| IPS-09.1 | Vendor C&C test URL | Test URL the vendor classifies as C&C (configurable in Internet targets). | Blocked | Anti-bot (C&C) |
| IPS-09.2 | Control: allowed business site | Control: legitimate traffic, must not be blocked. | Allowed | Anti-bot (C&C) |

### IPS-10 · Threat reaction time and propagation

**Priority:** High · _control agent_  
**Objective:** A new indicator of compromise is enforced on the gateways within a measured time.  
**Firewall configuration needed:** Anti-bot enabled on Internet egress. Test domain in internet.ioc_test_domain (resolved to the IP of the allowed site).  
_Check Point notes: An indicator (domain, Prevent) is created through the API, the threat policy is published and installed, and a client connects to that domain until it is blocked; then it is removed._  
_Check Point best practice: Optimized/Strict profile in Prevent, automatic updates, exceptions scoped by asset and protection (never global) and Inactive only for absent technologies (e.g. OT/SCADA by tag)._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| IPS-10.1 | From new indicator to effective block | Installs the threat policy twice on the test gateways. | Criterion met | Anti-bot (C&C) |

### IPS-11 · IDS vs IPS differentiated policy

**Priority:** High  
**Objective:** Detect mode does not block; prevent mode does; both log.  
**Firewall configuration needed:** Same as POL-15.  
_Check Point notes: Same stimulus against the Detect target (ids_target) and the Prevent server._  
_Check Point best practice: Optimized/Strict profile in Prevent, automatic updates, exceptions scoped by asset and protection (never global) and Inactive only for absent technologies (e.g. OT/SCADA by tag)._

| ID | Check | What it does | Expected | Capability |
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
**Firewall configuration needed:** Anti-Virus inspecting both directions and archives.  
_Check Point notes: Anti-Virus (signatures + ThreatCloud) over HTTP/HTTPS including nested archives and uploads._  
_Check Point best practice: Anti-Virus in both directions with archive inspection, Threat Emulation + Threat Extraction for documents and Anti-Bot in Prevent._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| THR-01.1 | EICAR (.com) | Download from the server; Anti-Virus inspects files in both directions and inside archives. | Blocked | Anti-malware |
| THR-01.2 | EICAR (.txt) | Download from the server; Anti-Virus inspects files in both directions and inside archives. | Blocked | Anti-malware |
| THR-01.3 | EICAR in zip | Download from the server; Anti-Virus inspects files in both directions and inside archives. | Blocked | Anti-malware |
| THR-01.4 | EICAR in nested zip | Download from the server; Anti-Virus inspects files in both directions and inside archives. | Blocked | Anti-malware |
| THR-01.5 | EICAR upload in request body (POST) | API-style upload: the file travels in the request body. | Blocked | IPS / Anti-malware |
| THR-01.6 | Benign zip (control) | Control: legitimate traffic, must not be blocked. | Allowed | Anti-malware |

### THR-02 · Anti-malware over HTTPS with and without decryption

**Priority:** High  
**Objective:** Quantifies what TLS inspection adds.  
**Firewall configuration needed:** TLS inspection with bypass for nodecrypt.testkit.lab and mtls.testkit.lab.  
_Check Point notes: Same EICAR over HTTPS to the same server with two names: inspect.testkit.lab (decrypted) and nodecrypt.testkit.lab (bypassed)._  
_Check Point best practice: Without decryption anti-malware only sees the SNI: decrypt download traffic._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| THR-02.1 | EICAR over HTTP | Download from the server; Anti-Virus inspects files in both directions and inside archives. | Blocked | Anti-malware |
| THR-02.2 | EICAR over decrypted HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | Anti-malware / TLS inspection |
| THR-02.3 | EICAR over non-decrypted HTTPS | Without decryption there is no content visibility (expected result). | Allowed | TLS inspection (bypass) |
| THR-02.4 | EICAR from the Internet over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | Anti-malware / TLS inspection |

### THR-03 · Benign files without false positives

**Priority:** High  
**Objective:** Clean files of several formats and sizes are not blocked.  
**Firewall configuration needed:** None.  
_Check Point notes: Downloads over HTTP and HTTPS._  
_Check Point best practice: Anti-Virus in both directions with archive inspection, Threat Emulation + Threat Extraction for documents and Anti-Bot in Prevent._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| THR-03.1 | benign.pdf over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | Anti-malware |
| THR-03.2 | benign.pdf over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | Anti-malware |
| THR-03.3 | benign.docx over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | Anti-malware |
| THR-03.4 | benign.docx over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | Anti-malware |
| THR-03.5 | benign.xlsx over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | Anti-malware |
| THR-03.6 | benign.xlsx over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | Anti-malware |
| THR-03.7 | benign.png over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | Anti-malware |
| THR-03.8 | benign.png over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | Anti-malware |
| THR-03.9 | benign.json over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | Anti-malware |
| THR-03.10 | benign.json over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | Anti-malware |
| THR-03.11 | benign.csv over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | Anti-malware |
| THR-03.12 | benign.csv over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | Anti-malware |
| THR-03.13 | benign_10m.bin over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | Anti-malware |
| THR-03.14 | benign_10m.bin over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | Anti-malware |

### THR-04 · Emulation/sandbox of a test file

**Priority:** Medium · _Manual_ · _needs extra infrastructure_  
**Objective:** Unknown files are analysed in a sandbox before delivery.  
**Firewall configuration needed:** Outside the reference lab: needs the licensed sandbox (emulation) capability and a vendor test file.  
_Check Point notes: Threat Emulation (ThreatCloud) in Prevent + Threat Extraction for documents (immediate delivery of a clean copy)._  
_Check Point best practice: Anti-Virus in both directions with archive inspection, Threat Emulation + Threat Extraction for documents and Anti-Bot in Prevent._

**Procedure:**

1. Enable emulation in the threat profile in Prevent mode (hold the file until the verdict).
2. Download from a client a vendor emulation test file and a new benign document.
3. Check the verdict, delivery time and the emulation report.

**Expected result:** Malicious file blocked with a report; benign file delivered with measured time.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### THR-05 · Combined AV, Anti-Bot and IPS

**Priority:** High  
**Objective:** Combined controls do not cancel each other and show who acted.  
**Firewall configuration needed:** Full profile and TLS inspection.  
_Check Point notes: Several blades in the same profile._  
_Check Point best practice: Anti-Virus in both directions with archive inspection, Threat Emulation + Threat Extraction for documents and Anti-Bot in Prevent._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| THR-05.1 | EICAR zip over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | Anti-malware / TLS inspection |
| THR-05.2 | SQLi over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | IPS / TLS inspection |
| THR-05.3 | C&C over HTTP | Anti-Bot. | Blocked | Anti-bot (C&C) |

### THR-06 · Threat intelligence updates

**Priority:** High · _control agent_  
**Objective:** Anti-malware, anti-bot, URL and application databases are up to date on every gateway.  
**Firewall configuration needed:** Gateway access to the vendor update services.  
_Check Point notes: Update status of every database on the gateways (run-script) and of the updatable objects (GEO, online services)._  
_Check Point best practice: Anti-Virus in both directions with archive inspection, Threat Emulation + Threat Extraction for documents and Anti-Bot in Prevent._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| THR-06.1 | Update status per gateway | Any database with errors or not updated is a failure. | Criterion met | Anti-malware / Anti-bot (C&C) |

<a id="tls"></a>
## TLS · TLS inspection

### TLS-01 · TLS 1.2 and 1.3 inspection

**Priority:** Critical  
**Objective:** Documents which versions are inspected and blocks patterns inside them.  
**Firewall configuration needed:** Outbound TLS inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.  
_Check Point notes: HTTPS Inspection inspects TLS 1.2 and 1.3 re-signing with the inspection CA._  
_Check Point best practice: HTTPS Inspection with its own layer, bypass by the recommended updatable object (sk163595) and sensitive categories, TLS 1.3 and certificate validation._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| TLS-01.1 | TLS 1.2 decrypted | The received certificate is issued by the inspection CA. | Decrypted | TLS inspection |
| TLS-01.2 | TLS 1.3 decrypted | Same with TLS 1.3. | Decrypted | TLS inspection |
| TLS-01.3 | SQLi over TLS 1.2 | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | IPS / TLS inspection |
| TLS-01.4 | SQLi over TLS 1.3 | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | IPS / TLS inspection |
| TLS-01.5 | Clean request over TLS 1.3 | Control: legitimate traffic, must not be blocked. | Allowed | TLS inspection |

### TLS-02 · Inspection CA and trust chain

**Priority:** High  
**Objective:** Only clients trusting the CA work; there is no hidden bypass.  
**Firewall configuration needed:** Outbound TLS inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.  
_Check Point notes: The inspection CA is distributed to clients; a client without it gets a certificate error._  
_Check Point best practice: HTTPS Inspection with its own layer, bypass by the recommended updatable object (sk163595) and sensitive categories, TLS 1.3 and certificate validation._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| TLS-02.1 | Certificate replaced on the Internet | The site arrives signed by the inspection CA. | Decrypted | TLS inspection |
| TLS-02.2 | Client with the inspection CA | Validates with the inspection CA in its store. | Cert. valid | TLS inspection |
| TLS-02.3 | Client without the inspection CA | Public CAs only: fails. | Cert. rejected | TLS inspection |

### TLS-03 · Expired, revoked or untrusted certificates

**Priority:** High  
**Objective:** The response matches the validation policy and is logged.  
**Firewall configuration needed:** HTTPS advanced settings: block untrusted, expired and revoked.  
_Check Point notes: HTTPS Inspection validates the original certificate and blocks untrusted, expired and revoked ones._  
_Check Point best practice: Block expired, untrusted and revoked certificates (server validation in the HTTPS layer)._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| TLS-03.1 | Expired certificate | Server certificate validation. | Blocked | TLS inspection |
| TLS-03.2 | Self-signed certificate | Untrusted CA. | Blocked | TLS inspection |
| TLS-03.3 | Untrusted root | Chain to an unknown root. | Blocked | TLS inspection |
| TLS-03.4 | Revoked certificate | Revoked. | Blocked | TLS inspection |
| TLS-03.5 | Control: valid certificate | Control: legitimate traffic, must not be blocked. | Allowed | TLS inspection |

### TLS-04 · mTLS and certificate pinning

**Priority:** High  
**Objective:** Incompatibilities are solved with a minimal bypass.  
**Firewall configuration needed:** Outbound TLS inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.  
_Check Point notes: mTLS and pinning do not accept a man-in-the-middle: only those FQDNs are bypassed._  
_Check Point best practice: HTTPS Inspection with its own layer, bypass by the recommended updatable object (sk163595) and sensitive categories, TLS 1.3 and certificate validation._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| TLS-04.1 | mTLS with client certificate (bypassed) | The server requires a client certificate. | Allowed | TLS inspection (bypass) |
| TLS-04.2 | CA pinning (bypassed) | Client trusting only the service CA. | Cert. valid | TLS inspection (bypass) |
| TLS-04.3 | CA pinning (inspected) | Against the inspected FQDN it fails: pinning needs a bypass. | Cert. rejected | TLS inspection |

### TLS-05 · Decryption bypass by FQDN and category

**Priority:** Critical  
**Objective:** Only the approved scope is not decrypted.  
**Firewall configuration needed:** Outbound TLS inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.  
_Check Point notes: Bypass by FQDN, sensitive categories (finance, health, government) and the Check Point recommended list._  
_Check Point best practice: HTTPS Inspection with its own layer, bypass by the recommended updatable object (sk163595) and sensitive categories, TLS 1.3 and certificate validation._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| TLS-05.1 | Bypassed FQDN | Not decrypted. | Not decrypted | TLS inspection |
| TLS-05.2 | Inspected FQDN | Decrypted. | Decrypted | TLS inspection |
| TLS-05.3 | Banking (Financial category) | Sensitive category bypassed. | Not decrypted | TLS inspection |
| TLS-05.4 | General website | Decrypted. | Decrypted | TLS inspection |

### TLS-06 · HTTP/2, QUIC and ECH

**Priority:** High  
**Objective:** Effective visibility is known and there is no silent bypass.  
**Firewall configuration needed:** Outbound TLS inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.  
_Check Point notes: HTTP/2 is inspected like HTTP/1.1; QUIC (UDP/443) is denied to force inspected TCP._  
_Check Point best practice: Block QUIC (UDP/443) to force inspectable HTTP/2 over TLS._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| TLS-06.1 | SQLi over HTTP/2 | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | IPS / TLS inspection |
| TLS-06.2 | EICAR over HTTP/2 | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | Anti-malware / TLS inspection |
| TLS-06.3 | Clean request over HTTP/2 | Control: legitimate traffic, must not be blocked. | Allowed | TLS inspection |
| TLS-06.4 | QUIC (UDP/443) to the Internet | QUIC Initial packet: no answer. | Blocked | Firewall |

### TLS-07 · Transparent mode and observability

**Priority:** Medium  
**Objective:** The impact on the source IP is known.  
**Firewall configuration needed:** Outbound TLS inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.  
_Check Point notes: Behind GWLB the firewall is transparent: it keeps the original IP and adds no proxy headers._  
_Check Point best practice: HTTPS Inspection with its own layer, bypass by the recommended updatable object (sk163595) and sensitive categories, TLS 1.3 and certificate validation._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| TLS-07.1 | Source IP preserved (inspected HTTPS) | The server returns the IP and headers it sees. | IP preserved | TLS inspection |

### TLS-08 · TLS inspection overhead

**Priority:** Critical  
**Objective:** The real handshake and latency overhead is measured.  
**Firewall configuration needed:** Outbound TLS inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.  
_Check Point notes: 100 new HTTPS connections with and without decryption to the same server; percentiles are compared._  
_Check Point best practice: Size TLS inspection with PERF-02; bypass trusted high-volume categories (OS updates, backups)._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| TLS-08.1 | TLS inspection overhead | inspect.testkit.lab vs nodecrypt.testkit.lab. | Measure | TLS inspection |

### TLS-09 · Threats inside HTTPS (east-west)

**Priority:** High  
**Objective:** IPS and AV payloads inside HTTPS are blocked as in HTTP.  
**Firewall configuration needed:** Outbound TLS inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.  
_Check Point notes: East-west HTTPS Inspection restores visibility for IPS, AV and DLP._  
_Check Point best practice: HTTPS Inspection with its own layer, bypass by the recommended updatable object (sk163595) and sensitive categories, TLS 1.3 and certificate validation._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| TLS-09.1 | XSS over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | IPS / TLS inspection |
| TLS-09.2 | Path traversal over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | IPS / TLS inspection |
| TLS-09.3 | Log4Shell over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | IPS / TLS inspection |
| TLS-09.4 | Shellshock over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | IPS / TLS inspection |
| TLS-09.5 | EICAR over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | Anti-malware / TLS inspection |
| TLS-09.6 | Clean request over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | TLS inspection |

### TLS-10 · Evasion and obfuscation over HTTPS

**Priority:** High  
**Objective:** No technique bypasses the controls.  
**Firewall configuration needed:** Outbound TLS inspection with the inspection CA trusted by clients and the testkit CA as a trusted CA.  
_Check Point notes: With HTTPS Inspection the gateway sees the real Host, decompresses gzip, reassembles chunked/multipart and validates the protocol per port._  
_Check Point best practice: HTTPS Inspection with its own layer, bypass by the recommended updatable object (sk163595) and sensitive categories, TLS 1.3 and certificate validation._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| TLS-10.1 | Domain fronting (allowed SNI, blocked Host) | With decryption the real Host is visible. | Blocked | Application control / TLS inspection |
| TLS-10.2 | EICAR with Content-Encoding gzip | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | Anti-malware / TLS inspection |
| TLS-10.3 | EICAR multipart upload (HTTPS) | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | Anti-malware / TLS inspection |
| TLS-10.4 | SQLi in chunked body (HTTP/1.1 over TLS) | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | IPS / TLS inspection |
| TLS-10.5 | HTTPS to non-standard port (8443) | TLS outside 443. | Blocked | Firewall |
| TLS-10.6 | Card data in JSON over HTTPS | HTTPS request to the server with SNI inspect.testkit.lab: TLS inspection decrypts and the blades inspect the content. | Blocked | DLP / TLS inspection |

<a id="app"></a>
## APP · L7 control and anomalies

### APP-01 · Port-independent application control

**Priority:** High  
**Objective:** The application is identified by protocol, not by port.  
**Firewall configuration needed:** HTTP/HTTPS services with protocol identification (not only the port) and SSH blocked as an application.  
_Check Point notes: App Control identifies applications on any port and egress only allows HTTP/HTTPS with protocol signature._  
_Check Point best practice: Inline egress layer with Application Control and URL Filtering, high-risk categories blocked and services matched by protocol signature._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| APP-01.1 | SSH tcp/22 to the Internet | Port and application not allowed. | Blocked | Firewall |
| APP-01.2 | SSH over tcp/443 | SSH over the HTTPS port (ssh.github.com). | Blocked | Application control |
| APP-01.3 | HTTP on tcp/8080 | Unauthorized port. | Blocked | Firewall |
| APP-01.4 | HTTP on tcp/8443 | Unauthorized port. | Blocked | Firewall |
| APP-01.5 | Cleartext HTTP on tcp/443 | Not TLS: does not match the HTTPS service with signature. | Blocked | Firewall |
| APP-01.6 | Control: HTTP on tcp/80 | Control: legitimate traffic, must not be blocked. | Allowed | Firewall |

### APP-02 · URL Filtering and App Control by category

**Priority:** High  
**Objective:** Category and action are logged.  
**Firewall configuration needed:** Gambling and Anonymizer categories and Facebook, TikTok, Dropbox and WeTransfer applications blocked; LinkedIn allowed.  
_Check Point notes: URL Filtering by category and App Control by application, over HTTP and HTTPS._  
_Check Point best practice: Block high-risk categories, anonymizers and P2P; UserCheck for medium-risk ones._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| APP-02.1 | Business site (allowed) | Control: legitimate traffic, must not be blocked. | Allowed | URL Filtering |
| APP-02.2 | bet365 (Gambling) over HTTP | Forbidden category. | Blocked | URL Filtering |
| APP-02.3 | pokerstars (Gambling) over HTTPS | Forbidden category. | Blocked | URL Filtering / TLS inspection |
| APP-02.4 | hidemyass (Anonymizer) | Anonymizer. | Blocked | URL Filtering |
| APP-02.5 | Facebook | Blocked application. | Blocked | Application control |
| APP-02.6 | TikTok | Blocked application. | Blocked | Application control |
| APP-02.7 | Dropbox | File sharing. | Blocked | Application control |
| APP-02.8 | WeTransfer | File sharing. | Blocked | Application control |
| APP-02.9 | LinkedIn (allowed) | Control: legitimate traffic, must not be blocked. | Allowed | Application control |

### APP-03 · Full URL vs domain/SNI

**Priority:** High  
**Objective:** Shows when the path is distinguished from the domain.  
**Firewall configuration needed:** Custom site with the configured blocked path (config.internet.blocked_path).  
_Check Point notes: With HTTPS Inspection the full URL is visible and a path can be blocked; without decryption only the domain._  
_Check Point best practice: Inline egress layer with Application Control and URL Filtering, high-risk categories blocked and services matched by protocol signature._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| APP-03.1 | Allowed path over HTTP | Control: legitimate traffic, must not be blocked. | Allowed | URL Filtering |
| APP-03.2 | Blocked path over HTTP | Path matches. | Blocked | URL Filtering |
| APP-03.3 | Allowed path over HTTPS | Control: legitimate traffic, must not be blocked. | Allowed | URL Filtering / TLS inspection |
| APP-03.4 | Blocked path over HTTPS | Only possible with decryption. | Blocked | URL Filtering / TLS inspection |

### APP-04 · DNS-independent filtering

**Priority:** High  
**Objective:** Covered surface is known: direct IP, no SNI, DoH and DoT.  
**Firewall configuration needed:** DoH application blocked; only DNS/HTTP/HTTPS on egress.  
_Check Point notes: Identification by Host, SNI and certificate; DoH blocked as an application and DoT by port._  
_Check Point best practice: Inline egress layer with Application Control and URL Filtering, high-risk categories blocked and services matched by protocol signature._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| APP-04.1 | Facebook by IP with Host header | No DNS query. | Blocked | Application control |
| APP-04.2 | Facebook by IP without SNI (HTTPS) | Classified by the certificate. | Blocked | Application control / TLS inspection |
| APP-04.3 | DNS over HTTPS | DoH application. | Blocked | Application control |
| APP-04.4 | DNS over TLS (tcp/853) | DoT on its standard port. | Blocked | Firewall |

### APP-05 · Anomalous traffic baseline

**Priority:** Critical · _Manual_  
**Objective:** Normal behaviour is established and deviations are detected.  
**Firewall configuration needed:** At least one week of logs.  
_Check Point notes: SmartEvent / Infinity XDR/XPR with anomaly correlation; Logs & Monitor views by application and volume._  
_Check Point best practice: Inline egress layer with Application Control and URL Filtering, high-risk categories blocked and services matched by protocol signature._

**Procedure:**

1. With one week of logs, get the top applications, destinations and volumes per environment.
2. Generate a deviation (e.g. a large night transfer to a new destination with the kit).
3. Check it shows up in anomaly reports/alerts.

**Expected result:** The deviation is detected and can be investigated.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### APP-06 · Spikes, beaconing and anomalous connections

**Priority:** High · _Manual_  
**Objective:** Beaconing patterns and connection spikes are detected.  
**Firewall configuration needed:** Anti-bot enabled and event correlation.  
_Check Point notes: Anti-Bot (C&C behaviour) + SmartEvent/Infinity XDR; IPS «Port Scan» protection._  
_Check Point best practice: Inline egress layer with Application Control and URL Filtering, high-risk categories blocked and services matched by protocol signature._

**Procedure:**

1. From a client, generate a periodic connection (every 60 s, same size) to an external destination for 1 h.
2. Generate a connection spike (e.g. PERF-06) and a scan (IPS-02).
3. Review which events are raised and their severity.

**Expected result:** Beaconing, spike and scan identified with evidence.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### APP-07 · Unexpected outbound connections

**Priority:** High  
**Objective:** A server cannot open connections to unexpected destinations and ports.  
**Firewall configuration needed:** Egress layer with a Drop cleanup.  
_Check Point notes: Default-deny egress; every attempt is logged._  
_Check Point best practice: Inline egress layer with Application Control and URL Filtering, high-risk categories blocked and services matched by protocol signature._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| APP-07.1 | SQL Server tcp/1433 to the Internet | Unexpected port to the Internet. | Blocked | Firewall |
| APP-07.2 | MySQL tcp/3306 to the Internet | Unexpected port to the Internet. | Blocked | Firewall |
| APP-07.3 | PostgreSQL tcp/5432 to the Internet | Unexpected port to the Internet. | Blocked | Firewall |
| APP-07.4 | SMTP tcp/25 to the Internet | Unexpected port to the Internet. | Blocked | Firewall |
| APP-07.5 | SMB tcp/445 to the Internet | Unexpected port to the Internet. | Blocked | Firewall |

### APP-08 · Rate limiting and basic abuse mitigation

**Priority:** Medium · _Manual_  
**Objective:** The connection rate of an abusive source can be limited.  
**Firewall configuration needed:** Rate limiting capability on the firewall.  
_Check Point notes: Rate limiting with «fw samp add quota» (sk112454) or IPS flood protections._  
_Check Point best practice: Inline egress layer with Application Control and URL Filtering, high-risk categories blocked and services matched by protocol signature._

**Procedure:**

1. Configure a connections-per-second limit per source towards the test server.
2. Run PERF-05 (CPS) from a client and check the rate is limited and logged.
3. Remove the limit and repeat to compare.

**Expected result:** Rate limited to the configured value and event logged.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

<a id="dlp"></a>
## DLP · Data loss prevention

### DLP-01 · Sensitive data transfer

**Priority:** Medium  
**Objective:** Synthetic sensitive patterns are detected and blocked.  
**Firewall configuration needed:** DLP (content inspection) rules (PCI, IBAN, executables) between environments over HTTP and HTTPS.  
_Check Point notes: Content Awareness with PCI and IBAN data types and executable file type._  
_Check Point best practice: Content Awareness on east-west and egress rules, with HTTPS decrypted._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| DLP-01.1 | Benign file upload | Control: legitimate traffic, must not be blocked. | Allowed | DLP |
| DLP-01.2 | Card numbers upload (PCI) | DLP (content inspection) inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | DLP |
| DLP-01.3 | IBAN upload | DLP (content inspection) inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | DLP |
| DLP-01.4 | Card numbers download (PCI) | DLP (content inspection) inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | DLP |
| DLP-01.5 | Executable download | Executable file type. | Blocked | DLP |

### DLP-02 · Minimal-scope DLP exceptions

**Priority:** Medium  
**Objective:** The exception applies only to the approved asset and direction.  
**Firewall configuration needed:** dlp_exception_client role and exception rule with direction 'up'.  
_Check Point notes: Exception rule (upload only, from dlp_exception_client to the server) above the blocking rule._  
_Check Point best practice: Content Awareness on the network layer with predefined data types (PCI, IBAN) and exceptions by asset and direction._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| DLP-02.1 | PCI upload from the excepted asset (only from role `dlp_exception_client`) | In scope. | Allowed | DLP |
| DLP-02.2 | PCI upload from another asset | Same file and destination from another asset. | Blocked | DLP |
| DLP-02.3 | PCI download to the excepted asset (only from role `dlp_exception_client`) | The exception only covers uploads. | Blocked | DLP |

### DLP-03 · DLP on encrypted traffic and object sizes

**Priority:** Medium  
**Objective:** Limits by format, encryption and size are documented.  
**Firewall configuration needed:** DLP (content inspection) rules (PCI, IBAN, executables) between environments over HTTP and HTTPS.  
_Check Point notes: Content Awareness on decrypted HTTPS, large files and Office._  
_Check Point best practice: Content Awareness on the network layer with predefined data types (PCI, IBAN) and exceptions by asset and direction._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| DLP-03.1 | PCI upload over HTTPS | DLP (content inspection) inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | DLP / TLS inspection |
| DLP-03.2 | PCI download over HTTPS | DLP (content inspection) inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | DLP / TLS inspection |
| DLP-03.3 | PCI at the end of a 2 MB file | DLP (content inspection) inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | DLP |
| DLP-03.4 | PCI inside a .docx | DLP (content inspection) inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | DLP |
| DLP-03.5 | Executable over HTTPS | DLP (content inspection) inspects transferred content (upload and download) and blocks synthetic sensitive data. | Blocked | DLP / TLS inspection |

<a id="waf"></a>
## WAF · Complementary web protection

### WAF-01 · SQLi and XSS (WAF coverage)

**Priority:** Medium  
**Objective:** Documents what the IPS covers and what needs a WAF.  
**Firewall configuration needed:** IPS in Prevent.  
_Check Point notes: IPS covers common web attack classes. Full application and API protection (including tautologies in forms and JSON) belongs to Check Point CloudGuard WAF._  
_Check Point best practice: IPS for the network; published web apps and APIs behind CloudGuard WAF._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| WAF-01.1 | SQLi in GET parameter | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| WAF-01.2 | Reflected XSS | HTTP request to the test server carrying a well-known attack pattern: IPS in Prevent must drop the connection. | Blocked | IPS |
| WAF-01.3 | SQL tautology in POST form (informative) | WAF-specific class: informative. | Blocked | IPS → WAF |
| WAF-01.4 | SQL tautology in JSON (API) (informative) | WAF-specific class: informative. | Blocked | IPS → WAF |

### WAF-02 · WAF policy exceptions, tuning and updates

**Priority:** Medium · _Manual_ · _needs extra infrastructure_  
**Objective:** The WAF is tuned without opening gaps and updates itself.  
**Firewall configuration needed:** Outside the reference lab: needs a web application published behind a WAF.  
_Check Point notes: CloudGuard WAF (contextual machine-learning engine, no signatures to maintain) with per-parameter exceptions._  
_Check Point best practice: IPS for the network; published web apps and APIs behind CloudGuard WAF._

**Procedure:**

1. Publish a test application with WAF in learning and then prevention mode.
2. Generate a false positive and create a narrow exception (parameter/URL).
3. Repeat the WAF-01 attacks and check they are still blocked.

**Expected result:** Narrow exception and attacks blocked.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### WAF-03 · API / HTTP and TLS protection

**Priority:** Medium · _Manual_ · _needs extra infrastructure_  
**Objective:** Published APIs are protected by schema and against abuse.  
**Firewall configuration needed:** Outside the reference lab: needs an API published behind a WAF.  
_Check Point notes: CloudGuard WAF with OpenAPI schema validation and rate limiting._  
_Check Point best practice: IPS for the network; published web apps and APIs behind CloudGuard WAF._

**Procedure:**

1. Publish an API with its OpenAPI schema behind the WAF.
2. Send out-of-schema requests, JSON injections and rate abuse.
3. Check blocks and logs.

**Expected result:** Out-of-schema requests and abuse blocked.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

<a id="obs"></a>
## OBS · Visibility and audit

### OBS-01 · Allow/deny logs per connection

**Priority:** Critical · _control agent_  
**Objective:** Every allowed or denied connection leaves a complete, searchable log.  
**Firewall configuration needed:** Logging enabled on the segmentation and cleanup rules.  
_Check Point notes: A client opens an allowed (tcp/80) and a denied (tcp/22) connection to the server and the control agent finds them in the logs through the API, measuring how long they take to show up and which fields they carry._  
_Check Point best practice: Logging on every rule; on high-volume rules use accounting if the SIEM requires it._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| OBS-01.1 | Log of an allowed and a denied connection | Fields: time, action, rule, layer, source, destination, service and gateway. | Criterion met | Logging |

### OBS-02 · Traceability of NGFW protections

**Priority:** Critical · _control agent_  
**Objective:** IPS, anti-malware and URL filtering events identify the protection, severity, confidence and rule.  
**Firewall configuration needed:** IPS, anti-malware and URL filtering in Prevent with logging.  
_Check Point notes: A client generates an SQLi attack, an EICAR download and an access to a blocked FQDN; the control agent finds the events and checks their fields._  
_Check Point best practice: Logging on every rule, Log Exporter to the SIEM and SmartEvent/Infinity Events; packet capture on threat rules._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| OBS-02.1 | IPS, anti-malware and URL events | The event must name the protection and its severity. | Criterion met | Logging |

### OBS-03 · Audit of API/UI/IaC changes

**Priority:** High · _Manual_  
**Objective:** Every configuration change is logged with who, what and when.  
**Firewall configuration needed:** Management audit log enabled.  
_Check Point notes: Logs & Monitor → Audit; one API key per automation (never shared) and a descriptive session name._  
_Check Point best practice: Logging on every rule, Log Exporter to the SIEM and SmartEvent/Infinity Events; packet capture on threat rules._

**Procedure:**

1. Make a change from the console, another through the API (e.g. OPS-03) and another with Terraform.
2. Find the three in the audit log and compare the details (user/API key, session, object, before/after).

**Expected result:** The three changes appear with author, time and detail.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### OBS-04 · SIEM export and event quality

**Priority:** Critical · _Manual_  
**Objective:** Events reach the SIEM complete, normalized and on time.  
**Firewall configuration needed:** SIEM or syslog collector reachable from the management.  
_Check Point notes: Log Exporter (CEF, LEEF, JSON) or Infinity Events SIEM connectors; TLS to the collector._  
_Check Point best practice: Logging on every rule, Log Exporter to the SIEM and SmartEvent/Infinity Events; packet capture on threat rules._

**Procedure:**

1. Configure log export (syslog CEF/LEEF or API) to the SIEM.
2. Run OBS-01 and OBS-02 and find those events in the SIEM.
3. Measure latency and compare fields with the original log.

**Expected result:** Complete events in the SIEM with measured latency.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### OBS-05 · Correlation with VPC/TGW Flow Logs

**Priority:** High · _Manual_  
**Objective:** Firewall logs can be matched with cloud flow logs.  
**Firewall configuration needed:** Flow logs enabled on spoke VPCs and the TGW.  
_Check Point notes: GWLB preserves the source IP; keep clocks on NTP to correlate._  
_Check Point best practice: Logging on every rule, Log Exporter to the SIEM and SmartEvent/Infinity Events; packet capture on threat rules._

**Procedure:**

1. Enable VPC/TGW Flow Logs.
2. Run NET-01 and find the same connection (5-tuple and time) in both logs.
3. Check that source IPs are preserved (no NAT on the east-west path).

**Expected result:** The same connection is identified in both logs.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### OBS-06 · Packet capture and session diagnostics

**Priority:** High · _Manual_  
**Objective:** A given session can be captured and diagnosed.  
**Firewall configuration needed:** Administrative access to the gateways.  
_Check Point notes: «fw monitor -F» / «tcpdump», «fw ctl zdebug drop» and packet capture in logs (track-settings packet capture)._  
_Check Point best practice: Logging on every rule, Log Exporter to the SIEM and SmartEvent/Infinity Events; packet capture on threat rules._

**Procedure:**

1. Start a capture filtered by a client IP on the gateway.
2. Run a kit check and download the capture.
3. Use the decision debugging tool to see which rule applied.

**Expected result:** Capture and diagnosis obtained without service interruption.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### OBS-07 · Asset, tag, VPC, account and region visibility

**Priority:** High · _Manual_  
**Objective:** Logs and console show the cloud context of the asset.  
**Firewall configuration needed:** Cloud connector configured.  
_Check Point notes: CloudGuard Controller data center objects in rules and logs; CloudGuard CNAPP for full inventory._  
_Check Point best practice: Logging on every rule, Log Exporter to the SIEM and SmartEvent/Infinity Events; packet capture on threat rules._

**Procedure:**

1. Check in the console the asset inventory imported from the cloud.
2. Open a kit log and check whether it shows instance name, tags, VPC, account or region.

**Expected result:** Cloud context visible to investigate without leaving the console.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### OBS-08 · Health, resources and alert monitoring

**Priority:** High · _control agent_  
**Objective:** The state of every gateway is known and alerts are configured.  
**Firewall configuration needed:** Control agent running with cloud credentials (read; HA checks change the Auto Scaling group and network ACLs) and Management API credentials.  
_Check Point notes: Cloud: state of the Auto Scaling group and load balancer targets, CPU metrics and alarms. Gateways: CPU, memory, connections, disk and processes._  
_Check Point best practice: CloudWatch alarms for CPU (scaling) and unhealthy GWLB targets; SNMPv3/Gaia monitoring._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| OBS-08.1 | Cloud health and alarms | Healthy targets, metrics and at least one alarm. | Criterion met | Monitoring |
| OBS-08.2 | Gateway health | No process down. | Criterion met | Monitoring |

### OBS-09 · Logs under load and retention

**Priority:** High · _Manual_  
**Objective:** No logs are lost under high load and retention meets the requirement.  
**Firewall configuration needed:** PERF-05/PERF-06 load available.  
_Check Point notes: Smart-1 Cloud: retention per subscription; logs buffered on the gateway if the management connection is lost._  
_Check Point best practice: Logging on every rule, Log Exporter to the SIEM and SmartEvent/Infinity Events; packet capture on threat rules._

**Procedure:**

1. Run PERF-05 (thousands of new connections) and count the connections generated.
2. Count the matching logs in the console and compute the percentage.
3. Review the contracted/configured retention policy.

**Expected result:** ≥ 99 % of logs and documented retention.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### OBS-10 · Syslog/SNMP/NetFlow telemetry

**Priority:** Medium · _Manual_  
**Objective:** The firewall exports standard telemetry.  
**Firewall configuration needed:** Syslog/SNMP/NetFlow collectors.  
_Check Point notes: Gaia: SNMPv3, NetFlow export and remote syslog; on autoscaling gateways apply them through the bootstrap script or CME template._  
_Check Point best practice: Logging on every rule, Log Exporter to the SIEM and SmartEvent/Infinity Events; packet capture on threat rules._

**Procedure:**

1. Configure SNMP (v3), NetFlow/IPFIX and system syslog on the gateways.
2. Check in the collectors that data arrives and matches the kit load.

**Expected result:** Telemetry received and consistent.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### OBS-11 · Investigation reports and filtered search

**Priority:** Medium · _Manual_  
**Objective:** What happened with an asset or attack is found quickly.  
**Firewall configuration needed:** Logs of a full kit run.  
_Check Point notes: Logs & Monitor (saved queries), Infinity Events/SmartEvent reports._  
_Check Point best practice: Logging on every rule, Log Exporter to the SIEM and SmartEvent/Infinity Events; packet capture on threat rules._

**Procedure:**

1. After a full run, search by source IP, protection and time range.
2. Generate a threat report for the period and export it.

**Expected result:** Searches in seconds and exportable report.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

<a id="ha"></a>
## HA · Availability and resilience

### HA-01 · Inspection instance failure

**Priority:** Critical · _control agent_  
**Objective:** The loss of a gateway is detected, the service continues and the group replaces it with the policy applied.  
**Firewall configuration needed:** Auto Scaling group with at least 2 gateways in 2 AZs behind the Gateway Load Balancer. Control agent with permissions on the group and the network ACLs. All clients online (continuous probes).  
_Check Point notes: A gateway is terminated in the Auto Scaling group. Measured: detection by the GWLB, launch and registration of the replacement, registration in the management with policy (CME) and removal of the old object. While the event lasts, every client probes the server (east-west), the Internet and a denied flow once per second; the longest interruption is measured and the denied flow must never pass. Failures are simulated reversibly: network ACL deny of the gateway IP (/32) and health processes of the group suspended during the test._  
_Check Point best practice: n+1 minimum per AZ and GWLB health check on the gateway port (8117)._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| HA-01.1 | Terminate a gateway and measure the recovery | Criterion: replacement in service with policy and interruption ≤ ha.max_outage_s. | Criterion met | Availability |

### HA-02 · Availability Zone failure

**Priority:** Critical · _control agent_  
**Objective:** If the gateways of one AZ fail, those of the other AZ keep the service.  
**Firewall configuration needed:** Auto Scaling group with at least 2 gateways in 2 AZs behind the Gateway Load Balancer. Control agent with permissions on the group and the network ACLs. All clients online (continuous probes).  
_Check Point notes: All the gateways of one AZ are isolated for ha.isolation_s and restored. Cross-zone load balancing and GWLB unhealthy-target behaviour are reported. While the event lasts, every client probes the server (east-west), the Internet and a denied flow once per second; the longest interruption is measured and the denied flow must never pass. Failures are simulated reversibly: network ACL deny of the gateway IP (/32) and health processes of the group suspended during the test._  
_Check Point best practice: Cross-zone enabled on the GWLB so an AZ without gateways uses the other AZ's._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| HA-02.1 | Isolate the gateways of one AZ | Criterion: interruption ≤ ha.max_outage_s and recovery after restoring. | Criterion met | Availability |

### HA-03 · Fail-closed behaviour on inspection failure

**Priority:** Critical · _control agent_  
**Objective:** If no inspection is available, traffic stops: it never passes uninspected.  
**Firewall configuration needed:** Auto Scaling group with at least 2 gateways in 2 AZs behind the Gateway Load Balancer. Control agent with permissions on the group and the network ACLs. All clients online (continuous probes).  
_Check Point notes: All the gateways are isolated at once (inspection data plane down) and any flow that still passes is counted; then they are restored and the recovery is measured. While the event lasts, every client probes the server (east-west), the Internet and a denied flow once per second; the longest interruption is measured and the denied flow must never pass. Failures are simulated reversibly: network ACL deny of the gateway IP (/32) and health processes of the group suspended during the test._  
_Check Point best practice: ASG in ≥ 2 AZs with an n+1 minimum, GWLB cross-zone, CME with template and policy, and update check (THR-06) on every new gateway._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| HA-03.1 | Isolate the whole inspection tier | Criterion: zero uninspected flows and recovery after restoring. | Criterion met | Availability |

### HA-04 · Failover and stateful session persistence

**Priority:** Critical · _control agent_  
**Objective:** Documents which established sessions survive the loss of a gateway.  
**Firewall configuration needed:** Auto Scaling group with at least 2 gateways in 2 AZs behind the Gateway Load Balancer. Control agent with permissions on the group and the network ACLs. All clients online (continuous probes).  
_Check Point notes: Every client keeps 20 HTTP keep-alive sessions (one request every 2 s) during the gateway loss of HA-01/HA-02 (or its own isolation when run alone) and the surviving ones are counted._  
_Check Point best practice: Sessions on the lost gateway are cut (no state sync in autoscaling): applications with retries; «target failover rebalance» speeds up flow failover._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| HA-04.1 | Long sessions during a gateway loss | Measure: surviving and cut sessions. | Measure | Availability |

### HA-05 · Horizontal scale-out and back

**Priority:** High · _control agent_  
**Objective:** A new gateway goes into service with policy without cutting traffic and is removed cleanly.  
**Firewall configuration needed:** Auto Scaling group with at least 2 gateways in 2 AZs behind the Gateway Load Balancer. Control agent with permissions on the group and the network ACLs. All clients online (continuous probes).  
_Check Point notes: The desired capacity of the group is raised by one (protecting the existing gateways), the scale-out is measured (instance, healthy target, registration with policy) and the group goes back to the initial capacity measuring the scale-in (deregistration, termination, object removed). While the event lasts, every client probes the server (east-west), the Internet and a denied flow once per second; the longest interruption is measured and the denied flow must never pass. Failures are simulated reversibly: network ACL deny of the gateway IP (/32) and health processes of the group suspended during the test._  
_Check Point best practice: CPU scaling policy (e.g. 70 %/30 %) and CME with the template so each new gateway gets the policy._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| HA-05.1 | Scale +1 and back | Includes the configured scaling policies. | Criterion met | Availability |

### HA-06 · Blue/green upgrade and maintenance

**Priority:** High · _Manual_  
**Objective:** Gateway versions are upgraded without service interruption.  
**Firewall configuration needed:** Versioned launch template of the Auto Scaling group.  
_Check Point notes: Instance refresh with «minimum healthy 100 %» or blue/green group; CME provisions the new gateways with the same template._  
_Check Point best practice: ASG in ≥ 2 AZs with an n+1 minimum, GWLB cross-zone, CME with template and policy, and update check (THR-06) on every new gateway._

**Procedure:**

1. With the HA probes running, change the image/version in the group template.
2. Start an instance refresh (or a new parallel group) and let gateways be replaced one at a time.
3. Measure interruptions and confirm version and policy of the new gateways.

**Expected result:** Progressive replacement without interruption above the HA threshold.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### HA-07 · Resilience to DNS or control plane failure

**Priority:** High · _Manual_  
**Objective:** If the management or DNS fails, traffic is still inspected with the last policy.  
**Firewall configuration needed:** Ability to cut the gateway–management connection in a controlled way.  
_Check Point notes: The gateway keeps the local policy and buffers logs; domain rules depend on the gateway DNS (use redundant resolvers)._  
_Check Point best practice: ASG in ≥ 2 AZs with an n+1 minimum, GWLB cross-zone, CME with template and policy, and update check (THR-06) on every new gateway._

**Procedure:**

1. Temporarily cut the gateways' connection to the management (egress rule or NACL).
2. Run a short kit batch (NET-01, IPS-01, TLS-01) and check decisions and that logs are buffered.
3. Restore and check the pending logs arrive; repeat cutting the gateways' DNS.

**Expected result:** Policy enforced without management or DNS; logs recovered.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### HA-08 · Disaster recovery and restore

**Priority:** Medium · _Manual_  
**Objective:** The whole deployment can be rebuilt from code and backups.  
**Firewall configuration needed:** Infrastructure as code and management backup.  
_Check Point notes: Terraform with the official modules + policy as code; Smart-1 Cloud with service-managed backups._  
_Check Point best practice: ASG in ≥ 2 AZs with an n+1 minimum, GWLB cross-zone, CME with template and policy, and update check (THR-06) on every new gateway._

**Procedure:**

1. Destroy the inspection tier (or deploy in another region) with the infrastructure code.
2. Recreate, let the management provision the gateways and install the policy.
3. Run the full batch and measure the total time (RTO).

**Expected result:** Environment recovered with the same results; RTO measured.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

<a id="perf"></a>
## PERF · Performance and capacity

### PERF-01 · Throughput with L3/L4 policy

**Priority:** Critical  
**Objective:** Measures throughput through the firewall with access control only.  
**Firewall configuration needed:** Role «perf_client»: one client runs the measurements (the iperf3 server serves one test at a time). Exception port (iperf3 TCP/UDP) allowed between environments without threat inspection.  
_Check Point notes: iperf3 to the exception port (allowed between environments and excluded from threat prevention): upload and download with 4 streams and a single stream (per-flow limit)._  
_Check Point best practice: Size with the real profile; compute-optimized instances; SecureXL/CoreXL and Dynamic Balancing enabled; scale on CPU._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| PERF-01.1 | TCP upload, 4 streams, 20 s (only from role `perf_client`) | Aggregate throughput client → server. | Measure | Performance |
| PERF-01.2 | TCP download, 4 streams, 20 s (only from role `perf_client`) | Server → client (-R). | Measure | Performance |
| PERF-01.3 | Single TCP stream, 20 s (only from role `perf_client`) | One flow always lands on the same gateway and core: per-flow limit. | Measure | Performance |

### PERF-02 · Throughput with IPS and advanced protection

**Priority:** Critical  
**Objective:** Measures throughput with every inspection capability enabled.  
**Firewall configuration needed:** Role «perf_client»: one client runs the measurements (the iperf3 server serves one test at a time). Exception port (iperf3 TCP/UDP) allowed between environments without threat inspection.  
_Check Point notes: Parallel downloads of a 200 MB file over HTTP (IPS, anti-malware, DLP) and over decrypted and not decrypted HTTPS, from the test server._  
_Check Point best practice: Measure with the production profile; with TLS, size by the decrypted figure._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| PERF-02.1 | Inspected HTTP, 4 parallel downloads (only from role `perf_client`) | Full threat profile. | Measure | Performance / IPS / Anti-malware |
| PERF-02.2 | Decrypted HTTPS, 4 parallel downloads (only from role `perf_client`) | TLS inspection plus full profile. | Measure | Performance / TLS inspection |
| PERF-02.3 | Not decrypted HTTPS, 4 parallel downloads (only from role `perf_client`) | Reference without decryption. | Measure | Performance / TLS inspection (bypass) |

### PERF-03 · Latency and jitter p50/p95/p99

**Priority:** Critical  
**Objective:** Measures the latency added by the inspection path.  
**Firewall configuration needed:** Role «perf_client»: one client runs the measurements (the iperf3 server serves one test at a time). Exception port (iperf3 TCP/UDP) allowed between environments without threat inspection.  
_Check Point notes: 200 samples of ICMP echo, TCP handshake and full HTTP request to the test server._  
_Check Point best practice: Size with the real profile; compute-optimized instances; SecureXL/CoreXL and Dynamic Balancing enabled; scale on CPU._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| PERF-03.1 | ICMP (200 echoes) (only from role `perf_client`) | Network round trip. | Measure | Performance |
| PERF-03.2 | TCP handshake (200) (only from role `perf_client`) | Includes the firewall decision for every new connection. | Measure | Performance |
| PERF-03.3 | Full HTTP request (200) (only from role `perf_client`) | Includes content inspection. | Measure | Performance |

### PERF-04 · Concurrent connections

**Priority:** High  
**Objective:** The firewall keeps many sessions open at the same time.  
**Firewall configuration needed:** Role «perf_client»: one client runs the measurements (the iperf3 server serves one test at a time). Exception port (iperf3 TCP/UDP) allowed between environments without threat inspection.  
_Check Point notes: 2000 TCP sessions open at the same time from one client, each one used, held for 30 s and used again._  
_Check Point best practice: Size with the real profile; compute-optimized instances; SecureXL/CoreXL and Dynamic Balancing enabled; scale on CPU._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| PERF-04.1 | 2000 concurrent sessions (only from role `perf_client`) | State table capacity (limited by a single client). | Measure | Performance |

### PERF-05 · New connections per second (CPS)

**Priority:** High  
**Objective:** Measures the rate of new connections processed by the firewall.  
**Firewall configuration needed:** Role «perf_client»: one client runs the measurements (the iperf3 server serves one test at a time). Exception port (iperf3 TCP/UDP) allowed between environments without threat inspection.  
_Check Point notes: Short HTTP requests (connect, GET, close) with 64 in parallel for 20 s._  
_Check Point best practice: Size with the real profile; compute-optimized instances; SecureXL/CoreXL and Dynamic Balancing enabled; scale on CPU._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| PERF-05.1 | Sustained CPS 20 s (only from role `perf_client`) | Measured from one client: a lower bound, not the firewall maximum. | Measure | Performance |

### PERF-06 · Bursts and sustained load

**Priority:** High  
**Objective:** Throughput stays stable under continuous load and absorbs bursts.  
**Firewall configuration needed:** Role «perf_client»: one client runs the measurements (the iperf3 server serves one test at a time). Exception port (iperf3 TCP/UDP) allowed between environments without threat inspection.  
_Check Point notes: iperf3 sustained for 120 s (min, average and max per second, retransmissions), a burst of 16 streams and a burst of new connections._  
_Check Point best practice: Size with the real profile; compute-optimized instances; SecureXL/CoreXL and Dynamic Balancing enabled; scale on CPU._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| PERF-06.1 | Sustained load 120 s (only from role `perf_client`) | Second-by-second stability. | Measure | Performance |
| PERF-06.2 | Burst of 16 streams, 15 s (only from role `perf_client`) | Spread across gateways and cores. | Measure | Performance |
| PERF-06.3 | Connection burst (256 in parallel, 10 s) (only from role `perf_client`) | Peak of new connections. | Measure | Performance |

### PERF-07 · Packet size and TCP/UDP

**Priority:** High  
**Objective:** Documents performance with small and large packets over TCP and UDP.  
**Firewall configuration needed:** Role «perf_client»: one client runs the measurements (the iperf3 server serves one test at a time). Exception port (iperf3 TCP/UDP) allowed between environments without threat inspection.  
_Check Point notes: iperf3 UDP at 300 Mbit/s with 64, 512 and 1400-byte datagrams (packets per second, loss, jitter) and TCP with a 536-byte MSS._  
_Check Point best practice: Size with the real profile; compute-optimized instances; SecureXL/CoreXL and Dynamic Balancing enabled; scale on CPU._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| PERF-07.1 | UDP 64 bytes (only from role `perf_client`) | Small packets: packets-per-second limit. | Measure | Performance |
| PERF-07.2 | UDP 512 bytes (only from role `perf_client`) | Medium size. | Measure | Performance |
| PERF-07.3 | UDP 1400 bytes (only from role `perf_client`) | Close to the MTU (with GENEVE). | Measure | Performance |
| PERF-07.4 | TCP with MSS 536 (only from role `perf_client`) | Small TCP segments. | Measure | Performance |

### PERF-08 · Resource usage and cost per load

**Priority:** High · _control agent_  
**Objective:** Relates load with gateway resource usage and cost.  
**Firewall configuration needed:** Control agent running with cloud credentials (read; HA checks change the Auto Scaling group and network ACLs) and Management API credentials.  
_Check Point notes: The control agent runs load from the performance client (iperf3 and inspected HTTP downloads) while sampling the gateways' CPU every 5 s and in CloudWatch, and computes the compute cost per hour with the Pricing API._  
_Check Point best practice: Size with the real profile; compute-optimized instances; SecureXL/CoreXL and Dynamic Balancing enabled; scale on CPU._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| PERF-08.1 | CPU and cost under load | Combined load, CPU and cost measure. | Measure | Performance / Cost |

<a id="ops"></a>
## OPS · Operations and governance

### OPS-01 · Automated onboarding and least privilege

**Priority:** High · _control agent_  
**Objective:** The management reads the account with a read-only, scoped role.  
**Firewall configuration needed:** aws.cme_role_arn set on the control agent.  
_Check Point notes: Analyses the role the management (CME) uses to discover the Auto Scaling group: allowed actions, wildcards, trusted principal and ExternalId._  
_Check Point best practice: Read-only STS role with ExternalId for CME/CloudGuard Controller; no long-lived access keys._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| OPS-01.1 | Permissions of the management role | No wildcards or writes, with ExternalId. | Criterion met | Operations |

### OPS-02 · RBAC/SSO/MFA administration

**Priority:** Critical · _Manual_  
**Objective:** Administrators log in with SSO and MFA and least-privilege profiles.  
**Firewall configuration needed:** Corporate identity provider (SAML/OIDC).  
_Check Point notes: Infinity Portal with SSO (SAML) and MFA; permission profiles per layer and domain._  
_Check Point best practice: Smart-1 Cloud with SSO+MFA, policy as code and per-automation API keys with least privileges._

**Procedure:**

1. Integrate the portal/management with the corporate IdP over SAML and require MFA.
2. Create a read-only profile and a policy operator profile; test each can only do its part.
3. Check the audit log shows the real user of each action.

**Expected result:** SSO+MFA enforced and separated permissions verified.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### OPS-03 · Policies through API, Terraform and CI/CD

**Priority:** High · _control agent_  
**Objective:** A policy change made through the API is enforced end to end and rolled back.  
**Firewall configuration needed:** Write access to the Management API (TK_ objects and test gateways only).  
_Check Point notes: A temporary rule blocking HTTPS from a client to the server is added through the API, published and installed; the time to block is measured; then it is removed, reinstalled and the time to recover is measured._  
_Check Point best practice: Check Point Terraform provider or API with publish and install in the pipeline and peer review._

| ID | Check | What it does | Expected | Capability |
|---|---|---|---|---|
| OPS-03.1 | API change and rollback, measured | Installs the access policy twice on the test gateways. | Criterion met | Operations |

### OPS-04 · Centralized multi-account/tenant management

**Priority:** High · _Manual_  
**Objective:** One console manages several accounts and environments with separation.  
**Firewall configuration needed:** At least two accounts or environments.  
_Check Point notes: CME with several accounts/templates; Multi-Domain on Smart-1 Cloud when tenant separation is needed._  
_Check Point best practice: Smart-1 Cloud with SSO+MFA, policy as code and per-automation API keys with least privileges._

**Procedure:**

1. Register several accounts in the autoscaling/cloud connector.
2. Assign different policy packages or domains and check an administrator of one cannot see the other.

**Expected result:** Central management with verified separation.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### OPS-05 · Versions, backup and rollback

**Priority:** High · _Manual_  
**Objective:** A previous policy or software version can be restored.  
**Firewall configuration needed:** Policy revision history.  
_Check Point notes: Installation History → «Install specific version»; revisions are kept automatically._  
_Check Point best practice: Smart-1 Cloud with SSO+MFA, policy as code and per-automation API keys with least privileges._

**Procedure:**

1. Publish and install a change and then revert to the previous revision from the history.
2. Verify with the kit that the behaviour returns to the previous one.

**Expected result:** Full rollback in minutes, verified.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### OPS-06 · Operational experience adding/removing/changing rules

**Priority:** High · _Manual_  
**Objective:** Routine tasks are quick and low-risk.  
**Firewall configuration needed:** Customer operators with console access.  
_Check Point notes: Sessions with change view, «Where used» object search and sections in the layers (as the kit creates)._  
_Check Point best practice: Smart-1 Cloud with SSO+MFA, policy as code and per-automation API keys with least privileges._

**Procedure:**

1. A customer operator adds, changes and removes a rule in the console, timing each task.
2. Check validations (conflicts, duplicate objects) and the change preview before publishing.

**Expected result:** Times and operator assessment documented.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### OPS-07 · Exception governance and ITSM traceability

**Priority:** Critical · _Manual_  
**Objective:** Every exception is linked to a ticket and reviewed periodically.  
**Firewall configuration needed:** Corporate ITSM tool.  
_Check Point notes: Ticket field in the session/rule, ITSM integration through the API and expiry with time objects._  
_Check Point best practice: Smart-1 Cloud with SSO+MFA, policy as code and per-automation API keys with least privileges._

**Procedure:**

1. Create an exception with the ticket number in the comment/session.
2. Check you can go from the ticket to the rule and back.
3. List expired exceptions or those without ticket.

**Expected result:** All exceptions traceable and reviewable.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### OPS-08 · Tagging, continuous discovery and policy onboarding

**Priority:** High · _Manual_  
**Objective:** New assets are discovered and get policy according to their tag.  
**Firewall configuration needed:** Tag convention (environment, application, criticality).  
_Check Point notes: CloudGuard Controller + cleanup rule in Drop with logging._  
_Check Point best practice: Smart-1 Cloud with SSO+MFA, policy as code and per-automation API keys with least privileges._

**Procedure:**

1. Define the tag convention and create dynamic objects for each value.
2. Deploy a new tagged asset and check it gets the expected policy (see POL-08).
3. Detect untagged assets and their default handling (deny).

**Expected result:** Automatic onboarding by tag; untagged assets denied.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### OPS-09 · Management credentials and secrets control

**Priority:** High · _Manual_  
**Objective:** Management and automation credentials are protected and rotated.  
**Firewall configuration needed:** Corporate secrets manager.  
_Check Point notes: One API key per integration with least privileges; STS roles (no long-lived keys) for the cloud connector._  
_Check Point best practice: Smart-1 Cloud with SSO+MFA, policy as code and per-automation API keys with least privileges._

**Procedure:**

1. Inventory API keys, cloud credentials and SIC/provisioning keys.
2. Check they are stored in a secrets manager, never in plain text in code or repositories.
3. Rotate an API key and check the automation keeps working.

**Expected result:** No clear-text secrets and rotation tested.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

<a id="int"></a>
## INT · Integrations

### INT-01 · Entra ID integration for administrative access

**Priority:** Medium · _Manual_  
**Objective:** Administrators authenticate with Entra ID.  
**Firewall configuration needed:** Entra ID tenant with a SAML enterprise application.  
_Check Point notes: Infinity Portal → Identity providers → Entra ID (SAML)._  
_Check Point best practice: SAML IdP in Infinity Portal and Management API for SOAR/ITSM._

**Procedure:**

1. Create the SAML application in Entra ID and configure it as IdP of the management portal.
2. Map groups to permission profiles and test access with conditional MFA.

**Expected result:** Access with Entra ID and group-based profiles.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### INT-02 · PingID/PingOne integration for administrators

**Priority:** Medium · _Manual_  
**Objective:** Administrators authenticate with PingOne.  
**Firewall configuration needed:** PingOne environment with a SAML application.  
_Check Point notes: Infinity Portal supports any SAML 2.0 IdP._  
_Check Point best practice: SAML IdP in Infinity Portal and Management API for SOAR/ITSM._

**Procedure:**

1. Configure PingOne as SAML IdP of the management portal.
2. Test access with PingID MFA and group mapping.

**Expected result:** Access with PingOne and MFA.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### INT-03 · Alerts and cases to ServiceNow

**Priority:** Medium · _Manual_  
**Objective:** Critical events open cases in the ITSM.  
**Firewall configuration needed:** ITSM instance with API.  
_Check Point notes: Infinity Events / Playblocks with actions to ServiceNow._  
_Check Point best practice: SAML IdP in Infinity Portal and Management API for SOAR/ITSM._

**Procedure:**

1. Configure the events → ITSM integration (webhook or connector).
2. Run IPS-01 and check a case is opened with the event data.

**Expected result:** Case created automatically with context.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### INT-04 · Interoperability with SOC tools

**Priority:** High · _Manual_  
**Objective:** The SOC consumes events and can act (block) from its tools.  
**Firewall configuration needed:** SOC SIEM/SOAR.  
_Check Point notes: Management API (indicators, dynamic objects), Log Exporter and SOAR connectors._  
_Check Point best practice: SAML IdP in Infinity Portal and Management API for SOAR/ITSM._

**Procedure:**

1. Send events to the SIEM (OBS-04).
2. From the SOAR, add an indicator through the API (as IPS-10) and verify the block.

**Expected result:** Automated detect → block loop.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### INT-05 · Containers/Kubernetes and dynamic services

**Priority:** Medium · _Manual_ · _needs extra infrastructure_  
**Objective:** The policy follows dynamic workloads (pods, services).  
**Firewall configuration needed:** Outside the reference lab: needs an EKS cluster in a spoke.  
_Check Point notes: CloudGuard Controller for Kubernetes and CloudGuard CNAPP for in-cluster security._  
_Check Point best practice: SAML IdP in Infinity Portal and Management API for SOAR/ITSM._

**Procedure:**

1. Deploy a cluster with labeled services in a spoke.
2. Use dynamic objects by namespace/label in the policy and scale the pods.
3. Check the rules follow the pods.

**Expected result:** Policy applied to dynamic workloads without editing rules.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### INT-06 · Same control across regions or clouds

**Priority:** Medium · _Manual_ · _needs extra infrastructure_  
**Objective:** A common policy is enforced across regions or clouds.  
**Firewall configuration needed:** Outside the reference lab: needs a second region or cloud.  
_Check Point notes: One management and a shared policy; CME templates per region._  
_Check Point best practice: SAML IdP in Infinity Portal and Management API for SOAR/ITSM._

**Procedure:**

1. Deploy the same pattern in another region/cloud with the same code.
2. Install the same policy and run the kit batch in both.
3. Compare the results with the portal comparison report.

**Expected result:** Same results in both locations.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

<a id="cost"></a>
## COST · Cost and efficiency

### COST-01 · Fixed platform and licence cost

**Priority:** High · _Manual_  
**Objective:** The fixed monthly cost of the solution is known.  
**Firewall configuration needed:** Licence and management prices.  
_Check Point notes: Per-vCPU licensing or Marketplace PAYG; Smart-1 Cloud as a service._  
_Check Point best practice: PAYG for peaks and BYOL for the baseline; TLS bypass of trusted high-volume traffic to save CPU._

**Procedure:**

1. Add licences (BYOL/PAYG), management and support for the minimum size (2 gateways in 2 AZs).
2. Add the fixed AWS cost: instances, GWLB, endpoints and TGW attachments per hour.

**Expected result:** Itemized fixed monthly cost.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### COST-02 · Variable cost per GB and AWS routes

**Priority:** High · _Manual_  
**Objective:** The cost per inspected GB is known for each path.  
**Firewall configuration needed:** Estimated traffic volumes.  
_Check Point notes: AWS calculator + actual consumption (Cost Explorer by tag) of the lab during the POC._  
_Check Point best practice: PAYG for peaks and BYOL for the baseline; TLS bypass of trusted high-volume traffic to save CPU._

**Procedure:**

1. For east-west and egress, add TGW, GWLB endpoint, GWLB, NAT and cross-AZ transfer processing per GB.
2. Compare with the actual consumption after a PERF run.

**Expected result:** Cost per GB per path.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### COST-03 · Incremental cost of IPS/TLS/AV

**Priority:** High · _Manual_  
**Objective:** Estimates the cost of enabling advanced capabilities.  
**Firewall configuration needed:** PERF-01, PERF-02 and PERF-08 results.  
_Check Point notes: Size with the real profile (Optimized/Strict) and TLS bypass of sensitive and trusted high-volume categories._  
_Check Point best practice: PAYG for peaks and BYOL for the baseline; TLS bypass of trusted high-volume traffic to save CPU._

**Procedure:**

1. Compare throughput and CPU with L3/L4 policy (PERF-01) and full profile (PERF-02/PERF-08).
2. Translate the difference into gateways (and cost) for the expected traffic.

**Expected result:** Incremental cost backed by measurements.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### COST-04 · Cost of AZ redundancy and scaling

**Priority:** Medium · _Manual_  
**Objective:** The cost of high availability and scaling is known.  
**Firewall configuration needed:** HA-02 and HA-05 results.  
_Check Point notes: AWS calculator + actual consumption (Cost Explorer by tag) of the lab during the POC._  
_Check Point best practice: PAYG for peaks and BYOL for the baseline; TLS bypass of trusted high-volume traffic to save CPU._

**Procedure:**

1. Compute the cost of the redundant minimum (n+1 per AZ) and of each extra gateway from scaling.
2. Use the observed scaling thresholds to estimate scaled hours per month.

**Expected result:** HA and peak cost documented.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.

### COST-05 · Administration, support and log cost

**Priority:** High · _Manual_  
**Objective:** Estimates operational effort and log cost.  
**Firewall configuration needed:** Log volume of a full run.  
_Check Point notes: Retention included in Smart-1 Cloud per plan; log Accepts only where useful (sections with selective logging)._  
_Check Point best practice: PAYG for peaks and BYOL for the baseline; TLS bypass of trusted high-volume traffic to save CPU._

**Procedure:**

1. Measure logs per day of a run and extrapolate to the real traffic.
2. Estimate operating hours per month (OPS-06) and retention/SIEM cost.

**Expected result:** Estimated yearly operating cost.  
**Evidence:** Screenshots of the management and cloud consoles with date and time, log exports and procedure notes.
