# Firewall setup

_Español: [configuracion-firewall.md](../es/configuracion-firewall.md)_

The kit tests what the policy is expected to do. This page lists the Check Point Cloud Firewall configuration that
the catalog assumes, so results reflect the policy and not a missing prerequisite. Names are examples.

## 1. Objects and segmentation

1. One network object per environment (by CIDR) and a group with all of them.
2. Rules that implement the **segmentation matrix** you enter in the portal Settings (the kit expects exactly that
   matrix), a rule allowing HTTP/HTTPS/ICMP to the test server environment and a final cleanup **Drop + Log**.
3. Optional exception rule for a single port between environments (default iperf3 tcp/5201, POL-02/POL-10), placed
   above the segmentation rules.

## 2. Egress (inline layer for Internet)

| Rule | Content | Cases |
|---|---|---|
| Geo-blocking | Destination: GEO updatable objects of the blocked countries | IPS-08 |
| Applications | Facebook, TikTok, Dropbox, WeTransfer, OpenSSH, SSH tunnelled, DoH → Drop | APP-01/02/04 |
| Categories | Gambling, Anonymizer, Phishing, Hacking, Botnets… → Drop (do not mix categories and applications in the same rule, sk112214) | APP-02 |
| Custom sites | Blocked FQDN (`www.example.org`) and blocked path (`www.example.com/testkit-blocked`) → Drop | POL-05, APP-03 |
| Allow | Services HTTP/HTTPS with **match by protocol signature** + DNS → Accept | NET-03, APP-01 |
| Cleanup | Drop + Log | NET-03, APP-07 |

## 3. Threat Prevention

| Rule | Profile | Notes |
|---|---|---|
| Environments → IDS target (optional) | Detect profile | IPS-11, POL-15 |
| East-west between environments | IPS + Anti-Virus in Prevent | Exceptions: exception port (inactive) and, optionally, IPS-04 |
| Environments → Internet | IPS + Anti-Bot + Anti-Virus in Prevent | |

- Anti-Virus: inspect files in both directions on all interfaces, archive scanning on (GWLB gateways have one interface).
- IPS-04 exception (optional): protection *TP-Link Archer AX21 Command Injection (CVE-2023-1389)*, source = environment
  of role `ips_exception_client`, destination = server, action **Detect**.
- The SQL tautology family ("SQL Servers Blind SQL Injection Techniques") is inactive by default (Critical performance
  impact); even when enabled, tautologies in urlencoded/JSON bodies are a WAF use case (WAF-01, informative).

## 4. Content Awareness

- Rules between environments over **HTTP and HTTPS**: data types *PCI – Credit Card Numbers* and *IBAN* → Drop;
  file type *Executable* → Drop.
- Optional DLP-02 exception above them: source = role `dlp_exception_client`, destination = server, direction **up**, Accept.

## 5. HTTPS Inspection

1. Create (or import) the **outbound inspection certificate** and export its public part to `certs/inspection_ca.crt`
   (clients trust it; in production, deploy it with GPO/MDM).
2. Add `certs/testkit_ca.crt` as a **trusted CA**, so the gateway can validate the test server when it decrypts
   east-west HTTPS.
3. HTTPS layer rules, in this order:
   - Bypass: custom site with `nodecrypt.testkit.lab` and `mtls.testkit.lab` (TLS-04/05).
   - Bypass: updatable object *HTTPS services – recommended bypass* (sk163595).
   - Bypass: categories Financial Services, Health, Government/Military (privacy).
   - Inspect: environments → environments.
   - Inspect: environments → Internet.
   Behind a GWLB all traffic enters through one interface: use "not internal networks" (negated object) instead of
   the *Internet* object in destinations.
4. Advanced settings → server certificate validation: **block untrusted, expired and revoked** certificates (TLS-03).
5. Enable HTTPS Inspection on the gateways (e.g., in the CME template for autoscaling groups, and on existing gateways).
6. Keep QUIC (UDP/443) blocked so browsers fall back to inspected TCP (TLS-06).

## 6. Recommended practices applied

- Build the policy from a **trust matrix** between zones; one Threat Prevention rule and profile per flow type.
- Deactivate protections that do not apply by **tags** (e.g., OT/SCADA vendors in IT-only VPCs) instead of disabling
  them globally.
- Roll out new profiles in **Detect** first (≥ 1 week of learning, then Prevent), with newly updated protections in staging.
- Prefer exceptions scoped to a protection + asset over global changes.
- Log every rule; packet capture on Threat Prevention rules.

References: sk108202 (HTTPS Inspection best practices), sk163595 (bypass list), sk112214, sk159872, sk112249 (App
Control best practices), sk95193 (ATRG: IPS).
