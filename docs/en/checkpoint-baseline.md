# Check Point baseline (optional)

_Español: [checkpoint-baseline.md](../es/checkpoint-baseline.md)_

`checkpoint/cp-baseline.sh` prepares a Check Point management for a test campaign: it builds a policy package that
follows Check Point best practices and implements exactly what the testkit expects from the portal settings.

## Requirements

- A Check Point management reachable over the Management API (Smart-1 Cloud or on-premises R81.20+) and an API key
  of an administrator with read-write permissions. A management dedicated to the tests is recommended: the tool also
  changes global TLS inspection settings (server-certificate validation, outbound CA if none exists).
- `curl`, `jq`, `openssl`.
- Every environment in the portal settings needs a **CIDR**.

## Usage

```bash
cd checkpoint
./cp-baseline.sh setup                                         # URL (…/web_api) + API key → settings.env
./cp-baseline.sh apply --portal http://<server IP>/portal --push-ca
./cp-baseline.sh install <gateway> [<gateway> …]               # or: install --prefix <gateway name prefix>
./cp-baseline.sh remove [--gateways-prefix <prefix>]           # delete the package and every TK_ object
```

`apply` can also take a configuration file (`--config file.json --testkit-ca ca.crt`) when the portal is not reachable.
With `--push-ca` the HTTPS Inspection CA is uploaded to the portal settings, so clients trust it and the TLS checks
know which certificates were decrypted. Re-running `apply` is safe: missing objects are created and rules are put back
in order.

The access and HTTPS Inspection layers are grouped in sections (`TK · Data loss prevention`, `TK · Segmentation
exceptions`, `TK · Segmentation matrix`, `TK · Internet egress`, `TK · Cleanup`; in the egress layer `TK · Geo-blocking`,
`TK · Applications and URL filtering`, `TK · Allowed web and DNS`; in HTTPS `TK · Bypass` and `TK · Inspect`). Threat
Prevention rules are ordered but not sectioned: the Management API cannot create sections in that layer.

## What it configures

| Area | Configuration |
|---|---|
| Objects | `TK_<environment>` networks, `TK_Envs`, `TK_Internal`, exception-port and protocol-signature HTTP/HTTPS services, custom sites (blocked FQDN, blocked path, TLS bypass), GEO and recommended-bypass updatable objects |
| Access | DLP (card numbers, IBAN, executables; optional DLP exception), exception port between environments, one Accept rule per allowed pair of the segmentation matrix, isolation, Internet inline layer, cleanup |
| Egress | GEO blocking, blocked applications (social, file sharing, SSH, DoH), blocked categories, high-risk apps, custom sites, HTTP/HTTPS with protocol signature + DNS |
| Threat prevention | Profiles per flow type (east-west, Internet, Detect), OT/SCADA protections deactivated by tags on east-west, SQL tautology protection enabled, exception for the exception port, optional per-asset IPS exception and IDS rule |
| TLS inspection | Outbound CA, testkit CA trusted, own HTTPS layer with bypass for FQDN/recommended list/sensitive categories and Inspect east-west and Internet, server-certificate validation |

Details and the reasoning behind each choice: [firewall-setup.md](firewall-setup.md).
