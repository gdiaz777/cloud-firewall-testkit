# Firewall Testkit

_Español: [README.es.md](README.es.md)_

A portable, vendor-neutral kit to **validate and compare network security solutions** (cloud firewalls, NGFWs,
east-west segmentation and egress inspection) with repeatable, explained tests, a web portal and Word reports in
English and Spanish.

Run one container as **test server** and one container as **client** in each network segment. Clients point at the
server, every test crosses the security solution, and the portal produces the report — whatever the architecture is.

![Portal – tests](docs/img/portal-tests.png)

## What it tests

**117 test cases in 14 domains**: architecture and routing, policy and segmentation, intrusion prevention, malware,
**TLS inspection** (including evasion over HTTPS), application/URL control, DLP, web attack coverage, visibility and
audit, **high availability**, **performance**, operations, integrations and cost.

- **69 automated cases (222 checks)**: run from the clients (traffic through the solution) and, for high availability,
  logs, policy and operations, from an optional **control agent** on an admin host (cloud and management APIs; it
  fails over gateways while every client probes continuously).
- **48 manual cases**: guided procedure, expected result and evidence (consoles, integrations, costs), in the portal and
  in the report.

Only harmless stimuli are used (EICAR, attack patterns against a non-vulnerable server, synthetic data). See the
[test catalog](docs/en/test-catalog.md). What the firewall must have configured for the tests is in the portal tab
**Firewall configuration** and in every case (vendor-neutral; Check Point best practices are shown when the solution
under test is Check Point).

## Quick start

### Hosts and Docker

One Linux host per environment (any distribution with Docker Engine; 2 vCPU / 4 GB is enough, more on the
performance client) plus the test server, which can share a host with one of the clients. Each host needs outbound
HTTPS to `ghcr.io` to pull the image (and to the Docker repository while installing). Install Docker Engine:

```bash
# Ubuntu / Debian (Docker's repository; replace "ubuntu" with "debian" on Debian)
sudo apt-get update && sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io

# RHEL / Rocky / Alma (Docker's repository)
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io

# Amazon Linux 2023
sudo dnf install -y docker

# all: start it at boot and let your user run docker without sudo (log out and back in afterwards)
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
docker version && docker pull ghcr.io/gdiaz777/cloud-firewall-testkit:latest
```

No access to `ghcr.io`? Pull the image on a host that has it, `docker save ghcr.io/gdiaz777/cloud-firewall-testkit:latest
| gzip > testkit.tar.gz`, copy the file and run `gunzip -c testkit.tar.gz | docker load` on each host.

The test traffic must leave through the interface the solution inspects. With one interface nothing needs doing.
With a management and a workload interface, the route to the other environments (and to the Internet, for the egress
tests) from the workload IP must use the workload interface; the client uses as source the IP of the interface
that reaches the server (force it with `-e SRC_IP=<workload IP>`).

### Containers

On the **test server**. `SERVER_IP` is the server's **workload IP** (the one the clients
reach through the solution); set it when the host has more than one interface (e.g. a management NIC), otherwise the
first address is used:

```bash
docker run -d --name testkit-server --restart unless-stopped --network host -e SERVER_IP=<server workload IP> -v testkit-data:/data \
  ghcr.io/gdiaz777/cloud-firewall-testkit:latest server
```

On every **client** (one per network segment / environment). `TESTKIT_ENV` is the environment name the portal will
use (e.g. `pro`, `pre`, `dev`): without it the host name is used, and renaming it later in the portal breaks the match
with the client:

```bash
docker run -d --name testkit-client --restart unless-stopped --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e SERVER=<server workload IP> -e TESTKIT_ENV=<environment name> ghcr.io/gdiaz777/cloud-firewall-testkit:latest client
```

On every client host **except the test server's**, also run the server without the portal: the other environments use
it as a target (cross-AZ peer, IDS target, east-west reachability between environments):

```bash
docker run -d --name testkit-target --restart unless-stopped --network host -e PORTAL=0 -e SERVER_IP=<this host's workload IP> \
  -v testkit-data:/data ghcr.io/gdiaz777/cloud-firewall-testkit:latest server
```

Open `http://<server IP>/portal/` (from an admin host: the address you can reach) → **Settings**:

1. **Solution under test**: name and vendor (it labels runs and reports; Check Point shows its notes and best practices).
2. **Environments**: *Add connected clients*, then fill CIDR, AZ, the environment that hosts the **test server** and the
   cross-AZ peers; then the **segmentation matrix** (what each environment may reach).
3. **Roles**: which environments play each role (production/non-production, IDS target, exceptions, **perf_client** for
   the performance checks…). Leave empty what does not apply: those checks are reported as *not applicable*.
4. **Internet targets**: change them only if the policy uses other sites.
5. **TLS inspection CA**: paste the CA certificate the solution uses to re-sign inspected TLS (the Check Point
   baseline below uploads it for you).
6. Save. Then configure the firewall as the **Firewall configuration** tab describes (or apply the Check Point baseline),
   go to **Tests** and click **Run all** — or run single checks and cases.

When a run finishes, download the **Word report (EN/ES)** or the CSV. Requirements: the clients must reach the server
over HTTP (tcp/80) through the solution; the server generates its own test CA and clients fetch it automatically.

Command line on a client (no portal needed): `docker exec testkit-client fw-tests run IPS-01 TLS-05`.
A `docker-compose.yml` with both profiles is included.

## Optional: control agent (HA, logs, policy, operations)

Some checks cannot be done from a workload: terminating or isolating a gateway, scaling the group, reading the
firewall logs, measuring a policy change end to end. They run in a **control agent** on an admin host with cloud
and management credentials; it registers in the portal as one more client (`CONTROL`). Without it those checks are
reported as *not applicable*. See [docs/en/control-agent.md](docs/en/control-agent.md).

## Comparing solutions

Change **Solution under test** in Settings, run the batch again with the same clients, tick two or more runs in the
**Runs** panel and download the **comparison report**: overall and per-domain results, a verdict per case for every
solution and the list of checks where they differ. Results come from what the clients observe (reset, drop, block
page, certificate issuer), not from vendor logs, so the same yardstick applies to every vendor.

| Settings | Report |
|---|---|
| ![Settings](docs/img/portal-settings.png) | ![Report](docs/img/report.png) |

## Optional: Check Point baseline

[`checkpoint/`](checkpoint/) configures a Check Point management (e.g. Smart-1 Cloud) from the portal settings with a
policy that follows Check Point best practices — segmentation matrix, egress control, threat prevention per flow type,
DLP and TLS inspection — and uploads the inspection CA to the portal:

```bash
cd checkpoint && ./cp-baseline.sh setup                       # management URL + API key
./cp-baseline.sh apply --portal http://<portal address>/portal --push-ca
./cp-baseline.sh install <gateway> …                         # or --prefix <name prefix>
```

Run it after saving the portal settings (it reads environments, matrix and roles from the portal), from a host that
reaches both the management API and the portal (`<portal address>`: the one you open in the browser).

See [docs/en/checkpoint-baseline.md](docs/en/checkpoint-baseline.md) and the [Check Point configuration guide](docs/en/firewall-setup.md).

## How it works

- **Server**: nginx on 80/443 with three TLS names (`inspect.testkit.lab`, `nodecrypt.testkit.lab`, `mtls.testkit.lab`),
  test content (EICAR variants, benign files, synthetic card numbers/IBANs, an executable), services on ports that
  should be blocked (22, 23, 3389, 8080), iperf3, and the portal.
- **Client**: an agent that runs the checks from its own IP and posts results to the portal (zlib+base64, so attack
  payloads in results do not trigger the IPS). It can also run as a CLI.
- **Catalog**: `catalog/catalog.py` → `tests.json`, bilingual; vendor-specific notes are kept apart and shown only when
  the solution under test is Check Point.

```
catalog/     catalog.py, tests.json, gen_docs.py
client/      runner.py (checks, agent, CLI, tasks requested by the control agent)
control/     control agent (agent.py) and cloud hooks (aws_hooks.py)
server/      nginx, content, portal (Flask + JS), report (docx + matplotlib), comparison report
checkpoint/  optional Check Point baseline (Management API) and Check Point hooks of the control agent
config/      default.json, config.example.json (4-environment example)
docs/        en/, es/, img/
```

Build locally: `./build.sh` (image `cloud-firewall-testkit:local`).

## Safety

Use it only on networks you are authorized to test. Every stimulus is harmless and every data set is synthetic.

## License

MIT — see [LICENSE](LICENSE). Not an official Check Point product.
