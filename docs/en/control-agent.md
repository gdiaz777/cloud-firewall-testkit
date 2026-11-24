# Control agent

_Español: [agente-control.md](../es/agente-control.md)_

The control agent runs the **operator-side** checks of the catalog (checks marked *control agent* in the portal):
high availability (HA-01…05), logs and health (OBS-01/02/08), route audit (NET-06), policy hygiene and drift
(POL-14/16), signatures and threat intelligence (IPS-03, THR-06), IoC reaction (IPS-10), resources under load
(PERF-08) and operations (OPS-01/03).

It runs on an **admin host** (never in a workload) with cloud and management credentials, polls the portal like any
client and shows up as `CONTROL`. While it fails a gateway over, it asks every client for **continuous probes**
(server, Internet and a denied flow, once per second) and **long sessions**, and measures interruptions.

## Run it

```bash
git clone https://github.com/gdiaz777/cloud-firewall-testkit && cd cloud-firewall-testkit
pip install boto3            # AWS hooks
export PORTAL_URL=http://<server>/portal CONTROL_CONFIG=control.json MGMT_API_KEY=<management API key>
python3 control/agent.py                 # agent mode (Run all in the portal includes its checks)
python3 control/agent.py run HA-01       # one-off from the CLI
```

`control.json`:

```json
{
  "aws":  {"region": "eu-west-1", "asg_name": "<gateways Auto Scaling group>", "cme_role_arn": "<role the management uses>",
           "env_file": "<optional file with temporary AWS_* credentials, re-read before every check>"},
  "mgmt": {"url": "https://<management>/web_api", "api_key_env": "MGMT_API_KEY", "package": "FW_Testkit",
           "gateway_prefix": "<only gateways with this prefix are touched>", "post_provision_cmd": "<optional>"},
  "ha":   {"max_outage_s": 60, "isolation_s": 240, "provision_timeout_s": 2700},
  "state_dir": "~/.testkit-control"
}
```

Cloud and vendor support: AWS hooks (`control/aws_hooks.py`) and Check Point hooks (`checkpoint/control_hooks.py`).
For other clouds or vendors the checks are reported as *not applicable*; a new vendor only needs a
`<vendor>/control_hooks.py` that registers the `fw.*` hooks.

## What it changes, and how it undoes it

| Check | Change | Undo |
|---|---|---|
| HA-01 | terminates one gateway in the Auto Scaling group | the group launches a replacement (measured) |
| HA-02/04 | network ACL deny entries (/32) and an empty security group on the gateways of one AZ, ASG health processes suspended | entries removed, original security groups restored, processes resumed (in `finally`) |
| HA-03 | same for every gateway (whole inspection tier) | same |
| HA-05 | desired capacity +1 (existing gateways protected from scale-in) | back to the initial capacity, protection removed |
| IPS-10 | threat indicator + threat policy install on the test gateways | indicator deleted + reinstall |
| OPS-03 | temporary rule and two host objects + access policy install | deleted + reinstall |
| POL-16 | a disabled rule published (no install) | deleted + publish |
| PERF-08 | load from the performance client | — |

Checks that disrupt traffic (marked *disruptive*) wait until every client of the run has finished. Policy
installations and run-script only target the gateways of `mgmt.gateway_prefix`.

## Permissions

- **AWS** (control host): `autoscaling:Describe*`, `SuspendProcesses`, `ResumeProcesses`, `TerminateInstanceInAutoScalingGroup`,
  `SetDesiredCapacity`, `SetInstanceProtection`, `UpdateAutoScalingGroup`; `ec2:Describe*`, `CreateNetworkAclEntry`,
  `DeleteNetworkAclEntry`, `CreateSecurityGroup`, `RevokeSecurityGroupEgress`, `DeleteSecurityGroup`, `ModifyNetworkInterfaceAttribute`; `elasticloadbalancing:Describe*`; `cloudwatch:GetMetricStatistics`, `DescribeAlarms`;
  `iam:GetRole*`, `ListRolePolicies`, `ListAttachedRolePolicies`, `GetPolicy*`; `pricing:GetProducts`.
- **Management**: an API key whose profile can read, publish, install policy and run scripts on the test gateways.
