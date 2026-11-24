"""AWS hooks of the control agent: firewall tier behind a Gateway Load Balancer with an Auto Scaling group.

Settings (CONTROL_CONFIG):  aws.region, aws.asg_name (gateways' Auto Scaling group), aws.cme_role_arn (role the
management uses to read the account, optional), ha.max_outage_s (60), ha.isolation_s (150), ha.provision_timeout_s
(2700), mgmt.post_provision_cmd (optional command run when a new gateway has its policy, e.g. lab-specific updates).
Credentials: the usual boto3 chain (environment, profile, instance role).

Failures are simulated so that they always undo themselves:
  - gateway loss / AZ loss / whole tier loss: deny entries for the gateways' private IPs (/32) in the subnet network
    ACL (stateless: cuts GENEVE, health checks and existing flows at once). The ASG health-check processes are
    suspended meanwhile so that the isolated gateways are not replaced; everything is restored in "finally".
  - instance failure: the instance is terminated in the ASG (the ASG launches a replacement).
"""
import json, os, re, subprocess, threading, time
from control.agent import HOOKS, Skip, fmt_outages, hook, log, outages, recovered

try:
    import boto3
except ImportError:   # the hooks report N/A without boto3
    boto3 = None


class AWS:
    def __init__(self, ctx):
        if boto3 is None:
            raise Skip("boto3 is not installed on the control agent")
        self.ctx = ctx
        ef = ctx.setting("aws.env_file")   # optional KEY=VALUE file with temporary credentials: re-read on every check
        if ef and os.path.exists(ef):
            for line in open(ef, encoding="utf-8"):
                m = re.match(r"\s*(?:export\s+)?(AWS_[A-Z_]+)\s*=\s*['\"]?([^'\"\n]*)", line)
                if m:
                    os.environ[m.group(1)] = m.group(2).strip()
            os.environ.pop("AWS_PROFILE", None)
        self.region = ctx.setting("aws.region") or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        self.asg_name = ctx.setting("aws.asg_name")
        if not self.region:
            raise Skip("not configured: aws.region")
        self.c = lambda svc, region=None: boto3.client(svc, region_name=region or self.region)
        self.ec2, self.asc, self.elb, self.cw = self.c("ec2"), self.c("autoscaling"), self.c("elbv2"), self.c("cloudwatch")

    # ---------------------------------------------------------------- firewall tier
    def asg(self):
        if not self.asg_name:
            raise Skip("not configured: aws.asg_name")
        g = self.asc.describe_auto_scaling_groups(AutoScalingGroupNames=[self.asg_name])["AutoScalingGroups"]
        if not g:
            raise Skip(f"Auto Scaling group {self.asg_name} not found")
        return g[0]

    def in_service(self, g=None):
        g = g or self.asg()
        return sorted([i for i in g["Instances"] if i["LifecycleState"] == "InService"], key=lambda i: (i["AvailabilityZone"], i["InstanceId"]))

    def tg_arn(self, g=None):
        g = g or self.asg()
        if not g.get("TargetGroupARNs"):
            raise Skip("the Auto Scaling group has no target group (not a GWLB deployment)")
        return g["TargetGroupARNs"][0]

    def tg_health(self, arn):
        return {d["Target"]["Id"]: d["TargetHealth"]["State"] for d in self.elb.describe_target_health(TargetGroupArn=arn)["TargetHealthDescriptions"]}

    def ips(self, ids):
        out = {}
        for r in self.ec2.describe_instances(InstanceIds=ids)["Reservations"]:
            for i in r["Instances"]:
                out[i["InstanceId"]] = dict(ip=i["PrivateIpAddress"], subnet=i["SubnetId"], az=i["Placement"]["AvailabilityZone"], type=i["InstanceType"])
        return out

    def lb_attrs(self, tg):
        t = self.elb.describe_target_groups(TargetGroupArns=[tg])["TargetGroups"][0]
        lb = t["LoadBalancerArns"][0] if t.get("LoadBalancerArns") else None
        a = {x["Key"]: x["Value"] for x in self.elb.describe_target_group_attributes(TargetGroupArn=tg)["Attributes"]}
        if lb:
            a.update({x["Key"]: x["Value"] for x in self.elb.describe_load_balancer_attributes(LoadBalancerArn=lb)["Attributes"]})
        a["hc"] = f"health check {t.get('HealthCheckProtocol')}/{t.get('HealthCheckPort')} every {t.get('HealthCheckIntervalSeconds')} s, unhealthy after {t.get('UnhealthyThresholdCount')}"
        return a

    def suspend(self, procs=("HealthCheck", "ReplaceUnhealthy", "AZRebalance")):
        self.asc.suspend_processes(AutoScalingGroupName=self.asg_name, ScalingProcesses=list(procs))

    def resume(self, procs=("HealthCheck", "ReplaceUnhealthy", "AZRebalance")):
        self.asc.resume_processes(AutoScalingGroupName=self.asg_name, ScalingProcesses=list(procs))

    def isolate(self, targets):
        """Network ACL deny entries (in/out) for each gateway IP /32 in its subnet's ACL. Returns what to remove."""
        made = []
        for t in targets:
            acl = self.ec2.describe_network_acls(Filters=[{"Name": "association.subnet-id", "Values": [t["subnet"]]}])["NetworkAcls"][0]
            used = {e["RuleNumber"] for e in acl["Entries"]}
            for egress in (False, True):
                n = next(k for k in range(1, 99) if k not in used and (k, egress) not in {(m[1], m[2]) for m in made if m[0] == acl["NetworkAclId"]})
                kw = dict(NetworkAclId=acl["NetworkAclId"], RuleNumber=n, Egress=egress)
                self.ec2.create_network_acl_entry(Protocol="-1", RuleAction="deny", CidrBlock=t["ip"] + "/32", **kw)
                made.append((acl["NetworkAclId"], n, egress)); used.add(n)
        return made

    def unisolate(self, made):
        for acl, n, egress in made:
            try:
                self.ec2.delete_network_acl_entry(NetworkAclId=acl, RuleNumber=n, Egress=egress)
            except Exception as e:  # noqa
                log("could not remove ACL entry", acl, n, e)

    # ---------------------------------------------------------------- vendor adapter (gateway objects in the management)
    def fw_gateways(self):
        fn = HOOKS.get(f"{self.ctx.vendor}._gateways")
        return fn(self.ctx) if fn else None   # {instance_id: {"name":…, "policy": bool}}


def rel(t, t0):
    return f"+{round(t - t0)} s" if t else "not observed"


def post_provision(ctx, name, t0):
    cmd = ctx.setting("mgmt.post_provision_cmd")
    if not cmd:
        return ""
    t = time.time(); env = dict(os.environ, TK_GATEWAY=name or "", TK_SINCE=str(int(t0)))
    p = subprocess.run(cmd, shell=True, env=env, capture_output=True, text=True, timeout=3600)
    return f"; post-provisioning step: {'OK' if p.returncode == 0 else 'rc=' + str(p.returncode)} in {round(time.time() - t)} s"


def wait_new_member(a, ctx, before, t0, timeout, ev):
    """Follows a new ASG member until it is a healthy target and (if the vendor adapter exists) has its policy."""
    tg = a.tg_arn(); new = None
    while time.time() - t0 < timeout:
        g = a.asg(); ids = {i["InstanceId"]: i for i in g["Instances"]}
        cand = [i for i in ids if i not in before]
        if cand and not new:
            new = cand[0]; ev["launched"] = time.time()
        if new:
            if ids.get(new, {}).get("LifecycleState") == "InService" and "inservice" not in ev:
                ev["inservice"] = time.time()
            if a.tg_health(tg).get(new) == "healthy" and "healthy" not in ev:
                ev["healthy"] = time.time()
            fw = a.fw_gateways()
            if fw is None:
                ev.setdefault("provisioned", ev.get("healthy"))
            elif fw.get(new, {}).get("policy") and "provisioned" not in ev:
                ev["provisioned"] = time.time(); ev["fw_name"] = fw[new]["name"]
            if ev.get("healthy") and ev.get("provisioned"):
                return new
        time.sleep(15)
    return new


def sessions_summary(res, t0):
    tot = brk = 0; when = []
    for r in res.values():
        s = r.get("sessions")
        if not s:
            continue
        tot += s["n"]; b = [t for t in s["broken"].values() if t >= t0]; brk += len(b); when += b
    if not tot:
        return "", 0, 0
    return (f"{tot - brk}/{tot} long sessions survived" + (f" ({brk} cut between +{round(min(when) - t0)} and +{round(max(when) - t0)} s)" if when else "")), tot, brk


# ------------------------------------------------------------------ NET-06
@hook("aws.route_audit")
def route_audit(c, ctx):
    """Every workload subnet sends inter-VPC and Internet traffic to the inspection path (TGW → inspection attachment);
    no IGW/NAT/peering/VGW route, no gateway endpoint, and the TGW route table of the spokes points only to inspection."""
    a = AWS(ctx); ec2 = a.ec2; bad, notes, seen_rt = [], [], set()
    insp = [x for x in ec2.describe_transit_gateway_vpc_attachments()["TransitGatewayVpcAttachments"]
            if x["State"] == "available" and x["Options"].get("ApplianceModeSupport") == "enable"]
    insp_ids = {x["TransitGatewayAttachmentId"] for x in insp}
    if not insp_ids:
        notes.append("no TGW attachment with appliance mode (inspection) found")
    for env, ip in ctx.cfg["envs"].items():
        enis = ec2.describe_network_interfaces(Filters=[{"Name": "addresses.private-ip-address", "Values": [ip]}])["NetworkInterfaces"]
        if not enis:
            bad.append(f"{env}: workload IP {ip} not found in {a.region}"); continue
        sub, vpc = enis[0]["SubnetId"], enis[0]["VpcId"]
        rts = ec2.describe_route_tables(Filters=[{"Name": "association.subnet-id", "Values": [sub]}])["RouteTables"] or \
            ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc]}, {"Name": "association.main", "Values": ["true"]}])["RouteTables"]
        for r in rts[0]["Routes"]:
            dst = r.get("DestinationCidrBlock") or r.get("DestinationPrefixListId") or r.get("DestinationIpv6CidrBlock")
            tgt = r.get("GatewayId") or r.get("NatGatewayId") or r.get("VpcPeeringConnectionId") or r.get("TransitGatewayId") or r.get("NetworkInterfaceId") or r.get("VpcEndpointId") or "?"
            if tgt == "local" or r.get("State") == "blackhole":
                continue
            if tgt.startswith(("tgw-", "vpce-")) and not r.get("DestinationPrefixListId"):
                continue
            bad.append(f"{env}: route {dst} → {tgt} skips the inspection path")
        # other subnets of the same VPC with their own Internet route (e.g. admin access): out of the workload path
        others = [rt for rt in ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["RouteTables"]
                  if rt["RouteTableId"] != rts[0]["RouteTableId"] and any((x.get("GatewayId") or "").startswith("igw-") for x in rt["Routes"])]
        if others:
            notes.append(f"{env}: {len(others)} other route table(s) with direct Internet access in the VPC (not used by the workload subnet)")
        peer = ec2.describe_vpc_peering_connections(Filters=[{"Name": "requester-vpc-info.vpc-id", "Values": [vpc]}])["VpcPeeringConnections"] + \
            ec2.describe_vpc_peering_connections(Filters=[{"Name": "accepter-vpc-info.vpc-id", "Values": [vpc]}])["VpcPeeringConnections"]
        if [p for p in peer if p["Status"]["Code"] == "active"]:
            bad.append(f"{env}: active VPC peering (traffic between VPCs without the TGW)")
        att = ec2.describe_transit_gateway_attachments(Filters=[{"Name": "resource-id", "Values": [vpc]}, {"Name": "state", "Values": ["available"]}])["TransitGatewayAttachments"]
        if not att:
            bad.append(f"{env}: VPC not attached to a Transit Gateway"); continue
        rt = (att[0].get("Association") or {}).get("TransitGatewayRouteTableId")
        if rt and rt not in seen_rt:
            seen_rt.add(rt)
            routes = ec2.search_transit_gateway_routes(TransitGatewayRouteTableId=rt, Filters=[{"Name": "state", "Values": ["active"]}])["Routes"]
            for r in routes:
                tg = {x["TransitGatewayAttachmentId"] for x in r.get("TransitGatewayAttachments", [])}
                if tg and not tg <= insp_ids:
                    bad.append(f"TGW route table {rt}: {r['DestinationCidrBlock']} → {', '.join(tg)} does not go to inspection")
            notes.append(f"TGW route table of the spokes: {len(routes)} active route(s), all to the inspection attachment" if not [b for b in bad if rt in b] else "")
    notes = [n for n in notes if n]
    det = (f"{len(ctx.cfg['envs'])} workload subnets audited; inspection attachments with appliance mode: {len(insp_ids)}. ")
    if bad:
        return "NOT_MET", det + "Bypass paths: " + "; ".join(bad) + (". Notes: " + "; ".join(notes) if notes else "")
    return "PASS", det + "No route bypasses the firewall" + (". Notes: " + "; ".join(notes) if notes else "")


# ------------------------------------------------------------------ OBS-08 (cloud side)
@hook("aws.health")
def health(c, ctx):
    a = AWS(ctx); g = a.asg(); tg = a.tg_arn(g); h = a.tg_health(tg); now = time.time(); probs = []
    ins = g["Instances"]
    for i in ins:
        if i["LifecycleState"] != "InService" or i["HealthStatus"] != "Healthy":
            probs.append(f"{i['InstanceId']} {i['LifecycleState']}/{i['HealthStatus']}")
    probs += [f"target {k} {v}" for k, v in h.items() if v != "healthy"]
    cpu = []
    for i in ins:
        d = a.cw.get_metric_statistics(Namespace="AWS/EC2", MetricName="CPUUtilization", Dimensions=[{"Name": "InstanceId", "Value": i["InstanceId"]}],
                                       StartTime=now - 3600, EndTime=now, Period=300, Statistics=["Average", "Maximum"])["Datapoints"]
        cpu.append(f"{i['InstanceId']} ({i['AvailabilityZone'][-1]}) avg {sum(x['Average'] for x in d) / len(d):.1f} % max {max(x['Maximum'] for x in d):.1f} %" if d else f"{i['InstanceId']} no metrics")
        if not d:
            probs.append(f"{i['InstanceId']} without CloudWatch metrics")
    alarms = [x for x in a.cw.describe_alarms(AlarmTypes=["MetricAlarm"])["MetricAlarms"]
              if any(d["Name"] == "AutoScalingGroupName" and d["Value"] == a.asg_name for d in x.get("Dimensions", []))]
    al = "; ".join(f"{x['AlarmName']}: {x['MetricName']} {x['ComparisonOperator'].replace('Threshold', '').replace('GreaterThan', '>').replace('LessThan', '<').replace('OrEqualTo', '=')} {x['Threshold']:g} ({x['StateValue']}, actions: {len(x.get('AlarmActions', []))})" for x in alarms)
    if not alarms:
        probs.append("no CloudWatch alarm on the Auto Scaling group")
    det = (f"{len(ins)} gateways (min {g['MinSize']}, desired {g['DesiredCapacity']}, max {g['MaxSize']}), GWLB targets: "
           f"{', '.join(f'{k} {v}' for k, v in h.items())}. CPU last hour: {'; '.join(cpu)}. Alarms: {al or 'none'}")
    return ("NOT_MET", det + ". Problems: " + "; ".join(probs)) if probs else ("PASS", det)


# ------------------------------------------------------------------ HA-01
@hook("aws.instance_failure")
def instance_failure(c, ctx):
    a = AWS(ctx); g = a.asg(); tg = a.tg_arn(g); ins = a.in_service(g); h = a.tg_health(tg)
    if len(ins) < 2 or any(h.get(i["InstanceId"]) != "healthy" for i in ins):
        return "NOT_MET", f"precondition not met: {len(ins)} gateways in service, targets {h} (at least 2 healthy needed)"
    max_out, timeout = ctx.setting("ha.max_outage_s", 60), ctx.setting("ha.provision_timeout_s", 2700)
    victim = ins[0]["InstanceId"]; before = {i["InstanceId"] for i in g["Instances"]}
    fw0 = a.fw_gateways() or {}
    ids = ctx.start_probes(duration=timeout + 900, sessions=20); time.sleep(30)
    t0 = time.time(); ev = {}
    log(f"HA-01: terminating {victim} ({ins[0]['AvailabilityZone']})")
    a.asc.terminate_instance_in_auto_scaling_group(InstanceId=victim, ShouldDecrementDesiredCapacity=False)

    def watch_victim():
        while time.time() - t0 < timeout and not ev.get("done"):
            st = a.tg_health(tg).get(victim)
            if st != "healthy" and "detected" not in ev:
                ev["detected"] = time.time()
            fw = a.fw_gateways()
            if fw is not None and victim in fw0 and victim not in fw and "removed" not in ev:
                ev["removed"] = time.time()
            time.sleep(5)
    th = threading.Thread(target=watch_victim, daemon=True); th.start()
    new = wait_new_member(a, ctx, before, t0, timeout, ev)
    extra = post_provision(ctx, ev.get("fw_name"), t0) if ev.get("provisioned") else ""
    t_ok = time.time(); time.sleep(90); ev["done"] = True
    res = ctx.collect(ids)
    ses, tot, brk = sessions_summary(res, t0)
    ctx.memo["failover"] = dict(kind=f"termination of {victim}", sessions=ses, t0=t0)
    out, worst, leaks = fmt_outages(res, t0, None)
    rec = recovered(res, t_ok + 30)
    det = (f"{victim} ({ins[0]['AvailabilityZone']}) terminated: GWLB target unhealthy {rel(ev.get('detected'), t0)}; replacement {new or '-'} launched "
           f"{rel(ev.get('launched'), t0)}, in service {rel(ev.get('inservice'), t0)}, healthy target {rel(ev.get('healthy'), t0)}, "
           f"registered with policy in the management {rel(ev.get('provisioned'), t0)}; old gateway object removed {rel(ev.get('removed'), t0)}{extra}. "
           f"{out}. {ses + '. ' if ses else ''}Traffic {'fully recovered' if rec else 'NOT fully recovered'} at the end.")
    ok = bool(ev.get("healthy") and ev.get("provisioned")) and worst <= max_out and not leaks and rec
    return ("PASS" if ok else "NOT_MET"), det + f" Criterion: replacement in service and interruption ≤ {max_out} s."


# ------------------------------------------------------------------ HA-02 / HA-04 / HA-03 (network isolation)
def isolation_event(a, ctx, victims, label, sessions=20):
    """Isolates the given gateways for ha.isolation_s with the probes running. Returns (res, ev, t0, t1)."""
    tg = a.tg_arn(); iso = ctx.setting("ha.isolation_s", 150)
    ids = ctx.start_probes(duration=iso + 900, sessions=sessions); time.sleep(30)
    ev, made = {}, []
    a.suspend()
    try:
        t0 = time.time(); log(f"{label}: isolating {', '.join(v['id'] for v in victims)} for {iso} s")
        made = a.isolate(victims)
        while time.time() - t0 < iso:
            h = a.tg_health(tg)
            if "detected" not in ev and all(h.get(v["id"]) != "healthy" for v in victims):
                ev["detected"] = time.time()
            time.sleep(5)
    finally:
        a.unisolate(made); t1 = time.time()
        try:
            while time.time() - t1 < 600:
                if all(a.tg_health(tg).get(v["id"]) == "healthy" for v in victims):
                    ev["back"] = time.time(); break
                time.sleep(5)
        finally:
            a.resume()
    time.sleep(60)
    return ctx.collect(ids), ev, t0, t1


@hook("aws.az_failure")
def az_failure(c, ctx):
    a = AWS(ctx); g = a.asg(); ins = a.in_service(g); tg = a.tg_arn(g)
    azs = sorted({i["AvailabilityZone"] for i in ins})
    if len(azs) < 2:
        return "NOT_MET", f"precondition not met: gateways in a single AZ ({', '.join(azs)})"
    az = azs[0]; info = a.ips([i["InstanceId"] for i in ins])
    victims = [dict(id=k, **v) for k, v in info.items() if v["az"] == az]
    at = a.lb_attrs(tg); max_out = ctx.setting("ha.max_outage_s", 60)
    res, ev, t0, t1 = isolation_event(a, ctx, victims, f"HA-02 ({az})")
    ses, _, _ = sessions_summary(res, t0)
    ctx.memo["failover"] = dict(kind=f"loss of the gateways of {az}", sessions=ses, t0=t0)
    out, worst, leaks = fmt_outages(res, t0, t1)
    rec = recovered(res, (ev.get("back") or t1) + 30)
    det = (f"Gateways of {az} ({', '.join(v['id'] for v in victims)}) isolated for {round(t1 - t0)} s; GWLB marked them unhealthy {rel(ev.get('detected'), t0)}, "
           f"back to healthy {rel(ev.get('back'), t1)} after restoring. During the loss: {out}. {ses + '. ' if ses else ''}"
           f"GWLB: cross-zone {at.get('load_balancing.cross_zone.enabled')}, target failover on unhealthy '{at.get('target_failover.on_unhealthy')}', "
           f"{at['hc']}. Traffic {'recovered' if rec else 'NOT recovered'} after restoring.")
    ok = worst <= max_out and not leaks and rec
    return ("PASS" if ok else "NOT_MET"), det + f" Criterion: the surviving AZ keeps the service (interruption ≤ {max_out} s)."


@hook("aws.session_failover")
def session_failover(c, ctx):
    m = ctx.memo.get("failover")
    if not m or not m.get("sessions"):
        a = AWS(ctx); ins = a.in_service()
        if len(ins) < 2:
            return "NOT_MET", "precondition not met: fewer than 2 gateways in service"
        info = a.ips([ins[0]["InstanceId"]]); v = [dict(id=k, **x) for k, x in info.items()]
        res, ev, t0, t1 = isolation_event(a, ctx, v, "HA-04")
        ses, _, _ = sessions_summary(res, t0); m = dict(kind=f"isolation of {v[0]['id']}", sessions=ses)
    return "MEASURE", (f"During the {m['kind']}: {m['sessions']}. Sessions that crossed the lost gateway are cut (members of the scaling group do not "
                       "synchronize state); the rest keep working and new sessions go to the surviving gateways.")


@hook("aws.fail_closed")
def fail_closed(c, ctx):
    a = AWS(ctx); ins = a.in_service()
    if not ins:
        return "NOT_MET", "no gateway in service"
    info = a.ips([i["InstanceId"] for i in ins]); victims = [dict(id=k, **v) for k, v in info.items()]
    res, ev, t0, t1 = isolation_event(a, ctx, victims, "HA-03 (whole tier)", sessions=0)
    passed = 0; per = []
    for r in res.values():
        for name, ss in r["samples"].items():
            n = sum(1 for t, ok in ss if t0 + 5 <= t <= t1 and ok)
            passed += n
            if n:
                per.append(f"{(r['env'] or '?').upper()} {name}: {n}")
    rec = recovered(res, (ev.get("back") or t1) + 30)
    o = {a_: outages(r["samples"], t1, None) for a_, r in res.items()}
    back = max((v["longest"] for x in o.values() for k, v in x.items() if k != "denied"), default=0)
    det = (f"All the gateways ({len(victims)}) isolated for {round(t1 - t0)} s (inspection data plane down). Flows that went through while there was no "
           f"firewall: {passed}{' (' + '; '.join(per) + ')' if per else ''}. Service back {rel(ev.get('back'), t1)} after restoring "
           f"(longest interruption after restoring: {back} s); traffic {'recovered' if rec else 'NOT recovered'}.")
    return ("PASS" if passed == 0 and rec else "NOT_MET"), det + " Criterion: no traffic without inspection (fail-closed)."


# ------------------------------------------------------------------ HA-05
@hook("aws.scale_out")
def scale_out(c, ctx):
    a = AWS(ctx); g = a.asg(); n0, max0 = g["DesiredCapacity"], g["MaxSize"]; before = {i["InstanceId"] for i in g["Instances"]}
    timeout, max_out = ctx.setting("ha.provision_timeout_s", 2700), ctx.setting("ha.max_outage_s", 60)
    pol = a.asc.describe_policies(AutoScalingGroupName=a.asg_name)["ScalingPolicies"]
    pols = "; ".join(f"{p['PolicyName'].split('-')[-1] or p['PolicyName']}: {p.get('ScalingAdjustment', p.get('TargetTrackingConfiguration', {}).get('TargetValue', ''))}" for p in pol)
    ids = ctx.start_probes(duration=2 * timeout + 900); time.sleep(30)
    ev, new = {}, None
    try:
        if n0 + 1 > max0:
            a.asc.update_auto_scaling_group(AutoScalingGroupName=a.asg_name, MaxSize=n0 + 1)
        a.asc.set_instance_protection(AutoScalingGroupName=a.asg_name, InstanceIds=list(before), ProtectedFromScaleIn=True)
        t0 = time.time(); log(f"HA-05: desired {n0} → {n0 + 1}")
        a.asc.set_desired_capacity(AutoScalingGroupName=a.asg_name, DesiredCapacity=n0 + 1, HonorCooldown=False)
        new = wait_new_member(a, ctx, before, t0, timeout, ev)
        extra = post_provision(ctx, ev.get("fw_name"), t0) if ev.get("provisioned") else ""
        time.sleep(60); t_mid = time.time()
        fw_new = ev.get("fw_name")
        t1 = time.time(); log(f"HA-05: desired {n0 + 1} → {n0}")
        a.asc.set_desired_capacity(AutoScalingGroupName=a.asg_name, DesiredCapacity=n0, HonorCooldown=False)
        tg = a.tg_arn()
        while time.time() - t1 < 1800:
            g2 = a.asg(); ids_now = {i["InstanceId"] for i in g2["Instances"]}
            if new and new not in ids_now and "gone" not in ev:
                ev["gone"] = time.time()
            if new and new not in a.tg_health(tg) and "dereg" not in ev:
                ev["dereg"] = time.time()
            fw = a.fw_gateways()
            if fw is not None and new and new not in fw and "fw_removed" not in ev:
                ev["fw_removed"] = time.time()
            if ev.get("gone") and ev.get("dereg") and (fw is None or ev.get("fw_removed")):
                break
            time.sleep(15)
    finally:
        a.asc.set_instance_protection(AutoScalingGroupName=a.asg_name, InstanceIds=list(before), ProtectedFromScaleIn=False)
        if a.asg()["DesiredCapacity"] != n0:
            a.asc.set_desired_capacity(AutoScalingGroupName=a.asg_name, DesiredCapacity=n0, HonorCooldown=False)
        if n0 + 1 > max0:
            a.asc.update_auto_scaling_group(AutoScalingGroupName=a.asg_name, MaxSize=max0)
    time.sleep(30)
    res = ctx.collect(ids)
    out, worst, leaks = fmt_outages(res, t0, None)
    det = (f"Scale out {n0} → {n0 + 1}: {new or '-'} launched {rel(ev.get('launched'), t0)}, in service {rel(ev.get('inservice'), t0)}, healthy target "
           f"{rel(ev.get('healthy'), t0)}, with policy in the management {rel(ev.get('provisioned'), t0)}{extra}. Scale in {n0 + 1} → {n0}: target "
           f"deregistered {rel(ev.get('dereg'), t1)}, instance terminated {rel(ev.get('gone'), t1)}, object removed from the management "
           f"{rel(ev.get('fw_removed'), t1)}. {out}. Scaling policies: {pols or 'none'}; group min/max {g['MinSize']}/{max0}.")
    ok = bool(ev.get("provisioned") and ev.get("gone")) and worst <= max_out and not leaks
    return ("PASS" if ok else "NOT_MET"), det + f" Criterion: new member in service with policy, removed cleanly, interruption ≤ {max_out} s."


# ------------------------------------------------------------------ PERF-08
def ec2_price(a, itype):
    try:
        pr = boto3.client("pricing", region_name="us-east-1")
        f = [{"Type": "TERM_MATCH", "Field": k, "Value": v} for k, v in [("instanceType", itype), ("regionCode", a.region), ("operatingSystem", "Linux"),
                                                                           ("tenancy", "Shared"), ("preInstalledSw", "NA"), ("capacitystatus", "Used")]]
        for p in pr.get_products(ServiceCode="AmazonEC2", Filters=f, MaxResults=5)["PriceList"]:
            j = json.loads(p)
            for term in j["terms"]["OnDemand"].values():
                for d in term["priceDimensions"].values():
                    v = float(d["pricePerUnit"]["USD"])
                    if v > 0:
                        return v
    except Exception as e:  # noqa
        log("pricing:", e)
    return None


@hook("aws.load_resources")
def load_resources(c, ctx):
    a = AWS(ctx); g = a.asg(); ins = a.in_service(g); info = a.ips([i["InstanceId"] for i in ins])
    env = (ctx.cfg["roles"].get("perf_client") or None); ag = ctx.agent_for(env if isinstance(env, str) else None)
    srv = ctx.cfg["server"]
    load = [dict(type="iperf", host=srv, port="{NET:exception_port}", seconds=120, streams=8, name="iperf3 8 streams 120 s"),
            dict(type="dl_bench", url=f"http://{srv}/perf/200m.bin", parallel=8, seconds=90, name="8 parallel HTTP downloads 90 s")]
    sampler = HOOKS.get(f"{ctx.vendor}._cpu_sample"); samp = {}
    t0 = time.time(); tid = ctx.task(ag["name"], "checks", dict(checks=load))
    if sampler:
        th = threading.Thread(target=lambda: samp.update(sampler(ctx, 220)), daemon=True); th.start()
    rs = ctx.wait(tid, 900)["results"]; t1 = time.time()
    if sampler:
        th.join(300)
    cw = []
    for i in ins:
        d = a.cw.get_metric_statistics(Namespace="AWS/EC2", MetricName="CPUUtilization", Dimensions=[{"Name": "InstanceId", "Value": i["InstanceId"]}],
                                       StartTime=t0 - 60, EndTime=t1 + 300, Period=60, Statistics=["Maximum"])["Datapoints"]
        cw.append(f"{i['InstanceId']} max {max((x['Maximum'] for x in d), default=0):.0f} %")
    itype = next(iter(info.values()))["type"]; price = ec2_price(a, itype); n = len(ins)
    loads = "; ".join(f"{r['name']}: {r['detail']}" for r in rs)
    gw = "; ".join(f"{k}: {v}" for k, v in samp.items()) if samp else "no per-second sampling for this vendor"
    cost = (f"{n} × {itype} at {price:.4f} USD/h on demand = {n * price:.3f} USD/h of compute (licence, GWLB, endpoints and data processing apart: see COST-*)"
            if price else f"{n} × {itype} (price not available from the Pricing API)")
    return "MEASURE", f"Load from {(ag.get('env') or ag['name']).upper()}: {loads}. Gateway CPU during the load: {gw}. CloudWatch (1 min): {', '.join(cw)}. Cost: {cost}."


# ------------------------------------------------------------------ OPS-01
@hook("aws.cme_least_privilege")
def cme_least_privilege(c, ctx):
    arn = ctx.setting("aws.cme_role_arn")
    if not arn:
        raise Skip("not configured: aws.cme_role_arn (role the management uses to read the account)")
    iam = AWS(ctx).c("iam"); name = arn.split("/")[-1]
    role = iam.get_role(RoleName=name)["Role"]; trust = role["AssumeRolePolicyDocument"]
    docs = [iam.get_role_policy(RoleName=name, PolicyName=p)["PolicyDocument"] for p in iam.list_role_policies(RoleName=name)["PolicyNames"]]
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        v = iam.get_policy(PolicyArn=p["PolicyArn"])["Policy"]["DefaultVersionId"]
        docs.append(iam.get_policy_version(PolicyArn=p["PolicyArn"], VersionId=v)["PolicyVersion"]["Document"])
    acts = set()
    for d in docs:
        for s in (d["Statement"] if isinstance(d["Statement"], list) else [d["Statement"]]):
            if s.get("Effect") == "Allow":
                acts |= set([s["Action"]] if isinstance(s.get("Action"), str) else s.get("Action", []))
    wild = sorted(x for x in acts if x == "*" or x.endswith(":*"))
    allowed_w = set(ctx.setting("aws.cme_allowed_write", []))
    write = sorted(x for x in acts if not re.match(r"^[\w-]+:(Describe|List|Get)", x) and x not in allowed_w and x not in wild)
    sts = trust["Statement"] if isinstance(trust["Statement"], list) else [trust["Statement"]]
    princ = [json.dumps(s.get("Principal")) for s in sts]
    ext = any("sts:ExternalId" in json.dumps(s.get("Condition", {})) for s in sts)
    anyp = any('"*"' in p for p in princ)
    det = (f"Role {name}: {len(acts)} allowed actions ({', '.join(sorted(acts))[:300]}); trusted by {', '.join(princ)[:200]}; "
           f"ExternalId {'required' if ext else 'NOT required'}. Onboarding: the management reads the account with this role (STS AssumeRole, temporary credentials).")
    probs = (["wildcard actions: " + ", ".join(wild)] if wild else []) + (["write actions: " + ", ".join(write)] if write else []) + \
        (["no ExternalId condition"] if not ext else []) + (["any principal can assume it"] if anyp else [])
    return ("NOT_MET", det + " Problems: " + "; ".join(probs)) if probs else ("PASS", det + " Read-only and scoped.")
