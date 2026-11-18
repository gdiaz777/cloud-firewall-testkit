#!/bin/bash
# CME: AWS account through STS (keys read from the Terraform state, sent on stdin, never printed) and the
# autoprovisioning template that binds the autoscaling group to the policy package, with HTTPS Inspection on.
. "$(dirname "$0")/../lib.sh"; load_settings
cp_login || die "management login failed"
show() { jq -r '"   \(."status-code" // "?") \(.error.message // "ok") \(.error.details // "")"'; }
STS=$(tfo cme_sts) || die "no Terraform outputs (run the infrastructure step first)"
# CME (Smart-1 Cloud) always needs access keys. Mode "user": keys of the IAM user created by Terraform in this
# account. Mode "role": keys of a broker IAM user in ANOTHER account (CME_BROKER_ACCESS_KEY_ID / _SECRET in
# settings.env) that may only assume this account's role — for accounts whose SCPs forbid access keys.
if [ "$(jq -r .access_key_id <<<"$STS")" = "" ]; then
  [ -n "${CME_BROKER_ACCESS_KEY_ID:-}" ] && [ -n "${CME_BROKER_SECRET_ACCESS_KEY:-}" ] || die "role mode: set CME_BROKER_ACCESS_KEY_ID / CME_BROKER_SECRET_ACCESS_KEY in settings.env"
  STS=$(jq -c --arg k "$CME_BROKER_ACCESS_KEY_ID" --arg s "$CME_BROKER_SECRET_ACCESS_KEY" '.access_key_id=$k | .secret_access_key=$s' <<<"$STS")
fi
ACC=$(jq -c --arg n "$CME_ACCOUNT" --arg r "$AWS_REGION" '{name:$n, regions:[$r], access_key:.access_key_id, secret_key:.secret_access_key,
      sts_role:.role_arn, sts_external_id:.external_id, scan_gateways:true, scan_vpn:false, scan_load_balancers:false, scan_subnets:false}' <<<"$STS")
log "CME account $CME_ACCOUNT"
if cme GET accounts | jq -e --arg n "$CME_ACCOUNT" '[.result[]?|select(.name==$n)]|length>0' >/dev/null; then
  cme PUT "accounts/$CME_ACCOUNT" "$(jq -c 'del(.name)' <<<"$ACC")" | show
else cme POST accounts/aws "$ACC" | show; fi
log "CME template $CME_TEMPLATE → $PKG"
TPL=$(jq -nc --arg n "$CME_TEMPLATE" --arg a "$CME_ACCOUNT" --arg s "$(printf %s "$SIC_KEY" | base64)" --arg p "$PKG" --arg v "${GW_VERSION%%-*}" \
  '{name:$n, related_account:$a, version:$v, base64_sic_key:$s, policy:$p,
    blades:{"application-control":true, "url-filtering":true, "content-awareness":true, ips:true, "anti-bot":true, "anti-virus":true, "https-inspection":true}}')
if cme GET gwConfigurations | jq -e --arg n "$CME_TEMPLATE" '[.result[]?|select(.name==$n)]|length>0' >/dev/null; then
  cme PUT "gwConfigurations/aws/$CME_TEMPLATE" "$(jq -c 'del(.name)' <<<"$TPL")" | show
else cme POST gwConfigurations/aws "$TPL" | show; fi
cp_logout
