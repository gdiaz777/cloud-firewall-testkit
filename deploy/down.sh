#!/bin/bash
# Destroys the lab: CME template and account, (optionally) every policy object created by the kit, and the AWS
# infrastructure.   ./deploy/down.sh [--purge-policy] [--yes]
. "$(dirname "$0")/lib.sh"; load_settings
PURGE=0; YES=0
for a in "$@"; do case $a in --purge-policy) PURGE=1;; --yes) YES=1;; *) die "unknown option $a";; esac; done
[ $YES = 1 ] || { read -r -p "Destroy the lab in $AWS_REGION (prefix $NAME_PREFIX)$([ $PURGE = 1 ] && echo " and delete package $PKG")? [y/N] " a; [ "$a" = y ] || exit 1; }
cp_login || die "management login failed"
log "CME"
cme DELETE "gwConfigurations/$CME_TEMPLATE" | jq -r '"   template: \(."status-code") \(.error.message // "deleted")"'
cme DELETE "accounts/$CME_ACCOUNT" | jq -r '"   account: \(."status-code") \(.error.message // "deleted")"'
cp_logout
log "AWS infrastructure (Terraform)"
terraform -chdir="$TF" destroy -input=false -auto-approve -no-color > "$STATE/terraform-destroy.log" 2>&1 && ok "$(grep -o 'Destroy complete.*' "$STATE/terraform-destroy.log")" || { tail -20 "$STATE/terraform-destroy.log"; die "terraform destroy failed"; }
if [ $PURGE = 1 ]; then
  cp_login || die "management login failed"
  log "Policy objects"
  # Gateway objects left by CME still have the package installed: remove them first
  for g in $(cp show-simple-gateways '{"limit":100}' | jq -r --arg p "$GW_PREFIX" '.objects[].name|select(startswith($p))'); do api delete-simple-gateway "{\"name\":\"$g\",\"ignore-warnings\":true}"; done
  api delete-package "{\"name\":\"$PKG\",\"ignore-warnings\":true}"
  for l in "TK Egress Internet"; do api delete-access-layer "{\"name\":\"$l\"}"; done
  api delete-https-layer '{"name":"TK HTTPS Outbound"}'
  for p in TK_EastWest TK_Strict TK_Detect; do api delete-threat-profile "{\"name\":\"$p\"}"; done
  for s in TK_Blocked_FQDN TK_Blocked_Path TK_NoDecrypt; do api delete-application-site "{\"name\":\"$s\"}"; done
  for s in TK_exception_port TK_http_sig TK_https_sig; do api delete-service-tcp "{\"name\":\"$s\"}"; done
  api delete-group '{"name":"TK_Envs"}'
  for e in $(lab '.environments[].name') Internal; do api delete-network "{\"name\":\"TK_$e\",\"ignore-warnings\":true}"; done
  publish
  cp_logout
fi
