#!/bin/bash
# Builds the whole lab from scratch and leaves the portal ready:
#   1 preflight  2 certificates + SSH key  3 policy (Management API)  4 AWS infrastructure (Terraform)
#   5 CME (account + template)  6 gateways registered + policy installed  7 testkit + portal configuration  [8 run]
#   ./deploy/up.sh [--run] [--from N]      (--from resumes at step N)
. "$(dirname "$0")/lib.sh"; load_settings
need terraform jq curl ssh scp openssl
RUN=0; FROM=1
while [ $# -gt 0 ]; do case $1 in --run) RUN=1;; --from) FROM=$2; shift;; *) die "unknown option $1";; esac; shift; done
step() { [ "$1" -ge "$FROM" ]; }

if step 1; then log "1/7 Preflight"
  cp_login || die "management login failed (check MGMT_URL / MGMT_API_KEY in deploy/settings.env)"
  ok "management API $MGMT_API_VERSION"
  M=$(cme GET management | jq -r '.result.name // empty'); [ -n "$M" ] && ok "CME management name: $M" || warn "CME API did not answer; using $CP_MANAGEMENT_NAME"
  cp_logout
  jq -e '.environments|length>1' "$LAB" >/dev/null || die "lab.json needs at least two environments"
  jq -e --arg s "$(lab .server_env)" '[.environments[].name]|index($s)' "$LAB" >/dev/null || die "server_env is not an environment"
  ok "lab: $(lab '[.environments[]|"\(.name) \(.cidr) az-\(.az)"]|join(" · ")')"
fi

if step 2; then log "2/7 Certificates and SSH key"
  "$ROOT/gen_certs.sh" >/dev/null && ok "testkit CA and client certificate in certs/"
  mkdir -p "$SSH_DIR"; chmod 700 "$SSH_DIR"
  [ -s "$SSHK" ] || ssh-keygen -q -t ed25519 -N '' -C firewall-testkit -f "$SSHK"; ok "SSH key deploy/.ssh/id_ed25519"
fi

if step 3; then log "3/7 Policy package $PKG"; "$DEPLOY/mgmt/policy.sh" || die "policy step failed"; fi

if step 4; then log "4/7 AWS infrastructure (Terraform, ~10 min)"
  HASH=""; [ -n "${GW_PASSWORD_HASH:-}" ] && HASH=$GW_PASSWORD_HASH
  jq -n --slurpfile lab "$LAB" --arg region "$AWS_REGION" --arg p "$NAME_PREFIX" --arg admin "$ADMIN_CIDR" --arg key "$SSHK.pub" \
     --arg sic "$SIC_KEY" --arg hash "$HASH" --arg it "$GW_INSTANCE_TYPE" --arg v "$GW_VERSION" --argjson min "$GW_MIN" --argjson max "$GW_MAX" \
     --arg gwa "$MGMT_GW_ADDRESSES" --arg tpl "$CME_TEMPLATE" --arg mgmt "$CP_MANAGEMENT_NAME" --arg img "${TESTKIT_IMAGE:-ghcr.io/gdiaz777/cloud-firewall-testkit:latest}" '
    {region:$region, name_prefix:$p, admin_cidrs:[$admin], ssh_public_key_file:$key,
     environments:($lab[0].environments|map({key:.name, value:{cidr, az}})|from_entries), server_env:$lab[0].server_env,
     internal_cidr:($lab[0].internal_cidr // "10.0.0.0/8"), testkit_image:$img,
     cp_gateway_sic_key:$sic, cp_gateway_password_hash:$hash, cp_gateway_instance_type:$it, cp_gateway_version:$v,
     cp_min_group_size:$min, cp_max_group_size:$max, cp_gateways_addresses:$gwa, cp_configuration_template:$tpl, cp_management_server:$mgmt}' \
     > "$TF/terraform.tfvars.json"
  chmod 600 "$TF/terraform.tfvars.json"
  terraform -chdir="$TF" init -input=false -no-color >/dev/null || die "terraform init failed"
  terraform -chdir="$TF" apply -input=false -auto-approve -no-color > "$STATE/terraform-apply.log" 2>&1 || { tail -20 "$STATE/terraform-apply.log"; die "terraform apply failed (deploy/state/terraform-apply.log)"; }
  ok "$(grep -o 'Apply complete.*' "$STATE/terraform-apply.log")"
fi

if step 5; then log "5/7 CME"; "$DEPLOY/mgmt/cme.sh" || die "CME step failed"; fi
if step 6; then log "6/7 Gateways"; "$DEPLOY/mgmt/gateways.sh" || die "gateways step failed"; fi
if step 7; then log "7/7 Testkit"; "$DEPLOY/testkit.sh" || die "testkit step failed"; fi
[ $RUN = 1 ] && "$DEPLOY/run.sh"
log "Done. Run the tests from the portal or with deploy/run.sh"
