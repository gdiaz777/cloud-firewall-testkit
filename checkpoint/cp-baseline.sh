#!/bin/bash
# Check Point baseline for Firewall Testkit (optional annex).
# Configures a Check Point management (e.g. Smart-1 Cloud) through the Management API with a policy package that
# follows Check Point best practices and implements what the testkit configuration expects (segmentation matrix,
# egress control, Threat Prevention per flow type, Content Awareness, HTTPS Inspection).
#
#   ./cp-baseline.sh setup                               management URL + API key → checkpoint/settings.env
#   ./cp-baseline.sh apply --portal http://SERVER/portal [--push-ca]
#   ./cp-baseline.sh apply --config file.json [--testkit-ca ca.crt]
#   ./cp-baseline.sh install GATEWAY... | --prefix PREFIX  install the package (access + threat prevention)
#   ./cp-baseline.sh remove [--gateways-prefix PREFIX]   delete the package and every TK_ object
#
# The configuration is the portal one (Settings): every environment needs a CIDR. --portal downloads it together
# with the testkit CA; --push-ca uploads the HTTPS Inspection CA back to the portal so clients trust it.
HERE=$(cd "$(dirname "$0")" && pwd); . "$HERE/lib.sh"
need curl jq openssl
cmd=${1:-help}; shift || true

case $cmd in
setup)
  [ -s "$SETTINGS" ] && { set -a; . "$SETTINGS"; set +a; }
  ask() { local cur=${!1:-$3} v; if [ "${4:-}" = secret ]; then read -r -s -p "  $2 [${cur:+********}]: " v; echo; else read -r -p "  $2 [${cur}]: " v; fi; printf -v "$1" '%s' "${v:-$cur}"; }
  echo "${B}Check Point baseline · setup${N}"
  echo "   Smart-1 Cloud: Infinity Portal → Smart-1 Cloud → Settings → API & SmartConsole (web API URL and API key)."
  echo "   On-premises: https://<management>/web_api with an API key of an administrator with read-write permissions."
  ask MGMT_URL "Management web API URL" ""; MGMT_URL=${MGMT_URL%/}; MGMT_URL=${MGMT_URL%/login}
  ask MGMT_API_KEY "API key" "" secret
  ask POLICY_PACKAGE "Policy package to create" "${POLICY_PACKAGE:-FW_Testkit}"
  cp_login && ok "login OK (Management API $MGMT_API_VERSION)" || die "cannot log in to $MGMT_URL"; cp_logout
  umask 077; printf 'MGMT_URL=%s\nMGMT_API_KEY=%s\nPOLICY_PACKAGE=%s\n' "$MGMT_URL" "$MGMT_API_KEY" "$POLICY_PACKAGE" > "$SETTINGS"
  ok "saved to checkpoint/settings.env (not versioned)";;

apply)
  load_settings; PORTAL=""; PUSH=0
  while [ $# -gt 0 ]; do case $1 in
    --portal) PORTAL=${2%/}; shift;; --config) command cp "$2" "$CONFIG"; shift;; --testkit-ca) command cp "$2" "$OUT/testkit_ca.crt"; shift;;
    --push-ca) PUSH=1;; *) die "unknown option $1";; esac; shift; done
  if [ -n "$PORTAL" ]; then
    curl -sf "$PORTAL/api/config" > "$CONFIG" || die "cannot read $PORTAL/api/config"
    curl -sf "$PORTAL/api/bootstrap" | jq -r '.testkit_ca // empty' > "$OUT/testkit_ca.crt" || warn "could not read the testkit CA from the portal"
    ok "configuration and testkit CA read from $PORTAL"
  fi
  [ -s "$CONFIG" ] || die "give --portal URL or --config file"
  CONFIG=$CONFIG "$HERE/policy.sh" || die "policy failed"
  if [ $PUSH = 1 ] && [ -n "$PORTAL" ] && [ -s "$OUT/inspection_ca.crt" ]; then
    jq --rawfile ca "$OUT/inspection_ca.crt" '.inspection_ca_pem=$ca | del(._server_ip)' "$CONFIG" \
      | curl -sf -X PUT -H 'Content-Type: application/json' --data @- "$PORTAL/api/config" >/dev/null \
      && ok "HTTPS Inspection CA uploaded to the portal (clients will trust it)" || warn "could not upload the CA to the portal"
  fi;;

install)
  load_settings; cp_login || die "login failed"
  if [ "${1:-}" = --prefix ]; then T=$(cp show-simple-gateways '{"limit":200}' | jq -c --arg p "$2" '[.objects[].name|select(startswith($p))]')
  else T=$(printf '%s\n' "$@" | jq -Rcs 'split("\n")|map(select(length>0))'); fi
  [ "$T" != "[]" ] || die "no gateways given"
  CUR=$(cp show-package "{\"name\":\"$PKG\"}" | jq -c '."installation-targets" | if type=="array" then map(.name) else . end')
  if [ "$CUR" != '"all"' ]; then MISS=$(jq -c --argjson c "$CUR" '[.[]|select(. as $g|$c|index($g)|not)]' <<<"$T")
    [ "$MISS" != "[]" ] && { api set-package "{\"name\":\"$PKG\",\"installation-targets\":{\"add\":$MISS}}" && publish; }; fi
  for what in access threat-prevention; do
    log "Install $PKG ($what) on $(jq -r 'join(", ")' <<<"$T")"
    body=$(jq -nc --arg p "$PKG" --argjson t "$T" --arg w "$what" '{"policy-package":$p, access:($w=="access"), "threat-prevention":($w=="threat-prevention"), targets:$t}')
    for try in $(seq 1 10); do   # another install in progress (e.g. CME) makes it fail: retry
      r=$(cp install-policy "$body"); tid=$(jq -r '."task-id" // empty' <<<"$r"); [ -n "$tid" ] || die "install: $(jq -r .message <<<"$r")"
      s=$(wait_task "$tid" 1200); [ "$s" = succeeded ] && { ok "$s"; break; }
      [ "$try" -lt 10 ] || die "install $what: $s"; warn "attempt $try: $s — retrying in 60 s"; sleep 60
    done
  done; cp_logout;;

remove)
  load_settings; cp_login || die "login failed"; PFX=""; [ "${1:-}" = --gateways-prefix ] && PFX=$2
  if [ -n "$PFX" ]; then for g in $(cp show-simple-gateways '{"limit":200}' | jq -r --arg p "$PFX" '.objects[].name|select(startswith($p))'); do api delete-simple-gateway "{\"name\":\"$g\",\"ignore-warnings\":true}"; done; fi
  api delete-package "{\"name\":\"$PKG\",\"ignore-warnings\":true}"
  api delete-access-layer '{"name":"TK Egress Internet"}'; api delete-https-layer '{"name":"TK HTTPS Outbound"}'
  for p in TK_EastWest TK_Strict TK_Detect; do api delete-threat-profile "{\"name\":\"$p\"}"; done
  for s in TK_Blocked_FQDN TK_Blocked_Path TK_NoDecrypt; do api delete-application-site "{\"name\":\"$s\"}"; done
  for s in TK_exception_port TK_http_sig TK_https_sig; do api delete-service-tcp "{\"name\":\"$s\"}"; done
  api delete-group '{"name":"TK_Envs"}'
  for n in $(cp show-objects '{"type":"network","filter":"TK_","limit":200}' | jq -r '.objects[]?.name|select(startswith("TK_"))'); do api delete-network "{\"name\":\"$n\",\"ignore-warnings\":true}"; done
  publish; cp_logout;;

*) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//';;
esac
