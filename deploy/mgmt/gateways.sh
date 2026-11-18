#!/bin/bash
# Waits until CME has registered at least GW_MIN gateways of the autoscaling group, makes sure HTTPS Inspection is
# enabled on them and installs the policy package (access + threat prevention). Timeout: WAIT_MIN minutes (default 40).
. "$(dirname "$0")/../lib.sh"; load_settings
cp_login || die "management login failed"
GWS() { cp show-simple-gateways '{"limit":100,"details-level":"full"}' | jq -c --arg p "$GW_PREFIX" '[.objects[]|select(.name|startswith($p))|{name,https:."enable-https-inspection",sic:."sic-state"}]'; }
log "Waiting for gateways ${GW_PREFIX}* (CME provisioning takes 10-20 min)"
for i in $(seq 1 $(( ${WAIT_MIN:-40} * 2 ))); do
  L=$(GWS); n=$(jq '[.[]|select(.sic=="communicating")]|length' <<<"$L")
  printf '\r   %s/%s gateways communicating (%s min)  ' "$n" "$GW_MIN" $(( i / 2 ))
  [ "$n" -ge "$GW_MIN" ] && break; sleep 30
done; echo
[ "$n" -ge "$GW_MIN" ] || die "gateways not ready: $L"
ok "$(jq -r 'map(.name)|join(", ")' <<<"$L")"
for g in $(jq -r '.[]|select(.https!=true)|.name' <<<"$L"); do api set-simple-gateway "{\"name\":\"$g\",\"enable-https-inspection\":true}"; CH=1; done
[ -n "${CH:-}" ] && publish
T=$(jq -c '[.[]|select(.sic=="communicating")|.name]' <<<"$L")
for what in access threat-prevention; do
  log "Install $PKG ($what)"
  body=$(jq -nc --arg p "$PKG" --argjson t "$T" --arg w "$what" '{"policy-package":$p, access:($w=="access"), "threat-prevention":($w=="threat-prevention"), targets:$t}')
  r=$(cp install-policy "$body"); tid=$(jq -r '."task-id" // empty' <<<"$r")
  [ -n "$tid" ] || die "install: $(jq -r .message <<<"$r")"; s=$(wait_task "$tid" 1200); [ "$s" = succeeded ] && ok "$s" || die "install $what: $s"
done
cp_logout
