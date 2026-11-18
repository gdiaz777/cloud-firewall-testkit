#!/bin/bash
# Starts the testkit on every test VM (server everywhere — portal only on server_env — plus the client agent) and
# loads the portal configuration generated from lab.json + Terraform outputs.
. "$(dirname "$0")/lib.sh"; load_settings
ENVJ=$(tfo environments) || die "no Terraform outputs"
SRV=$(lab .server_env); SIP=$(jq -r --arg s "$SRV" '.[$s].workload_ip' <<<"$ENVJ")
IMG=${TESTKIT_IMAGE:-ghcr.io/gdiaz777/cloud-firewall-testkit:latest}
for f in testkit_ca.crt testkit_ca.key client.crt client.key inspection_ca.crt; do [ -s "$CERTS/$f" ] || die "missing certs/$f"; done
deploy_vm() { local e=$1 h ip portal=0; h=$(jq -r --arg e "$e" '.[$e].mgmt_public_ip' <<<"$ENVJ"); ip=$(jq -r --arg e "$e" '.[$e].workload_ip' <<<"$ENVJ")
  [ "$e" = "$SRV" ] && portal=1
  for i in $(seq 1 60); do ssh_vm "$h" test -f /var/lib/testkit-bootstrap-done 2>/dev/null && break; sleep 10; done
  scp_vm "$h" "$CERTS"/{testkit_ca.crt,testkit_ca.key,client.crt,client.key,inspection_ca.crt} || { warn "$e: scp failed"; return 1; }
  ssh_vm "$h" "sudo bash -s" <<EOS
set -e
D=/opt/fw-testkit; mkdir -p \$D/certs; cd /tmp
install -m644 testkit_ca.crt inspection_ca.crt client.crt \$D/certs/; install -m600 testkit_ca.key client.key \$D/certs/; rm -f testkit_ca.key client.key
printf 'TESTKIT_ENV=$e\nSRC_IP=$ip\nSERVER_IP=$SIP\nPORTAL=$portal\nPORTAL_URL=http://$SIP/portal\n' > \$D/.env
docker pull -q $IMG >/dev/null
docker rm -f tk-server tk-client >/dev/null 2>&1 || true
docker run -d --name tk-server --restart unless-stopped --network host --env-file \$D/.env -v \$D/certs:/opt/testkit/certs:ro -v testkit-data:/data $IMG server >/dev/null
docker run -d --name tk-client --restart unless-stopped --network host --cap-add NET_RAW --cap-add NET_ADMIN --env-file \$D/.env -v \$D/certs:/opt/testkit/certs:ro $IMG client >/dev/null
EOS
  ok "$e ($ip) running"; }
log "Testkit containers"
for e in $(jq -r 'keys[]' <<<"$ENVJ"); do deploy_vm "$e" & done; wait

log "Portal configuration"
CN=$(cat "$STATE/inspection_ca_cn" 2>/dev/null)
CONF=$(jq -c --argjson env "$ENVJ" --arg cn "${CN:-HTTPS Inspection}" '{server_env, environments:[.environments[]|{name, ip:$env[.name].workload_ip, az, description}],
  segmentation, roles, peers, internet:(.internet|del(.geo_blocked_countries)), inspection_ca_match:$cn}' "$LAB")
H=$(jq -r --arg s "$SRV" '.[$s].mgmt_public_ip' <<<"$ENVJ")
for i in $(seq 1 30); do ssh_vm "$H" "curl -sf -o /dev/null http://127.0.0.1/portal/api/catalog" && break; sleep 5; done
printf '%s' "$CONF" | ssh_vm "$H" "curl -sf -X PUT -H 'Content-Type: application/json' --data @- http://127.0.0.1/portal/api/config" >/dev/null && ok "configuration loaded" || warn "could not load the configuration"
sleep 20
A=$(ssh_vm "$H" "curl -s http://127.0.0.1/portal/api/agents" | jq -r '[.[]|select(.online)|.name]|join(", ")')
ok "agents online: ${A:-none yet}"
echo "   Portal: ${B}http://$H/portal/${N}  (allowed from $ADMIN_CIDR)"
