#!/bin/bash
# Launches the full batch on every online agent, waits for it and downloads the Word reports (EN/ES) and the CSV
# to reports/<run-id>/.   ./deploy/run.sh [check or case IDs…]
. "$(dirname "$0")/lib.sh"; load_settings
ENVJ=$(tfo environments) || die "no Terraform outputs"
H=$(jq -r --arg s "$(lab .server_env)" '.[$s].mgmt_public_ip' <<<"$ENVJ")
P="http://127.0.0.1/portal/api"
AG=$(ssh_vm "$H" "curl -s $P/agents" | jq -c '[.[]|select(.online)|.name]')
[ "$AG" != "[]" ] || die "no agent online"
IDS=$(printf '%s\n' "$@" | jq -Rcs 'split("\n")|map(select(length>0))')
BODY=$(jq -nc --argjson a "$AG" --argjson i "$IDS" '{agents:$a, ids:$i, label:(if ($i|length)>0 then ($i|join(", ")) else "Full batch" end)}')
RID=$(printf '%s' "$BODY" | ssh_vm "$H" "curl -s -X POST -H 'Content-Type: application/json' --data @- $P/runs" | jq -r .id)
log "Run $RID on $(jq -r 'join(", ")' <<<"$AG")"
while :; do
  R=$(ssh_vm "$H" "curl -s $P/runs/$RID")
  printf '\r   %s   ' "$(jq -r '[.agents|to_entries[]|"\(.key): \(.value.results|length)/\(.value.total // "?") \(.value.status)"]|join(" · ")' <<<"$R")"
  [ "$(jq '[.agents[].status]|map(select(.!="done"))|length' <<<"$R")" = 0 ] && break; sleep 15
done; echo
jq -r '"   OK \([.agents[].results[]|select(.status=="OK")]|length) · FAIL \([.agents[].results[]|select(.status=="FAIL" or .status=="ERROR")]|length) · INFO \([.agents[].results[]|select(.status=="INFO")]|length) · N/A \([.agents[].results[]|select(.status=="SKIP")]|length)"' <<<"$R"
jq -r '.agents|to_entries[]|.key as $a|.value.results[]|select(.status=="FAIL" or .status=="ERROR")|"   ✘ \($a) \(.id) \(.name): \(.detail)"' <<<"$R"
OUT="$ROOT/reports/$RID"; mkdir -p "$OUT"; printf '%s' "$R" > "$OUT/run.json"
for l in en es; do ssh_vm "$H" "curl -s -o /tmp/r.docx '$P/runs/$RID/report?lang=$l' && cat /tmp/r.docx" > "$OUT/report_$l.docx"; done
ssh_vm "$H" "curl -s $P/runs/$RID/csv" > "$OUT/results.csv"
ok "reports in reports/$RID/ (report_en.docx, report_es.docx, results.csv)"
