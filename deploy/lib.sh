#!/bin/bash
# Shared helpers for deploy/*.sh. Source it: . "$(dirname "$0")/lib.sh"
set -o pipefail
DEPLOY=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$DEPLOY/.." && pwd)
TF="$DEPLOY/terraform"
STATE="$DEPLOY/state"; mkdir -p "$STATE"
SETTINGS="$DEPLOY/settings.env"
LAB="$STATE/lab.json"
CERTS="$ROOT/certs"
SSH_DIR="$DEPLOY/.ssh"
B=$'\e[1m'; G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; N=$'\e[0m'

log()  { printf '%s\n' "${B}==${N} $*"; }
ok()   { printf '   %s\n' "${G}✔${N} $*"; }
warn() { printf '   %s\n' "${Y}!${N} $*"; }
die()  { printf '%s\n' "${R}✘ $*${N}" >&2; exit 1; }
need() { for c in "$@"; do command -v "$c" >/dev/null || die "missing tool: $c"; done; }

load_settings() {
  [ -s "$SETTINGS" ] || die "no settings: run deploy/setup.sh first"
  set -a; . "$SETTINGS"; set +a
  [ -s "$LAB" ] || cp "$DEPLOY/lab.example.json" "$LAB"
  PKG=${POLICY_PACKAGE:-FW_Testkit}
  CME_TEMPLATE=${CME_TEMPLATE:-${NAME_PREFIX}-tpl}
  CME_ACCOUNT=${CME_ACCOUNT:-${NAME_PREFIX}-aws}
  GW_PREFIX="${CME_ACCOUNT}--"
  [ -n "${AWS_PROFILE:-}" ] && export AWS_PROFILE || unset AWS_PROFILE
  export AWS_REGION
}

lab() { jq -r "$@" "$LAB"; }
tfo() { terraform -chdir="$TF" output -json "$1" 2>/dev/null; }

SSHK="$SSH_DIR/id_ed25519"
ssh_vm() { local h=$1; shift; ssh -i "$SSHK" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$SSH_DIR/known_hosts" -o ConnectTimeout=10 -o LogLevel=ERROR ubuntu@"$h" "$@"; }
scp_vm() { local h=$1; shift; scp -q -i "$SSHK" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$SSH_DIR/known_hosts" "$@" ubuntu@"$h":/tmp/; }

# ------------------------------------------------------------------ Management API (session per process)
SID_FILE="$STATE/.sid.$$"
cp_login() {
  local r; r=$(jq -n --arg k "$MGMT_API_KEY" '{"api-key":$k,"session-name":"firewall-testkit","session-timeout":3600}' \
    | curl -sS -X POST -H 'Content-Type: application/json' --data @- "$MGMT_URL/login")
  (umask 077; jq -r '.sid // empty' <<<"$r" > "$SID_FILE")
  [ -s "$SID_FILE" ] || { echo "login failed: $(jq -c 'del(.sid)' <<<"$r" 2>/dev/null || echo "$r" | head -c 200)" >&2; return 1; }
  MGMT_API_VERSION=$(jq -r '."api-server-version"' <<<"$r")
}
cp() { curl -sS -X POST -H 'Content-Type: application/json' -H "X-chkp-sid: $(cat "$SID_FILE")" --data "${2:-{\}}" "$MGMT_URL/$1"; }
cme() { # cme <METHOD> <path> [json-on-stdin-if-3rd-arg]
  if [ -n "${3:-}" ]; then printf '%s' "$3" | curl -sS -X "$1" -H 'Content-Type: application/json' -H "X-chkp-sid: $(cat "$SID_FILE")" --data @- "$MGMT_URL/cme-api/v1/$2"
  else curl -sS -X "$1" -H 'Content-Type: application/json' -H "X-chkp-sid: $(cat "$SID_FILE")" "$MGMT_URL/cme-api/v1/$2"; fi
}
wait_task() {
  local s i; for i in $(seq 1 $(( ${2:-600} / 5 ))); do
    s=$(cp show-task "{\"task-id\":\"$1\"}" | jq -r '.tasks[0].status'); [ "$s" != "in progress" ] && break; sleep 5; done; echo "$s"; }
api() { # api <command> <json> → one summary line; waits for async tasks; returns 1 on error
  local r t; r=$(cp "$1" "$2")
  if jq -e '.code' >/dev/null 2>&1 <<<"$r"; then
    printf '   %-30s %s\n' "$1" "$(jq -r '[.code,.message,(.errors//[]|.[].message),(.warnings//[]|.[].message)]|join(" | ")' <<<"$r" | head -c 220)"; return 1; fi
  t=$(jq -r '."task-id" // empty' <<<"$r")
  if [ -n "$t" ]; then printf '   %-30s task %s\n' "$1" "$(wait_task "$t")"; else printf '   %-30s ok %s\n' "$1" "$(jq -r '.name // .uid // ""' <<<"$r")"; fi
}
exists() { cp show-objects "{\"filter\":\"$2\",\"type\":\"$1\",\"limit\":50}" | jq -e --arg n "$2" '[.objects[]?|select(.name==$n)]|length>0' >/dev/null; }
publish() { api publish '{}'; }
cp_logout() { [ -s "$SID_FILE" ] && cp logout '{}' >/dev/null; rm -f "$SID_FILE"; }
trap 'rm -f "$SID_FILE"' EXIT
