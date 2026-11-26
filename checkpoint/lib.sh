#!/bin/bash
# Helpers for the Check Point baseline tool (Management API). Source it: . "$(dirname "$0")/lib.sh"
set -o pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SETTINGS="$HERE/settings.env"
OUT="$HERE/out"; mkdir -p "$OUT"
CONFIG=${CONFIG:-$OUT/config.json}
B=$'\e[1m'; G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; N=$'\e[0m'
log()  { printf '%s\n' "${B}==${N} $*"; }
ok()   { printf '   %s\n' "${G}✔${N} $*"; }
warn() { printf '   %s\n' "${Y}!${N} $*"; }
die()  { printf '%s\n' "${R}✘ $*${N}" >&2; exit 1; }
need() { for c in "$@"; do command -v "$c" >/dev/null || die "missing tool: $c"; done; }

load_settings() {
  # MGMT_URL / MGMT_API_KEY (/ POLICY_PACKAGE) can come from the environment (e.g. another automation)
  if [ -z "${MGMT_URL:-}" ] || [ -z "${MGMT_API_KEY:-}" ]; then
    [ -s "$SETTINGS" ] || die "no settings: run ./cp-baseline.sh setup first"
    set -a; . "$SETTINGS"; set +a
  fi
  PKG=${POLICY_PACKAGE:-FW_Testkit}
  # Self-signed management certificate whose name does not match MGMT_URL (e.g. a management reached by its public
  # IP): MGMT_TLS_CERT=<PEM file of that certificate> pins its public key instead of checking the name.
  CURL_TLS=()
  if [ -n "${MGMT_TLS_CERT:-}" ]; then
    [ -s "$MGMT_TLS_CERT" ] || die "MGMT_TLS_CERT not found: $MGMT_TLS_CERT"
    CURL_TLS=(-k --pinnedpubkey "sha256//$(openssl x509 -in "$MGMT_TLS_CERT" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)")
  fi
}
lab() { [ -s "$CONFIG" ] || die "no configuration: $CONFIG"; jq -r "$@" "$CONFIG"; }

# ------------------------------------------------------------------ Management API (one session per process)
# Note: cp() is the Management API call; use "command cp" to copy files.
SID_FILE="$OUT/.sid.$$"
cp_login() {
  local r; r=$(jq -n --arg k "$MGMT_API_KEY" '{"api-key":$k,"session-name":"firewall-testkit-baseline","session-timeout":3600}' \
    | curl -sS "${CURL_TLS[@]}" -X POST -H 'Content-Type: application/json' --data @- "$MGMT_URL/login")
  (umask 077; jq -r '.sid // empty' <<<"$r" > "$SID_FILE")
  [ -s "$SID_FILE" ] || { echo "login failed: $(jq -c 'del(.sid)' <<<"$r" 2>/dev/null || echo "$r" | head -c 200)" >&2; return 1; }
  MGMT_API_VERSION=$(jq -r '."api-server-version"' <<<"$r")
}
cp() { curl -sS "${CURL_TLS[@]}" -X POST -H 'Content-Type: application/json' -H "X-chkp-sid: $(cat "$SID_FILE")" --data "${2:-{\}}" "$MGMT_URL/$1"; }
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
