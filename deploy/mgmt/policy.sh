#!/bin/bash
# Builds the whole policy package from deploy/state/lab.json through the Management API and publishes it.
# Idempotent: existing objects and rules (by name) are kept. Everything is prefixed TK_ and tagged firewall-testkit.
#
#  Access:   Content Awareness (PCI/IBAN, executables, optional DLP exception) → exception port between environments
#            → one Accept rule per allowed pair of the segmentation matrix → isolation → Internet (inline layer) → cleanup
#  Egress:   GEO, applications, URL categories, high-risk apps, custom sites, HTTP/HTTPS with protocol signature + DNS
#  Threat:   per-flow profiles (east-west / Internet / Detect), OT/SCADA protections deactivated by tags on east-west,
#            exceptions (exception port, IPS-04), optional IDS rule towards the ids_target environment
#  HTTPS:    outbound CA, testkit CA trusted, own HTTPS layer with bypasses (FQDN, recommended list, sensitive
#            categories) and Inspect east-west and Internet; server-certificate validation
. "$(dirname "$0")/../lib.sh"; load_settings
cp_login || die "management login failed"
TAGS='"tags":["firewall-testkit"]'
NETL="$PKG Network"; TPL="$PKG Threat Prevention"; IL="TK Egress Internet"; HL="TK HTTPS Outbound"
EW=TK_EastWest; ST=TK_Strict; DT=TK_Detect
INTERNAL=$(lab '.internal_cidr // "10.0.0.0/8"')
SRV=$(lab .server_env)
role() { lab --arg r "$1" '.roles[$r] // empty | if type=="array" then .[] else . end'; }
svc() { case $1 in icmp) echo echo-request;; http) echo http;; https) echo https;; ssh) echo ssh;; rdp) echo Remote_Desktop_Protocol;;
        tcp8080) echo HTTP_proxy;; iperf3) echo TK_exception_port;; *) echo "$1";; esac; }
rule_exists() { cp "show-${1}-rule" "{\"name\":\"$3\",\"layer\":\"$2\"}" | jq -e '.uid' >/dev/null; }

log "Objects"
for e in $(lab '.environments[].name'); do
  c=$(lab --arg e "$e" '.environments[]|select(.name==$e).cidr')
  exists network "TK_$e" || api add-network "{\"name\":\"TK_$e\",\"subnet\":\"${c%/*}\",\"mask-length\":${c#*/},$TAGS}"
done
G=$(lab -c '[.environments[].name|"TK_"+.]')
exists group TK_Envs && api set-group "{\"name\":\"TK_Envs\",\"members\":$G}" || api add-group "{\"name\":\"TK_Envs\",\"members\":$G,$TAGS}"
exists network TK_Internal || api add-network "{\"name\":\"TK_Internal\",\"subnet\":\"${INTERNAL%/*}\",\"mask-length\":${INTERNAL#*/},$TAGS}"
P=$(lab '.internet.exception_port // 5201')
exists service-tcp TK_exception_port || api add-service-tcp "{\"name\":\"TK_exception_port\",\"port\":\"$P\",$TAGS}"
exists service-tcp TK_http_sig  || api add-service-tcp "{\"name\":\"TK_http_sig\",\"port\":\"80\",\"protocol\":\"HTTP\",\"match-by-protocol-signature\":true,$TAGS}"
exists service-tcp TK_https_sig || api add-service-tcp "{\"name\":\"TK_https_sig\",\"port\":\"443\",\"protocol\":\"ENC-HTTP\",\"match-by-protocol-signature\":true,$TAGS}"
site() { exists application-site "$1" || api add-application-site "$(jq -nc --arg n "$1" --argjson u "$2" '{name:$n, "primary-category":"Custom_Application_Site", "url-list":$u, "urls-defined-as-regular-expression":false, tags:["firewall-testkit"]}')"; }
site TK_Blocked_FQDN "$(lab -c '[.internet.blocked_fqdn, (.internet.blocked_fqdn|sub("^www\\.";""))]')"
site TK_Blocked_Path "$(lab -c '[.internet.allowed_site + .internet.blocked_path]')"
site TK_NoDecrypt '["nodecrypt.testkit.lab","mtls.testkit.lab"]'
cp update-updatable-objects-repository-content '{}' >/dev/null
uo() { exists updatable-object "$1" && return 0
  local u; u=$(cp show-updatable-objects-repository-content "{\"filter\":{\"text\":\"$1\"},\"limit\":20}" | jq -r --arg n "$1" '[.objects[]?|select(."name-in-updatable-objects-repository"|ascii_downcase==($n|ascii_downcase))][0]."uid-in-updatable-objects-repository" // empty')
  [ -n "$u" ] && api add-updatable-object "{\"uid-in-updatable-objects-repository\":\"$u\"}" || warn "updatable object not found: $1"; }
GEO=$(lab -c '.internet.geo_blocked_countries // []'); for g in $(jq -r '.[]|@base64' <<<"$GEO"); do uo "$(base64 -d <<<"$g")"; done
uo "HTTPS services - recommended bypass"

log "Package $PKG"
if ! cp show-package "{\"name\":\"$PKG\"}" | jq -e .uid >/dev/null; then
  api add-package "{\"name\":\"$PKG\",\"access\":true,\"threat-prevention\":true,\"comments\":\"Firewall Testkit\",$TAGS}" || die "cannot create package"
fi
api set-access-layer "{\"name\":\"$NETL\",\"applications-and-url-filtering\":true,\"content-awareness\":true}"
exists access-layer "$IL" || api add-access-layer "{\"name\":\"$IL\",\"applications-and-url-filtering\":true,\"content-awareness\":false,\"add-default-rule\":true,$TAGS}"

log "Access rules ($NETL)"
AR() { local n; n=$(jq -r .name <<<"$2"); rule_exists access "$1" "$n" && return 0
  api add-access-rule "$(jq -c --arg l "$1" '. + {layer:$l, position:{"above":"Cleanup rule"}, "ignore-warnings":true}' <<<"$2")"; }
HTTPS2='["http","https"]'
D=$(role dlp_exception_client)
[ -n "$D" ] && AR "$NETL" "{\"name\":\"TK DLP exception $D -> $SRV\",\"source\":[\"TK_$D\"],\"destination\":[\"TK_$SRV\"],\"service\":$HTTPS2,\"content\":[\"PCI - Credit Card Numbers\",\"International Bank Account Number - IBAN\"],\"content-direction\":\"up\",\"action\":\"Accept\",\"track\":{\"type\":\"Log\"}}"
AR "$NETL" "{\"name\":\"TK CA - block card numbers and IBAN\",\"source\":[\"TK_Envs\"],\"destination\":[\"TK_Envs\"],\"service\":$HTTPS2,\"content\":[\"PCI - Credit Card Numbers\",\"International Bank Account Number - IBAN\"],\"content-direction\":\"any\",\"action\":\"Drop\",\"track\":{\"type\":\"Log\"}}"
AR "$NETL" "{\"name\":\"TK CA - block executables\",\"source\":[\"TK_Envs\"],\"destination\":[\"TK_Envs\"],\"service\":$HTTPS2,\"content\":[\"Executable File\"],\"content-direction\":\"any\",\"action\":\"Drop\",\"track\":{\"type\":\"Log\"}}"
ALW=$(lab -c '[.segmentation.always[]?]'); if [ "$ALW" != "[]" ]; then
  S=$(jq -c '[.[]]' <<<"$ALW" | jq -r '.[]' | while read -r x; do svc "$x"; done | jq -Rcs 'split("\n")|map(select(length>0))')
  AR "$NETL" "{\"name\":\"TK exception - between all environments\",\"source\":[\"TK_Envs\"],\"destination\":[\"TK_Envs\"],\"service\":$S,\"action\":\"Accept\",\"track\":{\"type\":\"Log\",\"accounting\":true}}"
fi
for pair in $(lab -r '.segmentation.allow | keys[]'); do
  s=${pair%>*}; d=${pair#*>}
  S=$(lab -r --arg p "$pair" '.segmentation.allow[$p][]' | while read -r x; do svc "$x"; done | jq -Rcs 'split("\n")|map(select(length>0))')
  AR "$NETL" "{\"name\":\"TK allow $s -> $d\",\"source\":[\"TK_$s\"],\"destination\":[\"TK_$d\"],\"service\":$S,\"action\":\"Accept\",\"track\":{\"type\":\"Log\"}}"
done
AR "$NETL" '{"name":"TK isolation - rest between environments","source":["TK_Envs"],"destination":["TK_Envs"],"service":["Any"],"action":"Drop","track":{"type":"Log"}}'
AR "$NETL" "{\"name\":\"TK environments -> Internet\",\"source\":[\"TK_Envs\"],\"destination\":[\"TK_Internal\"],\"destination-negate\":true,\"service\":[\"Any\"],\"action\":\"Apply Layer\",\"inline-layer\":\"$IL\",\"track\":{\"type\":\"None\"}}"
api set-access-rule "{\"name\":\"Cleanup rule\",\"layer\":\"$NETL\",\"track\":{\"type\":\"Log\"}}"

log "Egress rules ($IL)"
[ "$GEO" != "[]" ] && AR "$IL" "{\"name\":\"TK GEO - blocked countries\",\"source\":[\"Any\"],\"destination\":$GEO,\"service\":[\"Any\"],\"action\":\"Drop\",\"track\":{\"type\":\"Log\"}}"
AR "$IL" '{"name":"TK APPC - blocked applications","source":["Any"],"destination":["Any"],"service":["Facebook","TikTok","Dropbox","WeTransfer","OpenSSH","SSH tunnelled","DoH"],"action":"Drop","track":{"type":"Log"}}'
AR "$IL" '{"name":"TK URLF - blocked categories","source":["Any"],"destination":["Any"],"service":["Gambling","Anonymizer","Phishing","Hacking","Sex","Botnets"],"action":"Drop","track":{"type":"Log"}}'
AR "$IL" '{"name":"TK APPC - high and critical risk, P2P","source":["Any"],"destination":["Any"],"service":["Critical Risk","High Risk","P2P File Sharing"],"action":"Drop","track":{"type":"Log"}}'
AR "$IL" '{"name":"TK URLF - custom sites","source":["Any"],"destination":["Any"],"service":["TK_Blocked_FQDN","TK_Blocked_Path"],"action":"Drop","track":{"type":"Log"}}'
AR "$IL" '{"name":"TK allow web (protocol signature) and DNS","source":["Any"],"destination":["Any"],"service":["TK_http_sig","TK_https_sig","domain-udp","domain-tcp"],"action":"Accept","track":{"type":"Log","accounting":true}}'
api set-access-rule "{\"name\":\"Cleanup rule\",\"layer\":\"$IL\",\"track\":{\"type\":\"Log\"}}"

log "Threat Prevention profiles"
AV='{"protected-scope":{"inspect-files":"outgoing_and_incoming","incoming-interfaces":"all"},"filetypes-to-process":"all_file_types","archives":{"archive-scanning":true}}'
prof() { exists threat-profile "$1" || api add-threat-profile "{\"name\":\"$1\",\"active-protections-performance-impact\":\"high\",\"active-protections-severity\":\"Low or above\",\"confidence-level-high\":\"$2\",\"confidence-level-medium\":\"$2\",\"confidence-level-low\":\"$2\",\"ips\":true,\"anti-bot\":$3,\"anti-virus\":true,\"threat-emulation\":false,\"threat-extraction\":false,\"ips-settings\":{\"newly-updated-protections\":\"$4\"},$TAGS}"
  api set-threat-profile "{\"name\":\"$1\",\"anti-virus-settings\":$AV}"; }
prof $EW Prevent false active
prof $ST Prevent true active
prof $DT Detect true staging
# Deactivate OT/SCADA vendors and products on east-west (no OT assets in these VPCs). Format: [{"category":..,"name":..}]
OT='[{"category":"Vendor","name":"SCADA"},{"category":"Vendor","name":"Siemens"},{"category":"Vendor","name":"Schneider Electric"},{"category":"Vendor","name":"Iconics"},{"category":"Vendor","name":"Unitronics"},{"category":"Product","name":"SCADA"},{"category":"Product","name":"MicroSCADA"},{"category":"Product","name":"SCADA Expert ClearSCADA"}]'
api set-threat-profile "{\"name\":\"$EW\",\"use-extended-attributes\":true,\"deactivate-protections-by-extended-attributes\":$OT}"
# SQL tautology family is inactive by default (Critical performance impact): enable it on the Prevent profiles
api set-threat-protection "{\"name\":\"SQL Servers Blind SQL Injection Techniques\",\"overrides\":[{\"profile\":\"$EW\",\"action\":\"Prevent\",\"track\":\"Log\",\"capture-packets\":true},{\"profile\":\"$ST\",\"action\":\"Prevent\",\"track\":\"Log\",\"capture-packets\":true}]}"

log "Threat Prevention rules ($TPL)"
TRB() { cp show-threat-rulebase "{\"name\":\"$TPL\",\"limit\":50}" | jq -c '[.rulebase[] | if .type=="threat-section" then .rulebase[] else . end]'; }
HAS() { TRB | jq -e --arg n "$1" 'map(select(.name==$n))|length>0' >/dev/null; }
FIRST=$(TRB | jq -r 'map(select(.name!="TK rest of traffic" and (.name|startswith("TK ")|not)))[0].uid // empty')
[ -n "$FIRST" ] && api set-threat-rule "{\"uid\":\"$FIRST\",\"layer\":\"$TPL\",\"new-name\":\"TK rest of traffic\",\"action\":\"$ST\",\"track\":\"Log\"}"
HAS "TK Internet" || api add-threat-rule "{\"layer\":\"$TPL\",\"position\":\"top\",\"name\":\"TK Internet\",\"source\":[\"TK_Envs\"],\"destination\":[\"TK_Internal\"],\"destination-negate\":true,\"protected-scope\":[\"Any\"],\"action\":\"$ST\",\"track\":\"Log\",\"track-settings\":{\"packet-capture\":true}}"
HAS "TK east-west" || api add-threat-rule "{\"layer\":\"$TPL\",\"position\":\"top\",\"name\":\"TK east-west\",\"source\":[\"TK_Envs\"],\"destination\":[\"TK_Envs\"],\"protected-scope\":[\"Any\"],\"action\":\"$EW\",\"track\":\"Log\",\"track-settings\":{\"packet-capture\":true}}"
I=$(role ids_target)
[ -n "$I" ] && { HAS "TK IDS towards $I" || api add-threat-rule "{\"layer\":\"$TPL\",\"position\":\"top\",\"name\":\"TK IDS towards $I\",\"source\":[\"TK_Envs\"],\"destination\":[\"TK_$I\"],\"protected-scope\":[\"Any\"],\"action\":\"$DT\",\"track\":\"Log\"}"; }
EWR=$(TRB | jq -r 'map(select(.name=="TK east-west"))[0].uid')
XHAS() { cp show-threat-rule-exception-rulebase "{\"name\":\"$TPL\",\"rule-uid\":\"$EWR\"}" | jq -e --arg n "$1" '[..|objects|select(.name?==$n)]|length>0' >/dev/null; }
XHAS "TK exception port (not inspected)" || api add-threat-exception "{\"layer\":\"$TPL\",\"rule-uid\":\"$EWR\",\"position\":\"top\",\"name\":\"TK exception port (not inspected)\",\"source\":[\"TK_Envs\"],\"destination\":[\"TK_Envs\"],\"service\":[\"TK_exception_port\"],\"protected-scope\":[\"Any\"],\"protection-or-site\":[\"Any\"],\"action\":\"Inactive\",\"track\":\"None\"}"
X=$(role ips_exception_client)
[ -n "$X" ] && { XHAS "TK IPS-04 $X -> $SRV" || api add-threat-exception "{\"layer\":\"$TPL\",\"rule-uid\":\"$EWR\",\"position\":\"top\",\"name\":\"TK IPS-04 $X -> $SRV\",\"source\":[\"TK_$X\"],\"destination\":[\"TK_$SRV\"],\"service\":[\"Any\"],\"protected-scope\":[\"Any\"],\"protection-or-site\":[\"TP-Link Archer AX21 Command Injection (CVE-2023-1389)\"],\"action\":\"Detect\",\"track\":\"Log\"}"; }

log "HTTPS Inspection"
DEF=$(cp show-outbound-inspection-certificates '{"details-level":"full"}' | jq -r '[.objects[]?|select(."is-default")][0].name // empty')
if [ -z "$DEF" ]; then
  api add-outbound-inspection-certificate "$(jq -nc --arg p "$(openssl rand -hex 7 | base64 -w0)" --arg f "$(date -u +%F)" --arg t "$(date -u -d '+5 years' +%F)" \
    '{name:"TK_Outbound_CA", "issued-by":"Firewall Testkit HTTPS Inspection CA", "base64-password":$p, "valid-from":$f, "valid-to":$t, "is-default":true}')"
  DEF=TK_Outbound_CA
fi
mkdir -p "$CERTS"
cp show-outbound-inspection-certificate "{\"name\":\"$DEF\"}" | jq -r '."base64-public-certificate" // empty' > "$CERTS/inspection_ca.crt"
openssl x509 -in "$CERTS/inspection_ca.crt" -noout 2>/dev/null && ok "inspection CA exported: $(openssl x509 -in "$CERTS/inspection_ca.crt" -noout -subject)" || warn "could not export the inspection CA"
openssl x509 -in "$CERTS/inspection_ca.crt" -noout -subject -nameopt multiline 2>/dev/null | awk -F'= ' '/commonName/{print $2}' > "$STATE/inspection_ca_cn"
if cp show-custom-trusted-ca-certificates '{"limit":200,"details-level":"full"}' | jq -e '[.objects[]?|select(tostring|test("Firewall Testkit CA"))]|length>0' >/dev/null; then ok "testkit CA already trusted"
else api add-custom-trusted-ca-certificate "$(jq -nc --arg c "$(base64 -w0 < "$CERTS/testkit_ca.crt")" '{"base64-certificate":$c}')"; fi
exists https-layer "$HL" || api add-https-layer "{\"name\":\"$HL\",\"shared\":false,$TAGS}"
HRB() { cp show-https-rulebase "{\"name\":\"$HL\",\"limit\":100}" | jq -c '[.rulebase[] | if .type=="https-section" then .rulebase[] else . end]'; }
H() { local n; n=$(jq -r .name <<<"$1"); HRB | jq -e --arg n "$n" 'map(select(.name==$n))|length>0' >/dev/null && return 0
  api add-https-rule "$(jq -c --arg l "$HL" '. + {layer:$l, position:"bottom", track:"Log"}' <<<"$1")"; }
H '{"name":"TK bypass - FQDN (mTLS / pinning)","source":["TK_Envs"],"destination":["TK_Envs"],"service":["HTTPS default services"],"site-category":["TK_NoDecrypt"],"action":"Bypass"}'
exists updatable-object "HTTPS services - recommended bypass" && H '{"name":"TK bypass - recommended services (sk163595)","source":["Any"],"destination":["HTTPS services - recommended bypass"],"service":["HTTPS default services"],"site-category":["Any"],"action":"Bypass"}'
H '{"name":"TK bypass - sensitive categories","source":["TK_Envs"],"destination":["TK_Internal"],"destination-negate":true,"service":["HTTPS default services"],"site-category":["Financial Services","Health","Government / Military"],"action":"Bypass"}'
H '{"name":"TK inspect - east-west","source":["TK_Envs"],"destination":["TK_Envs"],"service":["HTTPS default services"],"site-category":["Any"],"action":"Inspect"}'
H '{"name":"TK inspect - Internet","source":["TK_Envs"],"destination":["TK_Internal"],"destination-negate":true,"service":["HTTPS default services"],"site-category":["Any"],"action":"Inspect"}'
# Predefined rules of a new layer use the "Internet" object (not valid behind a GWLB, single interface): remove them
for u in $(HRB | jq -r '.[]|select(.name|startswith("TK ")|not)|.uid'); do api delete-https-rule "{\"uid\":\"$u\",\"layer\":\"$HL\"}"; done
IN=$(cp show-package "{\"name\":\"$PKG\"}" | jq -r '."https-inspection-layers"."inbound-https-layer".name // "Default Inbound Layer"')
api set-package "{\"name\":\"$PKG\",\"https-inspection-layers\":{\"outbound-https-layer\":\"$HL\",\"inbound-https-layer\":\"$IN\"}}"
api set-https-advanced-settings '{"server-certificate-validation-actions":{"block-untrusted":true,"block-revoked":true,"block-expired":true,"track-errors":"log"},"log-sessions":true}'

log "Publish"
publish || die "publish failed"
cp_logout
