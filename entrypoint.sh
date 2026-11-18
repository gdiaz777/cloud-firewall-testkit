#!/bin/bash
# Roles:  server → nginx (80/443: inspect|nodecrypt|mtls.testkit.lab), listeners 23/3389/8080/5201 and the portal (PORTAL=1)
#         client → portal agent (or: docker run ... client run IPS-01 to run from the CLI)
set -e
ROLE=${1:-client}; shift || true
C=/opt/testkit/certs
# The firewall's HTTPS Inspection CA (if mounted) goes to the container trust store (TLS-02)
if [ -s $C/inspection_ca.crt ]; then
  cp $C/inspection_ca.crt /usr/local/share/ca-certificates/inspection_ca.crt && update-ca-certificates >/dev/null 2>&1 || true
fi
case $ROLE in
server)
  mkdir -p /run/testkit /data /var/log/nginx
  [ -s $C/testkit_ca.key ] || { echo "Missing certs/testkit_ca.key (run gen_certs.sh and mount certs/)"; exit 1; }
  SAN="DNS:inspect.testkit.lab,DNS:nodecrypt.testkit.lab,DNS:mtls.testkit.lab"
  for ip in $(hostname -I) ${SERVER_IP:-}; do SAN="$SAN,IP:$ip"; done
  openssl req -newkey rsa:2048 -nodes -keyout /run/testkit/server.key -out /run/testkit/server.csr -subj "/O=Firewall Testkit/CN=inspect.testkit.lab" 2>/dev/null
  openssl x509 -req -in /run/testkit/server.csr -CA $C/testkit_ca.crt -CAkey $C/testkit_ca.key -CAcreateserial \
    -CAserial /run/testkit/ca.srl -days 825 -sha256 -out /run/testkit/server.crt -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth" "$SAN") 2>/dev/null
  echo "<!doctype html><title>FW-TESTKIT-OK</title><h1>FW-TESTKIT-OK · test server (${TESTKIT_ENV:-server})</h1>" > /srv/www/index.html
  socat TCP-LISTEN:23,fork,reuseaddr SYSTEM:'echo telnet-testkit' &
  socat TCP-LISTEN:3389,fork,reuseaddr SYSTEM:'echo rdp-testkit' &
  python3 -m http.server 8080 --directory /srv/www >/dev/null 2>&1 &
  python3 /opt/testkit/server/sink.py &
  iperf3 -s -D
  if [ "${PORTAL:-1}" = 1 ]; then python3 /opt/testkit/server/portal/app.py & fi
  echo "server ready: $(hostname -I)"
  exec nginx -c /opt/testkit/server/nginx.conf -g 'daemon off;'
  ;;
client)
  [ -s $C/client.crt ] || echo "warning: certs/client.crt not mounted (TLS-04 mTLS check will fail)"
  if [ $# -gt 0 ]; then exec python3 /opt/testkit/client/runner.py "$@"; fi
  exec python3 -u /opt/testkit/client/runner.py agent
  ;;
*) exec "$ROLE" "$@";;
esac
