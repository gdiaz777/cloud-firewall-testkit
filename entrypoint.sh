#!/bin/bash
# Firewall Testkit
#   server → test server: nginx 80/443 (inspect|nodecrypt|mtls.testkit.lab), listeners 23/3389/8080/5201, portal (PORTAL=1)
#   client → agent: docker run --network host -e SERVER=<server IP> <image> client
#            CLI:   docker run --network host -e SERVER=<server IP> <image> client run IPS-01
set -e
ROLE=${1:-client}; shift || true
C=/opt/testkit/certs
first_ip() { hostname -I | tr ' ' '\n' | grep -vE '^(172\.17\.|127\.)' | head -1; }

case $ROLE in
server)
  mkdir -p /run/testkit /data/certs /var/log/nginx
  # Certificates: mounted in /opt/testkit/certs (testkit_ca.crt/.key) or generated once and kept in /data/certs
  if [ -s $C/testkit_ca.key ]; then D=$C; else D=/data/certs
    if [ ! -s $D/testkit_ca.key ]; then
      openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes -keyout $D/testkit_ca.key -out $D/testkit_ca.crt \
        -subj "/O=Firewall Testkit/CN=Firewall Testkit CA $(hostname -s)" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
      openssl req -newkey rsa:2048 -nodes -keyout $D/client.key -out /run/testkit/client.csr -subj "/O=Firewall Testkit/CN=testkit-client" 2>/dev/null
      openssl x509 -req -in /run/testkit/client.csr -CA $D/testkit_ca.crt -CAkey $D/testkit_ca.key -CAcreateserial -CAserial /run/testkit/ca.srl \
        -days 1825 -sha256 -out $D/client.crt -extfile <(printf "extendedKeyUsage=clientAuth") 2>/dev/null
      chmod 600 $D/*.key; echo "testkit CA and client certificate generated in /data/certs"
    fi
  fi
  ln -sf $D/testkit_ca.crt /run/testkit/testkit_ca.crt
  export SERVER_IP=${SERVER_IP:-$(first_ip)} CERT_DIR=$D
  SAN="DNS:inspect.testkit.lab,DNS:nodecrypt.testkit.lab,DNS:mtls.testkit.lab"
  for ip in $(hostname -I) $SERVER_IP; do SAN="$SAN,IP:$ip"; done
  openssl req -newkey rsa:2048 -nodes -keyout /run/testkit/server.key -out /run/testkit/server.csr -subj "/O=Firewall Testkit/CN=inspect.testkit.lab" 2>/dev/null
  openssl x509 -req -in /run/testkit/server.csr -CA $D/testkit_ca.crt -CAkey $D/testkit_ca.key -CAcreateserial \
    -CAserial /run/testkit/srv.srl -days 825 -sha256 -out /run/testkit/server.crt -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth" "$SAN") 2>/dev/null
  echo "<!doctype html><title>FW-TESTKIT-OK</title><h1>FW-TESTKIT-OK · test server (${TESTKIT_ENV:-$(hostname -s)})</h1>" > /srv/www/index.html
  socat TCP-LISTEN:23,fork,reuseaddr SYSTEM:'echo telnet-testkit' &
  socat TCP-LISTEN:3389,fork,reuseaddr SYSTEM:'echo rdp-testkit' &
  python3 -m http.server 8080 --directory /srv/www >/dev/null 2>&1 &
  python3 /opt/testkit/server/sink.py &
  iperf3 -s -D
  if [ "${PORTAL:-1}" = 1 ]; then python3 /opt/testkit/server/portal/app.py & fi
  echo "server ready on $SERVER_IP — portal: http://$SERVER_IP/portal/"
  exec nginx -c /opt/testkit/server/nginx.conf -g 'daemon off;'
  ;;
client)
  [ -n "${SERVER:-}" ] && export SERVER_IP=${SERVER_IP:-$SERVER} PORTAL_URL=${PORTAL_URL:-http://$SERVER/portal}
  [ -n "${SERVER_IP:-}" ] || { echo "set SERVER=<test server IP>"; exit 1; }
  export PORTAL_URL=${PORTAL_URL:-http://$SERVER_IP/portal} TESTKIT_ENV=${TESTKIT_ENV:-$(hostname -s)}
  # Testkit CA and client certificate come from the server (unless mounted)
  if [ ! -s $C/client.crt ]; then mkdir -p $C
    for i in $(seq 1 60); do
      B=$(curl -sf --max-time 5 "$PORTAL_URL/api/bootstrap" || true)
      if [ -n "$B" ]; then
        jq -r .testkit_ca <<<"$B" > $C/testkit_ca.crt; jq -r .client_crt <<<"$B" > $C/client.crt; jq -r .client_key <<<"$B" > $C/client.key
        chmod 600 $C/client.key; echo "certificates received from $PORTAL_URL"; break; fi
      [ $i = 1 ] && echo "waiting for the server at $PORTAL_URL …"; sleep 5
    done
  fi
  if [ $# -gt 0 ]; then exec python3 /opt/testkit/client/runner.py "$@"; fi
  exec python3 -u /opt/testkit/client/runner.py agent
  ;;
*) exec "$ROLE" "$@";;
esac
