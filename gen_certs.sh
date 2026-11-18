#!/bin/bash
# Creates (once) the testkit CA and a client certificate for the mTLS test.
#   ./gen_certs.sh  → certs/testkit_ca.{crt,key}, certs/client.{crt,key}
# The server signs its HTTPS certificate with this CA at start-up (SAN = its IPs + *.testkit.lab names).
# Add certs/testkit_ca.crt to the firewall's trusted CAs so east-west HTTPS can be inspected (outbound mode).
# certs/inspection_ca.crt = your firewall's HTTPS Inspection CA (public part): clients trust it.
set -euo pipefail
cd "$(dirname "$0")"; mkdir -p certs; cd certs
umask 077
if [ ! -s testkit_ca.crt ]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes -keyout testkit_ca.key -out testkit_ca.crt \
    -subj "/O=Firewall Testkit/CN=Firewall Testkit CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
fi
if [ ! -s client.crt ]; then
  openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/O=Firewall Testkit/CN=testkit-client" 2>/dev/null
  openssl x509 -req -in client.csr -CA testkit_ca.crt -CAkey testkit_ca.key -CAcreateserial -days 1825 -sha256 -out client.crt \
    -extfile <(printf "extendedKeyUsage=clientAuth") 2>/dev/null
  rm -f client.csr testkit_ca.srl
fi
chmod 644 testkit_ca.crt client.crt; chmod 600 testkit_ca.key client.key
openssl x509 -in testkit_ca.crt -noout -subject -enddate
