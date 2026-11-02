#!/usr/bin/env bash
# Generates the CA and server certificate the control plane uses.
#
# Self-signed rather than a public CA because the agents verify against this
# CA specifically -- pinning to one issuer we control is stronger here than
# trusting the world's, and it costs nothing since the install script
# distributes the CA with the agent anyway.
#
# Usage:
#   ./gen-certs.sh 192.0.2.5                # your host's LAN address
#   ./gen-certs.sh 192.0.2.5 mustra.lan     # any number of extra IPs/names
#   MUSTRA_NATS_SANS="IP:192.0.2.5,DNS:nats" ./gen-certs.sh   # full control
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$DIR"; cd "$DIR"

if [ -f ca.crt ] && [ -f server.crt ]; then
  echo "certs already exist in $DIR -- delete them to regenerate"; exit 0
fi

# The SANs must cover every name an agent might dial: the LAN address, the
# in-compose service name, and localhost. A missing SAN fails verification
# with an error that reads like a trust problem, which sends you looking in
# the wrong place entirely. The names compose needs are always included;
# the address agents use comes from the arguments.
SANS="${MUSTRA_NATS_SANS:-DNS:nats,DNS:localhost,IP:127.0.0.1}"
for extra in "$@"; do
  if [[ "$extra" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$extra" == *:*:* ]]; then
    SANS="$SANS,IP:$extra"
  else
    SANS="$SANS,DNS:$extra"
  fi
done
if [ $# -eq 0 ] && [ -z "${MUSTRA_NATS_SANS:-}" ]; then
  echo "warning: no LAN address given; agents on other machines will fail TLS verification." >&2
  echo "         re-run as: $0 <this host's LAN IP>" >&2
fi

# An existing CA is kept: every installed agent verifies the broker against
# it, so replacing it would cut the whole fleet off. Deleting only
# server.crt and server.key and re-running issues a new server certificate
# from it (for example to move an older install to an ECDSA server key).
if [ -f ca.crt ] && [ -f ca.key ]; then
  echo "keeping the existing CA; issuing a new server certificate from it"
else
  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout ca.key -out ca.crt \
    -subj "/CN=mustra control plane CA" >/dev/null 2>&1
fi

# The server key is ECDSA P-256, not RSA: the broker signs with it in every
# TLS handshake, and a fleet reconnects all at once after a broker restart.
# With an RSA-4096 key, 2,000 agents reconnecting saturated the broker on
# handshakes alone and were still not back after 13 minutes; with P-256
# they were back in 8 seconds. Agents verify it against the CA above as
# before, so changing it needs nothing on the endpoints.
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout server.key -out server.csr \
  -subj "/CN=mustra-nats" >/dev/null 2>&1

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 3650 -sha256 \
  -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\n" "$SANS") >/dev/null 2>&1

rm -f server.csr ca.srl
chmod 644 ca.crt server.crt
chmod 600 ca.key server.key
echo "generated in $DIR:"
openssl x509 -in server.crt -noout -subject -ext subjectAltName | sed 's/^/  /'
