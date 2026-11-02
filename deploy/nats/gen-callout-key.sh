#!/usr/bin/env bash
# Generates the NATS auth-callout account key: prints the nkey seed (SA...)
# on the first line and its public key (A...) on the second.
#
# The broker trusts authorization answers signed by this key (nats.conf
# auth_callout.issuer = the public key); the mustra server signs them with
# the seed (MUSTRA_NATS_CALLOUT_SEED). init.sh calls this and writes both
# into .env. Pure bash plus openssl, so it needs neither Go nor the nk tool:
# an nkey is an ed25519 key with a prefix byte and a CRC16, in base32.
#
#   ./gen-callout-key.sh            # new key
#   ./gen-callout-key.sh <hex seed> # encode an existing 32-byte seed (tests)
set -euo pipefail

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
umask 077

if [ $# -ge 1 ]; then
  seed_hex=$1
  # PKCS#8 wrapping of a raw ed25519 seed, so openssl derives the public key.
  [[ "$seed_hex" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "the seed must be 64 hex characters" >&2; exit 1; }
  # shellcheck disable=SC2059 # the format is built from validated hex
  printf "$(printf '302e020100300506032b657004220420%s' "$seed_hex" | sed 's/../\\x&/g')" > "$tmp/key.der"
else
  openssl genpkey -algorithm ed25519 -outform DER -out "$tmp/key.der" 2>/dev/null ||
    { echo "this openssl cannot generate ed25519 keys (OpenSSL 1.1.1+ is needed)" >&2; exit 1; }
fi
openssl pkey -inform DER -in "$tmp/key.der" -pubout -outform DER -out "$tmp/pub.der" 2>/dev/null ||
  { echo "openssl could not derive the public key" >&2; exit 1; }

# The last 32 bytes of each DER structure are the raw seed and public key.
read -r -a seed <<<"$(tail -c 32 "$tmp/key.der" | od -An -v -tu1 | tr -s ' \n' ' ')"
read -r -a pub <<<"$(tail -c 32 "$tmp/pub.der" | od -An -v -tu1 | tr -s ' \n' ' ')"
[ "${#seed[@]}" -eq 32 ] && [ "${#pub[@]}" -eq 32 ] || { echo "unexpected key length" >&2; exit 1; }

crc16() { # CRC-16/XMODEM, as nkeys computes it
  local crc=0 b i
  for b in "$@"; do
    crc=$(( crc ^ (b << 8) ))
    for i in 1 2 3 4 5 6 7 8; do
      if (( crc & 0x8000 )); then crc=$(( ((crc << 1) ^ 0x1021) & 0xFFFF )); else crc=$(( (crc << 1) & 0xFFFF )); fi
    done
  done
  echo "$crc"
}

base32() { # RFC 4648 alphabet, no padding
  local alphabet=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567 out="" buffer=0 bits=0 b
  for b in "$@"; do
    buffer=$(( (buffer << 8) | b )); bits=$(( bits + 8 ))
    while (( bits >= 5 )); do
      bits=$(( bits - 5 ))
      out+=${alphabet:$(( (buffer >> bits) & 31 )):1}
    done
    buffer=$(( buffer & ((1 << bits) - 1) ))
  done
  if (( bits > 0 )); then out+=${alphabet:$(( (buffer << (5 - bits)) & 31 )):1}; fi
  echo "$out"
}

encode() {
  local c
  c=$(crc16 "$@")
  base32 "$@" $(( c & 0xFF )) $(( c >> 8 ))
}

# Seed: prefix bytes (seed type 18<<3, account type 0) then the raw seed.
encode 144 0 "${seed[@]}"
# Public key: the account prefix byte (0) then the raw public key.
encode 0 "${pub[@]}"
