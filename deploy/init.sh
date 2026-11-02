#!/usr/bin/env bash
# First-run bootstrap for the compose stack, and the upgrade step for an
# existing one. Idempotent: it never overwrites a value already in .env or
# existing certificates, only adds what a newer version needs, so running
# it twice is safe.
#
#   ./init.sh --start               # bootstrap, build and start the stack
#   ./init.sh                       # bootstrap only; detect the LAN address
#   ./init.sh --ip 192.0.2.5        # or name the address yourself
#   ./init.sh --public-hostname mustra.example.com
#                                   # console will sit behind HTTPS: public
#                                   # URL and OIDC redirect filled in
#   ./init.sh --insecure-http       # LAN/dev only: console on plain
#                                   # http://<LAN address>:8080, cookies not
#                                   # Secure. Enrollment tokens cross it.
#   MUSTRA_CONSOLE_PORT=18080 MUSTRA_NATS_PORT=14222 ./init.sh --start
#                                   # publish on other host ports (first run
#                                   # records them in .env)
#
# It does three things that every fresh install needs and that, left to a
# README, get skipped: writes .env with generated secrets rather than the
# example placeholders (which the server refuses to run on), generates the
# NATS certificates whose SANs must include the LAN address agents dial,
# and records that address so the install scripts hand it to new agents.
set -euo pipefail
cd "$(dirname "$0")"

IP=""
PUBLIC_HOSTNAME=""
START=false
INSECURE_HTTP=false
while [ $# -gt 0 ]; do
  case "$1" in
    --ip) IP="$2"; shift 2 ;;
    --public-hostname) PUBLIC_HOSTNAME="$2"; shift 2 ;;
    --start) START=true; shift ;;
    --insecure-http) INSECURE_HTTP=true; shift ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# The host ports the console and the broker are published on. The
# containers listen on 8080/4222 regardless; only the host side moves, for
# a host where something else already holds those (or a second stack, such
# as the end-to-end tests). An existing .env's choice wins over the default.
# No .env must succeed with no output: the assignments below take this
# function's status, and under set -e a failure ends the script silently.
existing_port() { [ -f .env ] || return 0; sed -n "s|^$1=||p" .env | head -1; }
CONSOLE_PORT="${MUSTRA_CONSOLE_PORT:-$(existing_port MUSTRA_CONSOLE_PORT)}"
CONSOLE_PORT="${CONSOLE_PORT:-8080}"
NATS_PORT="${MUSTRA_NATS_PORT:-$(existing_port MUSTRA_NATS_PORT)}"
NATS_PORT="${NATS_PORT:-4222}"
for port in "$CONSOLE_PORT" "$NATS_PORT"; do
  case "$port" in
    ''|*[!0-9]*) echo "error: port '$port' is not a number" >&2; exit 2 ;;
  esac
done

# Preflight. Every check here is something that otherwise fails much later,
# in the middle of a ten-minute image build, with an error that does not name
# the thing that is actually wrong.
fail() { echo "error: $*" >&2; exit 1; }

command -v openssl >/dev/null || fail "openssl is required (apt install openssl / brew install openssl)"
command -v docker  >/dev/null || fail "docker is required -- see https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 ||
  fail "the docker daemon is not reachable. Start it, or add yourself to the 'docker' group and log in again."
docker compose version >/dev/null 2>&1 ||
  fail "docker compose v2 is required (you may have the older 'docker-compose'). See https://docs.docker.com/compose/install/"

# Both are published to the host, so a conflict means one of them silently
# does not come up rather than a port clash you can read. Only on a genuine
# first run: after that the thing holding 8080 is this stack. Deciding that
# from `docker compose ps` does not work — compose names the project after
# this directory, so a second checkout in a directory also called deploy/
# reports the first one's containers as its own.
port_in_use() {
  local port=$1
  if command -v ss >/dev/null; then
    ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN
  elif command -v lsof >/dev/null; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  elif command -v netstat >/dev/null; then
    netstat -an 2>/dev/null | grep -Eq "[.:]$port[[:space:]].*LISTEN"
  else
    # Last resort: try to connect. Something answering is something listening.
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null
  fi
}
if [ ! -f .env ]; then
  if ! command -v ss >/dev/null && ! command -v lsof >/dev/null && ! command -v netstat >/dev/null; then
    echo "note: neither ss, lsof nor netstat is installed; checking ports by connecting to them" >&2
  fi
  for port in "$CONSOLE_PORT" "$NATS_PORT"; do
    if port_in_use "$port"; then
      fail "port $port is already in use; stop whatever holds it, or publish on another one with MUSTRA_CONSOLE_PORT / MUSTRA_NATS_PORT"
    fi
  done
fi

# The build cross-compiles six agent binaries and packages a Python runtime
# for each. Running out of room halfway through leaves an unusable cache.
avail_mb=$(df -Pm . | awk 'NR==2 {print $4}')
if [ -n "${avail_mb:-}" ] && [ "$avail_mb" -lt 6000 ]; then
  echo "warning: only ${avail_mb} MB free here; the image build wants ~6 GB" >&2
fi

if [ -z "$IP" ]; then
  # The address of the interface that carries the default route, which is
  # the one other machines on the LAN reach this host at.
  if [ "$(uname)" = "Darwin" ]; then
    IP="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' | xargs -I{} ipconfig getifaddr {} 2>/dev/null || true)"
  elif command -v ip >/dev/null; then
    IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1 || true)"
  fi
  # Without iproute2 (minimal images), the first address hostname reports.
  if [ -z "$IP" ] && hostname -I >/dev/null 2>&1; then
    IP="$(hostname -I | awk '{print $1}')"
  fi
fi
if [ -z "$IP" ]; then
  echo "could not detect this host's LAN address; pass --ip <address>" >&2
  exit 1
fi

secret() { openssl rand -base64 32 | tr -d '/+=' | cut -c1-32; }

# The auth-callout account key (nkey seed + public key) and the agent update
# signing key. Generated once; agents pin the update key when they enroll,
# so it must not change underneath them.
gen_callout() {
  local out
  out=$(./nats/gen-callout-key.sh) || fail "could not generate the NATS auth callout key (needs OpenSSL 1.1.1+)"
  CALLOUT_SEED=$(printf '%s\n' "$out" | sed -n 1p)
  CALLOUT_ISSUER=$(printf '%s\n' "$out" | sed -n 2p)
}
gen_signing_key() {
  openssl genpkey -algorithm ed25519 -outform DER 2>/dev/null | tail -c 32 | openssl base64 -A ||
    fail "could not generate the agent update signing key (needs OpenSSL 1.1.1+)"
}

PUBLIC_URL=""
ALLOW_HTTP=false
if [ -n "$PUBLIC_HOSTNAME" ]; then
  PUBLIC_URL="https://$PUBLIC_HOSTNAME"
fi

# env_get / env_add read and append .env entries without touching others.
env_get() { sed -n "s|^$1=||p" .env | head -1; }
env_add() {
  if grep -q "^$1=" .env; then
    sed -i.bak "s|^$1=.*|$1=$2|" .env && rm -f .env.bak
  else
    printf '%s=%s\n' "$1" "$2" >> .env
  fi
}

# The one piece of configuration that cannot be changed later without
# revisiting every endpoint: the address baked into each agent's installer.
agent_note() {
  cat <<NOTE
Agents will be told to connect to tls://$IP:$NATS_PORT. If that is not the address
your endpoints can reach, edit MUSTRA_AGENT_NATS_URL in .env, delete
nats/certs/, and re-run ./init.sh --ip <address>.
NOTE
}

EXISTING_INSTALL=false
if [ -f .env ]; then
  EXISTING_INSTALL=true
  # An existing install: add what this version needs and change nothing
  # else. The legacy agent password stays, so the agents already out there
  # keep reporting while they move to credentials of their own.
  echo ".env already exists; keeping every value in it"
  chmod 600 .env
  if [ -z "$(env_get MUSTRA_NATS_CALLOUT_SEED)" ] || [ -z "$(env_get MUSTRA_NATS_CALLOUT_ISSUER)" ]; then
    gen_callout
    env_add MUSTRA_NATS_CALLOUT_SEED "$CALLOUT_SEED"
    env_add MUSTRA_NATS_CALLOUT_ISSUER "$CALLOUT_ISSUER"
    # First run of this version (the callout key was missing), so no agent
    # has pinned an update key yet: safe to add one now.
    if [ -z "$(env_get MUSTRA_AGENT_SIGNING_KEY)" ] && [ -z "$(env_get MUSTRA_AGENT_SIGNING_PUBKEY)" ]; then
      env_add MUSTRA_AGENT_SIGNING_KEY "$(gen_signing_key)"
    fi
    echo "added the per-agent identity keys to .env (auth callout, update signing)"
  fi
  if [ -z "$(env_get MUSTRA_NATS_SYS_PASSWORD)" ]; then
    env_add MUSTRA_NATS_SYS_PASSWORD "$(secret)"
    echo "added MUSTRA_NATS_SYS_PASSWORD (revoked agents are disconnected at once; restart nats and server)"
  fi
  if [ -n "$PUBLIC_URL" ] && [ -z "$(env_get MUSTRA_PUBLIC_URL)" ]; then
    env_add MUSTRA_PUBLIC_URL "$PUBLIC_URL"
    echo "set MUSTRA_PUBLIC_URL=$PUBLIC_URL"
  fi
  if [ -z "$(env_get MUSTRA_PUBLIC_URL)" ]; then
    echo "note: MUSTRA_PUBLIC_URL is not set. Confirm the console's public URL under Settings -> Agent identity," >&2
    echo "      or re-run with --public-hostname <name>; install and update links are not served until it is." >&2
  fi
else
  # Secure cookies unless the operator explicitly asks for a plain-http LAN
  # install. Without a public hostname the console is still reachable for
  # setup over an SSH tunnel (http://localhost:8080 counts as secure to a
  # browser), and the public URL is then entered in Settings.
  cookie_secure=true
  oidc_redirect=""
  if [ -n "$PUBLIC_HOSTNAME" ]; then
    oidc_redirect="https://$PUBLIC_HOSTNAME/auth/callback"
  elif [ "$INSECURE_HTTP" = true ]; then
    # Reached over plain http on port 8080: an explicit LAN/development
    # choice, recorded as such.
    PUBLIC_URL="http://$IP:$CONSOLE_PORT"
    ALLOW_HTTP=true
    cookie_secure=false
  fi
  gen_callout
  # A fresh install has no agents holding the old shared password, so it
  # gets none: MUSTRA_NATS_AGENT_PASSWORD stays empty.
  sed \
    -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(secret)|" \
    -e "s|^MUSTRA_NATS_SERVER_PASSWORD=.*|MUSTRA_NATS_SERVER_PASSWORD=$(secret)|" \
    -e "s|^MUSTRA_NATS_SYS_PASSWORD=.*|MUSTRA_NATS_SYS_PASSWORD=$(secret)|" \
    -e "s|^MUSTRA_NATS_AGENT_PASSWORD=.*|MUSTRA_NATS_AGENT_PASSWORD=|" \
    -e "s|^MUSTRA_NATS_CALLOUT_SEED=.*|MUSTRA_NATS_CALLOUT_SEED=$CALLOUT_SEED|" \
    -e "s|^MUSTRA_NATS_CALLOUT_ISSUER=.*|MUSTRA_NATS_CALLOUT_ISSUER=$CALLOUT_ISSUER|" \
    -e "s|^MUSTRA_AGENT_SIGNING_KEY=.*|MUSTRA_AGENT_SIGNING_KEY=$(gen_signing_key)|" \
    -e "s|^MUSTRA_PUBLIC_URL=.*|MUSTRA_PUBLIC_URL=$PUBLIC_URL|" \
    -e "s|^MUSTRA_ALLOW_INSECURE_PUBLIC_URL=.*|MUSTRA_ALLOW_INSECURE_PUBLIC_URL=$ALLOW_HTTP|" \
    -e "s|^MUSTRA_CREDENTIAL_ENCRYPTION_KEY=.*|MUSTRA_CREDENTIAL_ENCRYPTION_KEY=$(openssl rand -hex 32)|" \
    -e "s|^MUSTRA_COOKIE_SECURE=.*|MUSTRA_COOKIE_SECURE=$cookie_secure|" \
    -e "s|^MUSTRA_OIDC_REDIRECT_URL=.*|MUSTRA_OIDC_REDIRECT_URL=$oidc_redirect|" \
    -e "s|^MUSTRA_AGENT_NATS_URL=.*|MUSTRA_AGENT_NATS_URL=tls://$IP:$NATS_PORT|" \
    .env.example > .env
  # Recorded only when they differ from the defaults, so a later plain
  # `docker compose up` publishes on the same ports this run chose.
  if [ "$CONSOLE_PORT" != 8080 ]; then printf 'MUSTRA_CONSOLE_PORT=%s\n' "$CONSOLE_PORT" >> .env; fi
  if [ "$NATS_PORT" != 4222 ]; then printf 'MUSTRA_NATS_PORT=%s\n' "$NATS_PORT" >> .env; fi
  chmod 600 .env
  echo "wrote .env with generated secrets"
  if [ -z "$PUBLIC_URL" ]; then
    echo "note: no public URL yet. Re-run with --public-hostname <name> (HTTPS in front), or --insecure-http for a" >&2
    echo "      plain-http LAN install, or enter it under Settings -> Agent identity after signing in." >&2
  fi
fi

if [ -f nats/certs/ca.crt ]; then
  echo "NATS certificates already exist; leaving them alone"
else
  ./nats/gen-certs.sh "$IP" ${PUBLIC_HOSTNAME:+"$PUBLIC_HOSTNAME"}
fi

# No credential is generated here any more. A password written to .env is a
# password somebody has to find and copy before they can log in, and it sits
# in a file afterwards; the console asks for one instead, the first time
# somebody opens it, and nothing has to be rotated because nothing was
# issued. sign_in_note says so wherever this script tells you what is next.
console_url() {
  local u
  u=$(env_get MUSTRA_PUBLIC_URL)
  echo "${u:-http://localhost:$CONSOLE_PORT (through an SSH tunnel: ssh -L $CONSOLE_PORT:localhost:$CONSOLE_PORT <this host>)}"
}
sign_in_note() {
  if [ "$EXISTING_INSTALL" = true ]; then
    # An upgrade: the administrator already exists (possibly only in the
    # database, from the setup page), so there is no setup link to open.
    echo "Existing install: sign in at $(console_url) as before."
  elif grep -qE '^MUSTRA_(BREAKGLASS|BACKDOOR)_PASSWORD=.+' .env 2>/dev/null; then
    echo "Sign in at $(console_url) with the account already set in .env."
  else
    cat <<NOTE
Open the one-time setup link the server prints at first start to create the
first administrator:

  docker compose logs server | grep "FIRST-RUN SETUP"

The link carries a setup token, so reaching the console first is not enough
to claim it. Its host is the console as the server sees it; use
$(console_url) if that differs.
NOTE
  fi
}

next_step() {
  if [ "$EXISTING_INSTALL" = true ]; then
    cat <<NOTE
  cd .. && make up VERSION=<server version> AGENT_VERSION=<agent version>
                               # a build without versions serves agents that
                               # cannot be offered to existing endpoints; see
                               # README "Upgrading to per-agent identity"
NOTE
  else
    echo "  ./init.sh --start            # or: docker compose up -d --build --wait"
  fi
}

if [ "$START" = false ]; then
  cat <<MSG

Bootstrapped. Next:

$(next_step)

$(sign_in_note)

$(agent_note)
MSG
  exit 0
fi

# Both images are built, never pulled: script-tools has no published image
# for most installs, and `server` must match this checkout anyway. --wait
# returns when the console answers /healthz, so the message below is true
# by the time it prints rather than something to go and verify.
# Stamp the build with what this checkout is, as `make image` does, so the
# console's About page and footer say which version is running rather than
# "dev". A value already in the environment wins.
if git -C .. rev-parse --git-dir >/dev/null 2>&1; then
  : "${MUSTRA_VERSION:=$(git -C .. describe --tags --always --dirty 2>/dev/null | sed 's/^v//')}"
  : "${MUSTRA_COMMIT:=$(git -C .. rev-parse --short HEAD 2>/dev/null)}"
fi
: "${MUSTRA_BUILD_TIME:=$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
export MUSTRA_VERSION MUSTRA_COMMIT MUSTRA_BUILD_TIME

echo
echo "Building and starting the stack. The first build cross-compiles six agent"
echo "binaries and packages their Python runtimes, so it takes a few minutes."
echo
if ! docker compose up -d --build --wait; then
  echo >&2
  echo "The stack did not come up healthy. What each service says:" >&2
  docker compose ps >&2
  echo >&2
  echo "  docker compose logs server    # usually the one with the answer" >&2
  exit 1
fi

setup_link=$(docker compose logs server 2>/dev/null | grep "FIRST-RUN SETUP" | tail -1 || true)

cat <<MSG

Up.

$(sign_in_note)
${setup_link:+
$setup_link
}
Then add your first endpoint from Client Management -> Manual Install:
create an enrollment token there, and it hands you the copy-paste installer
per OS with the token in it. The installer refuses to enroll a new
endpoint without one.

$(agent_note)
MSG
