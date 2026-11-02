#!/usr/bin/with-contenv bash
# with-contenv: the base image starts this under s6, which hands the
# command an empty environment. The agent needs SUPERVISOR_TOKEN from it.
# Starts the mustra agent inside the Home Assistant add-on, reinstalling the
# server's current build first. The agent exits to be updated (it is told
# so by MUSTRA_UPDATE_BY_RESTART), and this loop is what brings it back.
set -uo pipefail

opts=/data/options.json
server=$(jq -r '.server_url // ""' "$opts")
server=${server%/}
site=$(jq -r '.site // "default"' "$opts")
# The enrollment token install.sh passed through, used only until the agent
# has its own credential: after that the token is spent, and the console
# serves enrolled endpoints a token-free update script.
token=$(jq -r '.enroll_token // ""' "$opts")
log_level=$(jq -r '.log_level // "info"' "$opts")
mkdir -p /data/agent /data/state

pid=""
trap '[ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null; [ -n "$pid" ] && wait "$pid"; exit 0' TERM INT

while true; do
  auth=()
  if [ -n "$token" ] && [ ! -s /var/lib/mustra-agent/agent-credential.json ]; then
    auth=(-H "Authorization: Bearer $token")
  fi
  if [ -z "$server" ]; then
    echo "[mustra] set server_url in the add-on's configuration" >&2
  elif curl -fsSL --retry 3 --retry-all-errors "${auth[@]}" "$server/install.sh" -o /tmp/install.sh; then
    # A failed install leaves the previous agent in place (the installer
    # stages and verifies before replacing), so carry on and start it.
    MUSTRA_NO_SERVICE=1 bash /tmp/install.sh || echo "[mustra] install failed; starting the installed agent" >&2
  else
    echo "[mustra] could not reach $server; starting the installed agent" >&2
  fi

  if [ ! -x /opt/mustra-agent/mustra-agent ] || [ ! -f /opt/mustra-agent/service.env ]; then
    echo "[mustra] no agent installed yet; retrying in 60s" >&2
    sleep 60 & wait $!
    continue
  fi

  set -a
  [ -f /opt/mustra-agent/agent.env ] && . /opt/mustra-agent/agent.env
  . /opt/mustra-agent/service.env
  set +a
  # No Self Service window: nobody signs in to a desktop on this host.
  MUSTRA_UPDATE_BY_RESTART=1 /opt/mustra-agent/mustra-agent \
    --site "$site" --log-level "$log_level" --self-service-addr "" &
  pid=$!
  wait "$pid"
  rc=$?
  pid=""
  echo "[mustra] agent exited with status $rc; restarting in 5s"
  sleep 5 & wait $!
done
