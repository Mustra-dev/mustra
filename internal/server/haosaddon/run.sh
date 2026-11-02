#!/usr/bin/with-contenv bash
# with-contenv: the base image starts this under s6, which hands the
# command an empty environment. The agent needs SUPERVISOR_TOKEN from it.
# Starts the mustra agent inside the Home Assistant add-on and brings it back
# when it exits.
#
# Updates arrive the way they do on every other platform: the agent checks
# the server's signed manifest, downloads the build, verifies its digest and
# size, and leaves it as mustra-agent.verified before exiting (it is told to
# by MUSTRA_UPDATE_BY_RESTART). This loop renames that into place; nothing it
# installs comes from the network.
#
# install.sh from the server runs only to install the agent: when there is
# none yet, or once after the add-on itself was installed, updated or
# rebuilt (a new /addon-build-id), which is how an operator asks for a
# reinstall. It used to run on every start, which made the server's install
# channel, not the signing key, the authority over what ran here.
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

agent=/opt/mustra-agent/mustra-agent
build_id=$(cat /addon-build-id 2>/dev/null || echo unknown)
build_marker=/data/addon-build-id
# Set when a verified build was just installed: if it then fails at once,
# the previous build comes back rather than a crash loop.
just_updated=""

pid=""
trap '[ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null; [ -n "$pid" ] && wait "$pid"; exit 0' TERM INT

while true; do
  auth=()
  if [ -n "$token" ] && [ ! -s /var/lib/mustra-agent/agent-credential.json ]; then
    auth=(-H "Authorization: Bearer $token")
  fi
  if [ -f "$agent.verified" ]; then
    # Verified by the agent against the signed manifest before it exited.
    # Same directory, so the rename is atomic.
    chmod 0755 "$agent.verified"
    [ -f "$agent" ] && mv -f "$agent" "$agent.previous"
    mv -f "$agent.verified" "$agent"
    just_updated=1
    echo "[mustra] installed the agent's verified update"
  elif [ ! -x "$agent" ] || [ ! -f /opt/mustra-agent/service.env ] || [ "$(cat "$build_marker" 2>/dev/null)" != "$build_id" ]; then
    if [ -z "$server" ]; then
      echo "[mustra] set server_url in the add-on's configuration" >&2
    elif curl -fsSL --retry 3 --retry-all-errors "${auth[@]}" "$server/install.sh" -o /tmp/install.sh; then
      # A failed install leaves the previous agent in place (the installer
      # stages and verifies before replacing), so carry on and start it.
      if MUSTRA_NO_SERVICE=1 bash /tmp/install.sh; then
        echo "$build_id" > "$build_marker"
      else
        echo "[mustra] install failed; starting the installed agent" >&2
      fi
    else
      echo "[mustra] could not reach $server; starting the installed agent" >&2
    fi
  fi

  if [ ! -x "$agent" ] || [ ! -f /opt/mustra-agent/service.env ]; then
    echo "[mustra] no agent installed yet; retrying in 60s" >&2
    sleep 60 & wait $!
    continue
  fi

  set -a
  [ -f /opt/mustra-agent/agent.env ] && . /opt/mustra-agent/agent.env
  . /opt/mustra-agent/service.env
  set +a
  # No Self Service window: nobody signs in to a desktop on this host.
  started=$(date +%s)
  MUSTRA_UPDATE_BY_RESTART=1 "$agent" \
    --site "$site" --log-level "$log_level" --self-service-addr "" &
  pid=$!
  wait "$pid"
  rc=$?
  pid=""
  # A new build that fails within two minutes, other than to update again,
  # is put back to the previous one.
  if [ -n "$just_updated" ] && [ "$rc" != 75 ] && [ "$rc" != 0 ] && [ $(( $(date +%s) - started )) -lt 120 ] && [ -f "$agent.previous" ]; then
    echo "[mustra] the updated agent failed at once (status $rc); restoring the previous build" >&2
    mv -f "$agent.previous" "$agent"
  fi
  just_updated=""
  echo "[mustra] agent exited with status $rc; restarting in 5s"
  sleep 5 & wait $!
done
