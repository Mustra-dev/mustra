#!/usr/bin/env bash
# Runs the end-to-end tests the way CI does: bootstrap a blank-slate stack
# with deploy/init.sh --start, run the e2e-tagged Go tests against it, and
# tear everything down again.
#
#   test/e2e/run.sh                 # full pass, then teardown
#   MUSTRA_E2E_KEEP=1 test/e2e/run.sh   # leave the stack and endpoints up
#   test/e2e/run.sh -run 'TestE2E/(setup|public-url|enroll)'
#                                   # extra arguments go to `go test`
#
# Environment (all optional):
#   COMPOSE_PROJECT_NAME   compose project for the stack (default mustra-e2e)
#   COMPOSE_FILE           extra compose files, colon-separated, e.g. a local
#                          override for a host that needs one
#   MUSTRA_CONSOLE_PORT    host ports to publish on (init.sh; default
#   MUSTRA_NATS_PORT       8080 and 4222)
#   MUSTRA_VERSION         version stamped on the build (default 1.0.0-e2e;
#                          the update test needs a comparable version)
#   MUSTRA_E2E_HOST_IP     address endpoint containers reach this host at
#                          (default: the docker bridge gateway)
#   MUSTRA_E2E_ARTIFACTS   where logs, the UI report and screenshots go
#   MUSTRA_E2E_ENDPOINT_IMAGE, MUSTRA_E2E_UI, MUSTRA_E2E_CONSOLE_URL:
#                          see test/e2e/harness_test.go
#
# It needs a checkout with no deploy/.env: the pass is about a first run,
# and an existing .env is somebody's stack.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-mustra-e2e}"
export MUSTRA_VERSION="${MUSTRA_VERSION:-1.0.0-e2e}"
export MUSTRA_E2E_ARTIFACTS="${MUSTRA_E2E_ARTIFACTS:-$root/test/e2e/artifacts}"
mkdir -p "$MUSTRA_E2E_ARTIFACTS"

if [ -e deploy/.env ] || [ -e deploy/nats/certs ]; then
  echo "error: deploy/.env or deploy/nats/certs already exists. The e2e pass bootstraps a fresh" >&2
  echo "       stack and removes it afterwards; run it in a separate checkout or worktree." >&2
  exit 1
fi

host_ip="${MUSTRA_E2E_HOST_IP:-$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')}"

teardown() {
  status=$?
  (cd deploy && docker compose logs --no-color >"$MUSTRA_E2E_ARTIFACTS/compose.log" 2>&1) || true
  if [ "${MUSTRA_E2E_KEEP:-}" = 1 ]; then
    echo "MUSTRA_E2E_KEEP=1: leaving project $COMPOSE_PROJECT_NAME running" >&2
  else
    (cd deploy && docker compose down -v --remove-orphans) || true
    rm -rf deploy/.env deploy/nats/certs
  fi
  exit "$status"
}
trap teardown EXIT

start=$(date +%s)
deploy/init.sh --ip "$host_ip" --start
echo "stack up in $(( $(date +%s) - start ))s"

# The deployment checks no other job makes (see .github/workflows/e2e.yml).
# Both compose files resolve now that .env exists: compose.dev.yml is not
# part of this stack, so a slip in it would otherwise go unnoticed.
docker compose -f deploy/docker-compose.yml config -q
docker compose -f deploy/compose.dev.yml config -q
# The image compose just built carries every agent download -- six agents,
# two tray builds and the Python runtimes -- and the server.
server_image="$(docker inspect -f '{{.Image}}' "$(cd deploy && docker compose ps -q server)")"
docker run --rm --entrypoint sh "$server_image" -c '
  set -e
  cd /usr/local/share/mustra-agent-builds
  ls
  test "$(ls mustra-agent-* | wc -l)" -eq 6
  test "$(ls mustra-tray-windows-* | wc -l)" -eq 2
  ls mustra-python-* >/dev/null
  test -x /usr/local/bin/mustra-server'

go test -tags e2e -count=1 -timeout 60m -v ./test/e2e/ "$@" 2>&1 | tee "$MUSTRA_E2E_ARTIFACTS/go-test.log"
exit "${PIPESTATUS[0]}"
