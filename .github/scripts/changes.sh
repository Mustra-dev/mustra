#!/usr/bin/env bash
# Decides which of CI's expensive jobs a push or pull request needs, and
# writes the answers to $GITHUB_OUTPUT (or stdout when run by hand):
#
#   agent=true|false         the macOS test job and the macOS/Windows sensor
#                            jobs, the slowest machines to get
#   script_tools=true|false  the script editor and language engines job
#
# Everything answers true when in doubt: a scheduled or manual run, an
# unknown event, a range git cannot resolve. A wrong "false" skips a check;
# a wrong "true" only costs minutes.
#
#   .github/scripts/changes.sh BASE HEAD     # by hand: what BASE...HEAD needs
#
# In CI (ci.yml's changes job) the range comes from the event instead:
#   EVENT_NAME   github.event_name
#   BASE_SHA     pull_request: the base commit
#   HEAD_SHA     pull_request: the head commit
#   BEFORE_SHA   push: the commit the branch pointed at before the push
#   SHA          push: the pushed commit
set -euo pipefail
cd "$(dirname "$0")/../.."

out="${GITHUB_OUTPUT:-/dev/stdout}"
answer() {
  echo "agent=$1" >>"$out"
  echo "script_tools=$2" >>"$out"
  echo "agent=$1 script_tools=$2 ($3)" >&2
}

zeros=0000000000000000000000000000000000000000
# from and to are the two trees the range compares.
if [ $# -eq 2 ]; then
  range="$1...$2"
  from="$(git merge-base "$1" "$2" 2>/dev/null)" || from=
  to="$2"
else
  case "${EVENT_NAME:-}" in
    pull_request)
      # Three dots: what the pull request changes, not what main gained
      # since it branched.
      range="$BASE_SHA...$HEAD_SHA"
      from="$(git merge-base "$BASE_SHA" "$HEAD_SHA" 2>/dev/null)" || from=
      to="$HEAD_SHA" ;;
    push)
      # A new branch, or a force push past history this checkout has, has
      # no usable "before".
      if [ -z "${BEFORE_SHA:-}" ] || [ "$BEFORE_SHA" = "$zeros" ] ||
        ! git cat-file -e "$BEFORE_SHA^{commit}" 2>/dev/null; then
        answer true true "push with no reachable before commit"
        exit 0
      fi
      range="$BEFORE_SHA..$SHA"
      from="$BEFORE_SHA"
      to="$SHA" ;;
    *)
      answer true true "${EVENT_NAME:-unknown} event runs everything"
      exit 0 ;;
  esac
fi

if ! changed="$(git diff --name-only "$range")"; then
  answer true true "cannot diff $range"
  exit 0
fi

# The agent's own packages, computed rather than listed so a new import is
# covered the day it lands (TestDockerfileCopiesAgentPackages does the
# same), plus every package their tests import -- that is how
# internal/sensorbuild, which the sensor jobs exercise, comes in. Only
# directories in this checkout matter, so no module needs downloading:
# GOPROXY=off with -e lists them without fetching anything.
agent_dirs() {
  local os pkgs
  for os in darwin windows; do
    pkgs="$(GOOS=$os GOPROXY=off go list -e -deps \
      -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./cmd/agent ./cmd/mustra-tray |
      grep "^$(go list -m)/" || true)"
    # shellcheck disable=SC2086 # one argument per package
    GOOS=$os GOPROXY=off go list -e -deps -test -f '{{if not .Standard}}{{.Dir}}{{end}}' $pkgs
  done | sed -n "s|^$PWD/||p" | sort -u
}
dirs="$(agent_dirs)" || dirs=
if [ -z "$dirs" ]; then
  answer true true "could not list the agent's packages"
  exit 0
fi

# The modules the agent and its tests build with, for both OSes. Unlike
# agent_dirs this may download modules, so it runs only when go.mod
# changed, and any failure answers "the agent needs testing".
agent_modules() {
  local os pkgs mod
  mod="$(go list -m)" || return 1
  for os in darwin windows; do
    pkgs="$(GOOS=$os go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./cmd/agent ./cmd/mustra-tray)" || return 1
    pkgs="$(grep "^$mod/" <<<"$pkgs")" || return 1
    # shellcheck disable=SC2086 # one argument per package
    GOOS=$os go list -deps -test -f '{{with .Module}}{{if not .Main}}{{.Path}}{{end}}{{end}}' $pkgs || return 1
  done
}

# Whether the go.mod change reaches the agent: a requirement on a module
# the agent builds with, or any directive other than a plain requirement
# (go, toolchain, replace, exclude, ...). A server-only dependency, such as
# a new YAML library for the API spec, does not.
gomod_reaches_agent() {
  local mods line path
  mods="$(agent_modules)" || return 0
  [ -n "$mods" ] || return 0
  while IFS= read -r line; do
    line="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^require[[:space:]]\{1,\}//' <<<"$line")"
    case "$line" in
      '' | '(' | ')' | 'require (' | //*) continue ;;
    esac
    if [[ "$line" =~ ^([^[:space:]]+)[[:space:]]+v[^[:space:]]+([[:space:]]+//[[:space:]]*indirect)?$ ]]; then
      path="${BASH_REMATCH[1]}"
      grep -qxF "$path" <<<"$mods" && return 0
      continue
    fi
    return 0
  done < <(git diff -U0 "$range" -- go.mod | sed -n 's/^[-+]\([^-+]\)/\1/p')
  return 1
}

# Whether ci.yml changed where the macOS and Windows legs run: anything
# above jobs: (triggers, concurrency) or the changes, check and go-sensors
# jobs. Editing another job (the script-tools Node version, say) does not
# need them. Either side unreadable answers yes.
workflow_reaches_agent() {
  local before after
  [ -n "$from" ] || return 0
  before="$(git show "$from:.github/workflows/ci.yml" 2>/dev/null | agent_jobs)" || return 0
  after="$(git show "$to:.github/workflows/ci.yml" 2>/dev/null | agent_jobs)" || return 0
  [ -n "$before" ] && [ -n "$after" ] || return 0
  [ "$before" != "$after" ]
}
agent_jobs() {
  awk '
    /^jobs:/ { injobs = 1; print; next }
    !injobs { print; next }
    /^  [A-Za-z0-9_-]+:/ { keep = ($1 == "changes:" || $1 == "check:" || $1 == "go-sensors:") }
    keep { print }
  '
}

# Anything a macOS or Windows run would build differently, or that decides
# how these jobs run.
agent=false
agent_reason=
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in
    .github/scripts/changes.sh | internal/sensorbuild/*)
      agent=true ;;
    go.mod)
      if gomod_reaches_agent; then agent=true; fi ;;
    # A go.sum change is judged by the go.mod change that comes with it;
    # one on its own is unusual enough to test everything.
    go.sum)
      if ! grep -qx go.mod <<<"$changed"; then agent=true; fi ;;
    .github/workflows/ci.yml)
      if workflow_reaches_agent; then agent=true; fi ;;
    *_darwin.go | *_windows.go | *_unix.go | *_darwin_test.go | *_windows_test.go | *_unix_test.go | \
      *_darwin_amd64.go | *_darwin_arm64.go | *_windows_amd64.go | *_windows_arm64.go)
      agent=true ;;
    *)
      while IFS= read -r d; do
        case "$f" in "$d"/*) agent=true; break ;; esac
      done <<<"$dirs" ;;
  esac
  if [ "$agent" = true ]; then agent_reason="$f"; break; fi
done <<<"$changed"

# Every input of the script-tools job: its own steps (the editor's npm
# test and build, the vendored output it diffs) and every COPY in
# deploy/Dockerfile.script-tools.
script_tools=false
tools_reason=
while IFS= read -r f; do
  case "$f" in
    tools/script-editor/* | tools/script-service/* | tools/python-runtime/* | \
      internal/sensorbuild/* | cmd/sensor-builder/* | internal/server/static/vendor/* | \
      go.mod | deploy/Dockerfile.script-tools | .github/workflows/ci.yml | .github/scripts/changes.sh)
      script_tools=true; tools_reason="$f"; break ;;
  esac
done <<<"$changed"

answer "$agent" "$script_tools" "$range: agent ${agent_reason:-untouched}, script tools ${tools_reason:-untouched}"
