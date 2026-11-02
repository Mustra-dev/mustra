# End-to-end fixtures

Operator-style inputs the e2e harness (`test/e2e`, build tag `e2e`) feeds a
fresh stack and an Ubuntu systemd endpoint. They started as the fixtures of
a manual acceptance run; each one pins down a behavior that run found
broken at some point, so the expected result is part of the fixture.

All packages are legacy `/api/software` packages: created with
`POST /api/software`, deployed with
`POST /api/software/deploy {"package_id","operation","agent_ids"}`, and
judged by the device result in `GET /api/agents/{id}/actions` for the
deployment's `run_id`.

| File | Kind | Operation | Expected device result |
|---|---|---|---|
| `packages/htop-install.json` | software, detects `app_name=htop` | install, then remove | `succeeded` both times; `htop` present, then gone, and applicability returns to `install_eligible` |
| `packages/always-fails.json` | action, exits 7 | install | `failed`, detail carries `exit status 7` and the stderr line |
| `packages/always-times-out.json` | action, `sleep 120` with a 10 s budget | install | `timed_out` near the budget (not `failed` after the server's grace period), and no `sleep 120` left running on the endpoint |
| `packages/env-credential-probe.json` | action | run | `succeeded` with `nats_password_vars_visible=0`: operator commands do not inherit the agent's bus credential. `run` must be accepted for a legacy action package |
| `custom-payload/` | software + uploaded file `mustra-hello.sh` (`POST /api/software/{id}/files`, multipart field `file`) | install | `succeeded`; the file is staged into the command's working directory and the output carries `hello from mustra test payload` |

## patching/

Shell scripts run on the endpoint (as root, with `dpkg-dev` installed). All
set `umask 022`, because `dpkg-deb` rejects group- or world-writable control
directories.

- `build-debs.sh <dir>` builds `mustra-dummy` 1.0 and 1.1 (arch `all`).
- `publish.sh <dir> <version>` exposes exactly one version in a flat repo,
  used with `deb [trusted=yes] file:<dir>/repo ./`.
- `build-broken-1.2.sh <dir>` builds 1.2 whose `postinst` exits 1.

Flow: install 1.0, publish 1.1, `apt-get update`, `POST /api/patches/rescan`;
`/api/patches` lists `mustra-dummy` 1.0 → 1.1; `POST /api/patches/deploy
{"target_agent": id}` succeeds and the endpoint has 1.1. Then publish the
broken 1.2 and deploy again: the device result is `failed` with dpkg's
error, not a false success.
