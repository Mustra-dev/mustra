# deploy/ — the control plane

One compose stack: NATS (JetStream, TLS, a server credential plus a per-agent
identity for every endpoint, decided by the server through the broker's auth
callout), Postgres, the
mustra server (API + console UI), and isolated script-analysis tools. Endpoints run the agent binary the server
itself serves. Nothing here terminates TLS for the console; that is your
reverse proxy's job, or the optional Cloudflare Tunnel profile.

```
init.sh              first-run bootstrap and upgrade step: .env, keys,
                     certificates, LAN address; --start also builds and
                     starts the stack
docker-compose.yml   the stack; `--profile tunnel` adds cloudflared
compose.dev.yml      NATS + Postgres + script tools, server runs from source
Dockerfile.server    server image, with all six agent binaries inside
Dockerfile.script-tools  ShellCheck and PowerShell analysis/completion image
.env.example         every setting, documented; init.sh turns it into .env
nats/nats.conf       production NATS: TLS, server credential, auth callout
nats/gen-callout-key.sh  the auth-callout account key (nkey) init.sh writes to .env
nats/nats.dev.conf   development NATS: open, localhost only
nats/gen-certs.sh    self-signed CA + server certificate for the bus
cloudflared/         tunnel config template (placeholders: your tunnel ID, hostname)
```

## First run

```sh
./init.sh --start             # or: make quickstart, from the repository root
```

One command from a fresh clone to a console you can sign in to. It
preflights the host (Docker running, compose v2, ports 8080 and 4222 free,
or the ones named in `MUSTRA_CONSOLE_PORT` / `MUSTRA_NATS_PORT`,
disk space for the build), writes `.env` with generated secrets, generates
the NATS certificates with this host's LAN address in their SANs, points the
install scripts at that address, builds the images, and waits for
`/healthz` before printing where to sign in.

Bootstrap without starting anything by leaving `--start` off:

```sh
./init.sh                     # or: ./init.sh --ip 192.0.2.5
docker compose up -d --build --wait
```

`init.sh` never overwrites a value in an existing `.env` or existing
certificates, so it is safe to re-run; on an existing `.env` it only adds
what a newer version needs (see [Upgrading to per-agent identity](#upgrading-to-per-agent-identity)). The server refuses to start on placeholder secrets,
so skipping it does not produce a half-working stack, it produces a clear
error in `docker compose logs server`.

Then open the one-time setup link the server prints at first start
(`docker compose logs server | grep "FIRST-RUN SETUP"`; `--start` shows it)
and create the administrator — see [Console login](#console-login). There is
no default credential.

The console's **public URL** (`MUSTRA_PUBLIC_URL`) is what every agent-facing
link is built from. `init.sh --public-hostname <name>` sets it to
`https://<name>`; without it, set it under **Settings → Agent identity**. The server never derives it from a
request's `Host` header, and install scripts are not served until it is set.

### When it does not come up

`--start` prints `docker compose ps` and stops if the stack is not healthy.
The usual causes, in the order worth checking:

| Symptom | Cause |
| --- | --- |
| `server` restarting, logs say placeholder secrets | `.env` was copied from `.env.example` by hand instead of generated |
| `nats` will not start | `nats/certs/` missing — re-run `init.sh`, or `nats/gen-certs.sh <ip>` |
| `server` unhealthy, `script-tools` never healthy | tried to pull rather than build; see below |
| Agents install but never appear | `MUSTRA_AGENT_NATS_URL` names an address the endpoint cannot reach, or the certificate's SANs do not cover it |
| `nats` refuses to start: `MUSTRA_NATS_CALLOUT_ISSUER` | an `.env` from before per-agent identity — run `./init.sh` once |
| Every agent: `Authorization Violation` | the server is down (the broker asks it about every agent connection), or `MUSTRA_NATS_CALLOUT_SEED` and `MUSTRA_NATS_CALLOUT_ISSUER` are not a pair |
| `server` restarting: `ensure agent stream: … insufficient storage resources available` | JetStream reserves 3 GiB for the agent stream and the disk holding the `nats` volume has less than about 4 GiB free |

`docker compose logs server` answers most of the rest.

## Building vs pulling

`docker compose up -d --build` builds the server and script-tools images from this checkout. It
cross-compiles six agent binaries using the native builder. Later builds
reuse separate server and agent layers and shared Go caches. `make image` from the repository root
builds the server image with the version stamped in from `git describe`, so the
About page reports what is actually running.

`docker compose pull && docker compose up -d` uses published images
instead, `ghcr.io/mustra-dev/mustra` and
`ghcr.io/mustra-dev/mustra-script-tools` at the tag in `MUSTRA_IMAGE_TAG`
(default `latest`). Releases are published by `.github/workflows/release.yml`
on every `v*` tag. CI compiles once and packages the same agent binaries into
both image architectures and release downloads.

**Building is the path that always works**, and the one `init.sh --start`
and `make up` take. The published packages are public, so pulling needs no
login; but `server` waits on `script-tools` being healthy, so a pull that
fetched only one image (a tag published for one and not the other) sits
there rather than failing loudly. Pin `MUSTRA_IMAGE_TAG` to a release that
has both.

For an existing healthy stack, update the server and matching language tools
without restarting NATS or Postgres:

```sh
docker compose pull server script-tools
docker compose up -d --no-deps --no-build script-tools server
```

Set `MUSTRA_IMAGE_TAG` to a specific release for a repeatable deployment.

## Public access

The console must be reached over HTTPS for anything beyond a first look:
the session cookie is Secure by default, enrollment tokens travel in the
install one-liners, and the install scripts fetch the NATS CA over the
console's own connection.

Any reverse proxy that forwards to `server:8080` works. The stack also
carries a Cloudflare Tunnel as an opt-in profile:

```sh
cloudflared tunnel create mustra
cloudflared tunnel route dns mustra console.example.com
cp ~/.cloudflared/<tunnel-id>.json cloudflared/creds.json
cp cloudflared/config.yml cloudflared/config.local.yml
# edit cloudflared/config.local.yml: replace the placeholder tunnel ID and
# console.example.com with your tunnel ID and hostname
echo 'MUSTRA_CLOUDFLARED_CONFIG=./cloudflared/config.local.yml' >> .env
docker compose --profile tunnel up -d
```

`config.local.yml` is ignored by git, so pulling a new release never
replaces your tunnel config with the template. (Editing `config.yml` in
place still works when `MUSTRA_CLOUDFLARED_CONFIG` is unset, but then an
update overwrites it.)

Then set `MUSTRA_PUBLIC_URL` and `MUSTRA_OIDC_REDIRECT_URL` in `.env`, or run
`init.sh --public-hostname console.example.com` to have them filled in. Set
`MUSTRA_TRUSTED_PROXIES` to the proxy's network so forwarded client addresses
are believed (and only then), and `MUSTRA_TRUSTED_ORIGINS` if the proxy
rewrites `Host`.

## Configuration

Everything is in `.env`, documented inline in `.env.example`. Every
`MUSTRA_*` value passes straight through to the server; `mustra-server -h`
lists them all with defaults. The pre-rename `BEACON_*` names are still read,
so an older `.env` keeps working untouched.

Settings the console can change at runtime (SSO, break-glass account, SCIM,
agent staleness, public URL, legacy agent credential) are seeded from `.env`
on first boot and edited under **Administration → Settings** after that.

Variables added by the 0.80 hardening, all documented in `.env.example`:
`MUSTRA_NATS_CALLOUT_SEED`/`_ISSUER` (auth callout key), `MUSTRA_PUBLIC_URL`
and `MUSTRA_ALLOW_INSECURE_PUBLIC_URL`, `MUSTRA_AGENT_SIGNING_KEY` (or
`MUSTRA_AGENT_SIGNING_KEY_FILE`, or `MUSTRA_AGENT_SIGNING_PUBKEY` for
release-signed builds), `MUSTRA_BREAKGLASS_USERNAME`/`_PASSWORD` (replacing
`MUSTRA_BACKDOOR_*`, still read with a warning), `MUSTRA_TRUSTED_PROXIES`,
`MUSTRA_TRUSTED_ORIGINS`, `MUSTRA_OIDC_ALLOWED_*`, `MUSTRA_SETUP_TOKEN`,
`MUSTRA_BACKUP_SIGNING_KEY`, `MUSTRA_IMPORT_ALLOWED_HOSTS`,
`MUSTRA_EXPORT_DIR`, and `MUSTRA_ALLOW_PLACEHOLDER_SECRETS` (development only).

## Console login

- **First run.** A deployment with no account configured serves a one-time
  setup page instead of a login, and only through the setup link the server
  prints in its log at first start (`docker compose logs server | grep
  "FIRST-RUN SETUP"`), which carries a one-time token — or with
  `MUSTRA_SETUP_TOKEN` if you set one. Whoever opens it creates the
  administrator, and the page closes permanently once it exists.
- **Break-glass local account**, `MUSTRA_BREAKGLASS_USERNAME` /
  `MUSTRA_BREAKGLASS_PASSWORD` (the older `MUSTRA_BACKDOOR_*` names still
  work, with a warning), synced to Postgres on every restart. This is
  what gets you in if SSO is down. Setting both here skips the setup page,
  which is what you want when rebuilding a deployment from configuration.
- **SSO**, once `MUSTRA_OIDC_*` are set; the button on `/login` appears when
  discovery succeeds and retries in the background until it does. Nobody
  signs in through it until an allowlist rule (`MUSTRA_OIDC_ALLOWED_*`, or
  Settings) admits them.
- **SCIM provisioning** at `/scim/v2/` with the bearer token in
  `MUSTRA_SCIM_TOKEN`. Provisioned users sign in via SSO.

See `docs/ARCHITECTURE.md` for how each works and for RBAC.

## Deploying agents

Every endpoint has an identity of its own. **Client Management → Manual
install** creates an **enrollment token** (one use by default; up to 1000 for
a mass rollout; it expires) and shows the one-liner per OS that carries it. The
command checks the installer's hash before running it, so it stops working if the
server changes; the console also offers commands for automation that stores them,
such as:

```sh
curl -fsSL -H 'Authorization: Bearer mte_…' 'https://<console>/install.sh?site=lab' | sudo bash
```

The installer pulls the binary from `/downloads/` (checksum mandatory),
fetches the CA, installs a systemd unit, OpenRC service (Alpine: the console's
Alpine command adds `bash` and `curl` first), launchd daemon or Windows service and
a checksum-verified Python runtime ([Custom sensors](../docs/CUSTOM-SENSORS.md#python-installation)),
and leaves the token in the agent's data directory. On first start the agent
exchanges it — over the bus, authenticated by the token — for its own
credential (agent ID + secret; the server stores only a hash), deletes the
token and pins this deployment's update signing key. From then on the broker
lets it publish and subscribe only on its own subjects. The script carries no
shared secret: fetched without a token it updates an already-enrolled
endpoint and refuses to install a new one. The endpoint needs to reach
`MUSTRA_AGENT_NATS_URL` on port 4222.

Network scan and SSH push needs `MUSTRA_CREDENTIAL_ENCRYPTION_KEY` set
(`init.sh` generates one); each push mints a single-use token of its own.

**Updates** are signed. The console's Update buttons and Self Service send the
endpoint a manifest signed with the deployment key (`MUSTRA_AGENT_SIGNING_KEY`);
the agent verifies it against the key it pinned, refuses anything older unless
the operator explicitly allowed a downgrade for that one endpoint, swaps the
binary atomically and rolls back if the new build does not start and reach the
console within three minutes. No install script is run to update.

**Revoking** an endpoint: `POST /api/agents/<id>/revoke-credential` (deploy.manage);
the broker refuses it from its next connection, at most an hour later.

By hand, against this stack (with a token from the console):

```sh
go run ./cmd/agent --nats-url tls://<host>:4222 --nats-ca deploy/nats/certs/ca.crt \
  --enroll-token "mte_…" --site lab
```

## Upgrading to per-agent identity

> **The shared credential is retired from the release after 0.104.** A
> server that enforces agent identity no longer accepts the shared password
> at all. An install from before 0.80 must first upgrade to **0.104.x**, the
> last release that accepts it, and finish the steps below until
> **Endpoints that need re-enrollment** is empty; only then move on. An
> agent that never enrolled cannot connect to a newer server and has to be
> reinstalled with an enrollment token.

An install from before 0.80 has agents that all hold one shared password.
They keep working through the upgrade to 0.104.x. Take a backup first (Administration
→ Backup) and keep a copy of `.env` and `nats/certs/`.

1. `git pull` (or check out the release), then `./init.sh` (no flags needed;
   add `--public-hostname` if you have one). It adds
   `MUSTRA_NATS_CALLOUT_SEED`/`_ISSUER` and `MUSTRA_AGENT_SIGNING_KEY` to
   `.env` and changes nothing else; the shared password and the NATS
   certificates stay. It ends with the generic first-run text about a setup
   link: on an upgrade there is none to open, sign in as before.
2. Rebuild **with a version**, then start:

   ```sh
   cd .. && make up VERSION=0.80.0 AGENT_VERSION=0.55.0   # your release numbers
   # or: cd deploy && MUSTRA_VERSION=0.80.0 MUSTRA_AGENT_VERSION=0.55.0 docker compose up -d --build
   ```

   A plain `docker compose up -d --build` (or `make up` in a clone without
   tags) stamps the server and every agent it serves as `dev` or a bare
   commit, which cannot be compared with the 0.5x your endpoints run, so
   **no endpoint can be updated** from that build; the Update button says
   so. The console is down for a few seconds and agents reconnect on their
   own. The server sees existing agents and turns **Settings → Agent
   identity → Allow legacy shared agent credential** on.
3. Confirm the **public URL** in Settings. The URL the old version learned
   from request headers is shown as a suggestion only; nothing uses it until
   you confirm it, because anyone who could reach the console could have
   written it. A plain-http LAN install (the old default) must also tick
   **Allow plain http** (or set `MUSTRA_ALLOW_INSECURE_PUBLIC_URL=true`);
   without a public URL no agent can be updated.
4. Update the agents (Client Management → Update, or **Update all online**).
   An agent from before 0.80 updates the old way, by running the installer;
   it keeps its agent ID, history and site. On its first start the new agent
   trades the shared password for its own credential, pins the update key,
   and removes the password from where the installer left it (Linux/macOS:
   `agent.env`; Windows: the world-readable Machine environment). From then
   on updates are signed and verified by the agent.
   - The console reports an old agent's update as **started** as soon as the
     endpoint has launched the installer; the outcome is not reported back.
     Check the version under Client Status a minute later.
   - An endpoint that was **offline** during the upgrade reconnects on the
     shared password while it is still allowed; update it then.
   - An endpoint whose update cannot run (no `curl`, the console's HTTP port
     blocked, a broken install) stays on its old version. Run the token
     one-liner from **Client Management → Manual install** on it, with its
     current `?site=`. An endpoint that has no credential of its own yet
     keeps its agent ID and history; one that already enrolled keeps its
     credential and ignores the token (the token is not used up).
5. When **Endpoints that need re-enrollment** is empty, switch the legacy
   credential off. Anything still using it is disconnected within ten minutes
   and must then be reinstalled with a token. Then remove
   `MUSTRA_NATS_AGENT_PASSWORD` from `.env` and recreate the server
   (`docker compose up -d`).

Until step 5, the shared password still lets its holder act as any agent that
has not enrolled: the exposure the transition exists to end, so keep it short.

**Backups from before the upgrade** are unsigned. Only an administrator can
restore one, through **Import an external backup**. It returns the database
to that moment: settings made since (the public URL, the legacy switch) are
gone and must be set again, sessions end, and agents that enrolled since
keep their credentials and keep reporting.

**Rolling the server back** to a pre-0.80 build is not supported once any
agent has enrolled. The old broker configuration has no auth callout, so
every enrolled agent is refused (`authorization violation`, retried every
few seconds) and, its shared password removed, cannot reconnect until the
server is rolled forward again or the endpoint is reinstalled with the old
installer. The old server also cannot use what this release rewrote:
every sign-in session ends (session tokens are stored hashed), webhook
trigger URLs stop firing (tokens hashed), and deploy credentials and
escrowed BitLocker passwords no longer decrypt (re-sealed in a format it
does not know). API tokens, packages, history, groups and schedules are
unaffected. Rolling forward again makes webhooks and stored credentials
work again, and agents reconnect with their credentials within seconds. Keep the pre-upgrade backup and `.env` if
you need a way back before any agent has updated.

### Windows endpoints

Not exercised end to end in this release's upgrade test (Linux endpoints
were); the installer and agent paths are the same as on Linux, so expect:

- The old agent's update runs `install.ps1` (staged to `%TEMP%`) from the
  public URL with the endpoint's site, under the service account. It finds
  the shared password in the Machine environment, moves it into
  `C:\Program Files\mustra-agent\agent.env` readable only by SYSTEM and
  Administrators, deletes the Machine variables, and updates the existing
  service in place (ImagePath; restart-on-failure set).
- The new agent trades the password for its credential
  (`agent-credential.json` in the data directory, SYSTEM/Administrators
  only), removes `agent.env`, and logs "removed a legacy credential from the
  Machine environment" if anything was left. Processes started before the
  update keep the old environment until they exit; a reboot clears it from
  every session.
- This first, installer-based update also replaces the tray helper. Later
  signed updates replace only the agent binary; the tray, Python runtime
  and uninstall password are refreshed by re-running the token one-liner,
  which does not change an enrolled agent's identity.
- An endpoint whose PowerShell execution or download is blocked by policy
  stays on its old version: use the PowerShell token one-liner from Client
  Management, elevated.

## Verifying store-and-forward

```sh
docker compose stop nats
# the agent logs "buffering" warnings and keeps trying
docker compose start nats
# the agent logs "nats reconnected" then "outbox flushed"; nothing is lost
```

## Backing up

**Administration → Backup** in the console takes a backup now or nightly,
keeps the number of archives you choose, and restores from a kept one or an
uploaded file. An archive is a `pg_dump` of the database plus, optionally,
the package files staged to endpoints — those are large and re-uploadable,
so they are excluded by default.

Two things are deliberately **not** in a backup, both of which live here in
`deploy/` rather than in the database:

- `MUSTRA_CREDENTIAL_ENCRYPTION_KEY` from `.env`. Stored credentials are
  encrypted with it, so restoring a database onto a deployment with a
  different key leaves those rows undecryptable. A backup carrying the key
  that protects it would protect nothing.
- `nats/certs/`. Losing them takes the bus down; they are regenerated with
  `nats/gen-certs.sh`, not restored.

Back both up by whatever means you already use for host files, and keep them
somewhere other than the machine they came from.

A restore replaces every row and then restarts the server: the dump drops
and recreates every object, so the pool, the settings snapshot and the live
hub are all describing a database that stopped existing partway through. It
applies under `ON_ERROR_STOP` in a single transaction, so a damaged archive
commits nothing.

To check an archive without touching the running deployment, restore it into
a scratch database instead:

```sh
tar -xzf <archive>.tar.gz database.sql
docker compose exec -T postgres psql -U "$POSTGRES_USER" -d postgres \
  -c 'CREATE DATABASE restorecheck'
docker compose exec -T postgres psql -U "$POSTGRES_USER" -d restorecheck \
  -v ON_ERROR_STOP=1 --single-transaction < database.sql
```

Compare a table or two against the live database, then
`DROP DATABASE restorecheck`.

## Disconnecting revoked agents at once

Revoking an agent's credential (Endpoints → the agent → Revoke
credential) closes its live connection through NATS's system account, so
the agent is cut off at once instead of when its authorization expires,
up to an hour later. That needs `MUSTRA_NATS_SYS_PASSWORD` in `.env`.
A fresh `./init.sh` writes it. On an existing install, run `./init.sh`
again (it only adds what is missing), then recreate NATS and the server:

```sh
./init.sh
docker compose up -d --force-recreate nats server
```

Agents reconnect within seconds of NATS restarting. Without the variable
NATS starts the system user with a random password, and revocation waits
for the expiry as before.

## Upgrading Postgres across a major version

The compose file pins a Postgres major. A major upgrade is never in place:
the new server refuses to start on the old cluster's data directory, so
moving from 16 to 18 means dumping with the old image and loading into a new
one. The control plane is down for the length of the dump.

Postgres 18 also changed the image's own defaults -- `PGDATA` moved to
`/var/lib/postgresql/<major>/docker` and the volume to `/var/lib/postgresql`.
The compose file sets `PGDATA` back to `/var/lib/postgresql/data` so the
existing `postgres-data` volume stays the cluster directory. Leaving that out
is worse than an error: the entrypoint finds nothing at the new path, runs
`initdb`, and the stack comes up healthy on an empty database while the real
one sits untouched in the volume.

Use `pg_dump` of the one application database, not `pg_dumpall`. The stack has
a single role, and `pg_dumpall` emits `CREATE ROLE` for it, which collides
with the role the new container's entrypoint has already created from
`POSTGRES_USER` -- under `ON_ERROR_STOP` that aborts the whole restore on its
first statement.

**Stop the server before dumping.** `process_events` and `recorder_events`
take agent telemetry continuously; a dump taken while the server is running is
a point-in-time snapshot that is already behind by the time it finishes, and
those rows are simply lost.

Take a console backup first (**Administration → Backup**), then, with the old
image still pinned in `docker-compose.yml`:

```sh
docker compose stop server                     # stop writes, keep Postgres up
docker compose exec -T postgres \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" > /tmp/mustra-pg16.sql
docker compose stop postgres
```

Keep the old volume as the rollback rather than deleting it:

```sh
docker volume create mustra-postgres-data-16
docker run --rm -v <project>_postgres-data:/from \
  -v mustra-postgres-data-16:/to alpine sh -c 'cd /from && cp -a . /to'
docker volume rm <project>_postgres-data
```

Now pin the new major and bring Postgres up on the empty volume. Match the old
cluster's locale explicitly -- `initdb` otherwise picks the image default, and
a different collation silently changes text index ordering:

```sh
docker compose exec -T postgres \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -tAc 'select datcollate from pg_database where datname=current_database()'
```

Set `LANG` and `POSTGRES_INITDB_ARGS=--locale=<that value>` on the postgres
service for the first start, then restore into the database the entrypoint
created:

```sh
docker compose up -d postgres
docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -v ON_ERROR_STOP=1 --single-transaction < /tmp/mustra-pg16.sql
docker compose up -d server
```

Verify before trusting it. Table inventory, row counts and index count should
match the old cluster exactly; `pg_constraint` will not, because PG17+ records
NOT NULL constraints there and PG16 does not. Compare constraints with
`contype <> 'n'`, or count NOT NULL columns through `information_schema.columns`,
which reads the same on both.

The server image's `pg_dump`/`psql` are pinned to the same major as the
service for a reason: `pg_dump` refuses to dump a server newer than itself, so
bump the `postgresql<major>-client` package in `Dockerfile.server` in the same
change, or Administration → Backup starts failing quietly. A client ahead of
the server is fine, so rebuild the server image before the upgrade and it
covers both sides of the window.

Once the new cluster has served real traffic for a while, delete
`mustra-postgres-data-16`.

## Resetting

```sh
docker compose down            # keep volumes (Postgres, NATS, package files)
docker compose down -v         # wipe everything
rm -rf nats/certs .env         # start from init.sh again
```

Rotating the agent NATS password means re-running the installer on every
endpoint, since the credential is embedded in the install script.

## Script tools

The custom sensor editor uses the separate `script-tools` service for ShellCheck,
PSScriptAnalyzer, and language-server completion. Compose supplies the server's
`MUSTRA_SCRIPT_TOOLS_URL` and places the tools on a private internal network.
The tools have no NATS/database credentials or package/output mounts. Keep the
network restrictions and resource limits in place: PowerShell completion uses a
live runspace. Releases publish `mustra-script-tools` under the same version tags
as the server. Updating this feature requires pulling/recreating both services:

```sh
docker compose pull server script-tools
docker compose up -d --no-deps --no-build script-tools server
```

Without reachable tools, script saves report validation unavailable; they are
not silently accepted. Endpoint collection of already-saved sensors is unchanged.
See [script-service documentation](../tools/script-service/README.md) for engine
versions, runtime limits, and validation commands.

### Go sensor builds

Rebuild/redeploy `script-tools`, server, and agents for Go custom sensors. The
tools image includes Go 1.27.2 and the isolated builder. Compose increases its
noexec scratch filesystem to 1 GiB for compilation; memory remains 1.5 GiB.
The server stores compiled artifacts in the existing package-files volume.
See [Go programs](../docs/CUSTOM-SENSORS.md#go-programs) for limits, cache
retention, rollback, and agent capability negotiation.
