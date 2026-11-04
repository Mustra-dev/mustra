-- Mustra inventory schema. Applied automatically by the server at startup
-- (idempotent: every statement is CREATE ... IF NOT EXISTS).
--
-- Slice 1 keeps this to a single table: current agent state. Historical
-- facts/heartbeat time series belong in VictoriaMetrics, not Postgres — see
-- docs/ARCHITECTURE.md.

CREATE TABLE IF NOT EXISTS agents (
    agent_id         TEXT PRIMARY KEY,
    hostname         TEXT NOT NULL,
    os               TEXT NOT NULL,
    arch             TEXT NOT NULL,
    site             TEXT NOT NULL,
    agent_version    TEXT NOT NULL DEFAULT '',
    platform         TEXT NOT NULL DEFAULT '',
    platform_version TEXT NOT NULL DEFAULT '',
    kernel_version   TEXT NOT NULL DEFAULT '',
    cpu_count        INTEGER NOT NULL DEFAULT 0,
    mem_total_mb     BIGINT NOT NULL DEFAULT 0,
    ips              TEXT[] NOT NULL DEFAULT '{}',
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat   TIMESTAMPTZ,
    last_facts       TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agents_last_heartbeat ON agents (last_heartbeat);

-- Console identity: local (backdoor) accounts, OIDC-authenticated users, and
-- users/groups provisioned via SCIM. One table for all three sources —
-- "source" and "external_id" record provenance, but auth (session creation)
-- doesn't care which source a user came from.
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL DEFAULT '',
    display_name  TEXT NOT NULL DEFAULT '',
    password_hash TEXT,                          -- bcrypt hash; NULL for SSO/SCIM-only users
    source        TEXT NOT NULL DEFAULT 'local',  -- 'local' | 'oidc' | 'scim'
    external_id   TEXT,                           -- SCIM externalId / OIDC subject
    is_admin      BOOLEAN NOT NULL DEFAULT false,
    active        BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id ON users (external_id) WHERE external_id IS NOT NULL;

-- Sign-in history, for the profile menu's "Last Sign In".
--
-- Two columns rather than one because the useful answer is the sign-in
-- BEFORE this one: "you last signed in on Tuesday" is something a person can
-- check against their own memory and notice is wrong, which is the entire
-- security value of showing it. Displaying the current session's own start
-- time would just tell them what they already know.
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_sign_in TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS previous_sign_in TIMESTAMPTZ;

-- Per-user console preferences.
--
-- Stored server-side rather than in the browser because one of them is a
-- security control: "sign out after N minutes idle" that lives in
-- localStorage is a security control anyone can clear by opening a private
-- window, which is no control at all. The rest ride along so that a person's
-- console follows them between machines.
--
-- One JSON column rather than a column per preference: these change shape
-- as the console grows, and a migration per checkbox is a tax with no payer.
CREATE TABLE IF NOT EXISTS user_preferences (
    user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    prefs      JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS groups (
    id           TEXT PRIMARY KEY,
    display_name TEXT NOT NULL UNIQUE,
    external_id  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_external_id ON groups (external_id) WHERE external_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

-- Server-side sessions: the cookie holds only the opaque token, so a
-- session can be revoked (e.g. on logout, or by clearing the table) without
-- needing a JWT blocklist.
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);

-- Latest cached snapshot per (agent, sensor) — a "keep an answer fresh
-- centrally" cache. One row per sensor per agent, overwritten
-- on every periodic publish or on-demand query response; no history here
-- (that's VictoriaMetrics territory, not yet wired — see docs/ROADMAP.md).
-- SSH credentials for pushing the agent to discovered hosts (deploy page's
-- network-scan flow). Secrets are encrypted at rest with AES-256-GCM using
-- BEACON_CREDENTIAL_ENCRYPTION_KEY — Postgres never sees plaintext, and
-- the plaintext is never returned by any API once stored. See
-- docs/ARCHITECTURE.md.
CREATE TABLE IF NOT EXISTS deploy_credentials (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    username      TEXT NOT NULL,
    auth_type     TEXT NOT NULL,   -- 'password' | 'private_key'
    secret_cipher BYTEA NOT NULL,  -- AES-GCM(nonce || ciphertext) of the password or private key PEM
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT NOT NULL DEFAULT ''
);
-- Added after the table above already shipped, hence a separate idempotent
-- ALTER rather than folding into CREATE TABLE: the encrypted passphrase
-- for a passphrase-protected private_key credential (NULL for password
-- credentials, and for private keys with no passphrase).
ALTER TABLE deploy_credentials ADD COLUMN IF NOT EXISTS passphrase_cipher BYTEA;

-- The first Self Service catalog: what a person could install on their own
-- machine. `packages` maps an OS to the package name for that OS
-- ({"linux":"vlc","windows":"VideoLAN.VLC","darwin":"vlc"}), so one item
-- covered a mixed fleet.
--
-- Superseded by software_packages (below), and nothing writes it any more.
-- It stays for the data an older release left in it, which the one-time
-- carry into the package model further down reads.
CREATE TABLE IF NOT EXISTS catalog_items (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    category          TEXT NOT NULL DEFAULT '',
    icon              TEXT NOT NULL DEFAULT '',
    type              TEXT NOT NULL DEFAULT 'package',
    packages          JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Which computer groups may install this. Empty means every device.
    group_ids         TEXT[] NOT NULL DEFAULT '{}',
    -- When true a device outside those groups can still ask for it, and an
    -- admin decides. When false it simply isn't offered.
    allow_requests    BOOLEAN NOT NULL DEFAULT true,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by        TEXT NOT NULL DEFAULT ''
);

-- carried_to_packages: this item has had its one copy into
-- software_packages, so no later start copies it again. Without it the
-- carry ran on every start, and a carried package an operator deleted came
-- back at the next restart.
--
-- It is decided here, before software_packages is created, because that
-- table's presence is the only record of whether the old every-start copy
-- has run: both arrived in the same release. A database that already has
-- the table has had every item copied at some earlier start, so its items
-- are marked as carried rather than copied again; one from before the
-- package model has its items carried below, once.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema = current_schema() AND table_name = 'catalog_items'
       AND column_name = 'carried_to_packages'
  ) THEN
    ALTER TABLE catalog_items ADD COLUMN carried_to_packages BOOLEAN NOT NULL DEFAULT false;
    IF to_regclass('software_packages') IS NOT NULL THEN
      UPDATE catalog_items SET carried_to_packages = true;
    END IF;
  END IF;
END $$;

-- A software package is one piece of software mustra knows how to install,
-- update, or remove, on whichever platforms it defines a command for.
--
-- It deliberately supersedes catalog_items: there is one package catalog
-- and Self Service is a publishing decision on top of it, because a
-- package someone can request is the same object as one
-- an operator pushes, and keeping two tables would mean maintaining the
-- same software twice.
CREATE TABLE IF NOT EXISTS software_packages (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    vendor        TEXT NOT NULL DEFAULT '',
    version       TEXT NOT NULL DEFAULT '',
    description   TEXT NOT NULL DEFAULT '',
    category      TEXT NOT NULL DEFAULT '',
    icon          TEXT NOT NULL DEFAULT '',

    -- Per-OS operations: {"linux": {"install": "...", "update": "...",
    -- "remove": "..."}, "darwin": {...}, "windows": {...}}. An OS with no
    -- entry is simply not applicable to that platform, which is how a
    -- Windows-only package stays invisible to Macs.
    commands      JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- How to tell whether it is already installed, and at what version.
    -- {"app_name": "...", "match": "exact|contains"} matches the
    -- installed_apps sensor mustra already collects, which costs nothing
    -- extra on the endpoint.
    detect        JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- {"arch": ["amd64"], "min_disk_gb": 2, "min_ram_mb": 2048}
    requirements  JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Which computer groups may receive it. Empty means every device.
    group_ids     TEXT[] NOT NULL DEFAULT '{}',
    -- Published to the Self Service window on entitled endpoints.
    self_service  BOOLEAN NOT NULL DEFAULT false,
    -- A device outside the scope may ask for it, and an admin decides.
    allow_requests BOOLEAN NOT NULL DEFAULT false,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    -- 'manual' when someone authored it, 'discovered' when it came from
    -- what the fleet already has installed.
    source        TEXT NOT NULL DEFAULT 'manual',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_software_packages_name ON software_packages (lower(name));

-- Package files: the payload a package needs, staged to the endpoint before
-- its command runs.
--
-- Without this, every command has to fetch its own installer, which quietly
-- limits the catalog to software reachable from a URL the endpoint can hit.
-- That rules out anything licensed, anything internal, and anything on a
-- network segment with no egress -- which between them is most of what an
-- organisation actually deploys.
--
-- Only metadata lives here. The bytes are on disk (see packageFileStore),
-- because a Postgres row is a poor place to keep a 400 MB MSI: every backup,
-- every replica and every query planner statistic then carries it too.
CREATE TABLE IF NOT EXISTS package_files (
    id         TEXT PRIMARY KEY,
    package_id TEXT NOT NULL REFERENCES software_packages(id) ON DELETE CASCADE,
    -- The filename the endpoint sees. Separate from the id so a package can
    -- refer to "setup.msi" in its command regardless of how it is stored.
    name       TEXT NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    -- Recorded at upload and re-verified on the endpoint after download. A
    -- staged file that silently truncated is worse than one that failed to
    -- arrive, because the command runs anyway.
    sha256     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_package_files_package ON package_files (package_id);

-- Scheduled actions: run a package on a cadence, not just patches.
--
-- Patch schedules already existed, which quietly said "recurring work is a
-- patching concern". It is not: restarting a service every Sunday, clearing
-- a cache nightly, re-running a compliance script weekly are all the same
-- shape, and doing them meant somebody remembering to click Deploy.
--
-- Deliberately a schedule over a PACKAGE rather than over a raw command.
-- The package already carries per-OS commands, applicability, a timeout, an
-- expiry and its parameters; a schedule that took a command string instead
-- would be a second, worse way to define the same thing, and the one nobody
-- audits.
CREATE TABLE IF NOT EXISTS scheduled_actions (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    package_id  TEXT NOT NULL REFERENCES software_packages(id) ON DELETE CASCADE,
    operation   TEXT NOT NULL DEFAULT 'install',   -- install | update | remove
    -- Parameter values for a parameterised package, resolved and validated
    -- at fire time exactly as an interactive deploy would.
    parameters  JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Targeting, same vocabulary the bulk deploy uses. All empty means
    -- every applicable online endpoint.
    target_os    TEXT NOT NULL DEFAULT '',
    target_site  TEXT NOT NULL DEFAULT '',
    target_agent TEXT NOT NULL DEFAULT '',

    kind        TEXT NOT NULL DEFAULT 'daily',     -- once | daily | weekly
    run_at      TIMESTAMPTZ,                       -- "once" only
    time_of_day TEXT NOT NULL DEFAULT '03:00',     -- HH:MM UTC
    weekday     INTEGER,                           -- 0 (Sunday) - 6, "weekly" only

    enabled     BOOLEAN NOT NULL DEFAULT true,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_scheduled_actions_next ON scheduled_actions (next_run_at) WHERE enabled;

-- Threat hunting: indicators of compromise, matched against what mustra
-- already collects.
--
-- This is deliberately hunting over CACHED sensor data rather than a live
-- sweep of every endpoint. The whole point of the sensor model is that the
-- fleet's state is already here; asking "is this hash anywhere in my
-- estate" should be a database question answered in milliseconds, not
-- thirty-nine machines woken up to grep their own disks. The trade is
-- explicit and worth stating: a hunt sees what the sensors see, so a file
-- outside the integrity watch set or a process that started and exited
-- between collections is invisible to it.
CREATE TABLE IF NOT EXISTS iocs (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    -- What kind of thing the value is, which decides the sensor it is
    -- matched against: file_hash -> integrity, process_name -> processes,
    -- file_path -> integrity, ip -> neighbours and interfaces,
    -- app_name -> installed applications.
    kind        TEXT NOT NULL,
    value       TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'warning',  -- info | warning | critical
    description TEXT NOT NULL DEFAULT '',
    -- Where it came from, so a finding can be traced back to the feed or
    -- advisory that justified looking for it.
    source      TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_iocs_kind ON iocs (kind) WHERE enabled;

-- One indicator seen on one endpoint.
--
-- Keyed on (ioc, agent, matched_value) so a repeat hunt updates last_seen
-- rather than adding a row every fifteen minutes: a finding that multiplies
-- itself is one nobody can count, and "how long has this been here" is the
-- question that actually matters.
CREATE TABLE IF NOT EXISTS ioc_findings (
    id            TEXT PRIMARY KEY,
    ioc_id        TEXT NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    agent_id      TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    matched_value TEXT NOT NULL DEFAULT '',
    context       TEXT NOT NULL DEFAULT '',
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Acknowledged findings stay visible but stop counting as outstanding,
    -- because deleting them would lose the fact that it was ever there.
    acknowledged  BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (ioc_id, agent_id, matched_value)
);
CREATE INDEX IF NOT EXISTS idx_ioc_findings_ioc ON ioc_findings (ioc_id);

-- Custom sensors: operator-authored collection.
-- The built-in thirteen answer the questions everybody has;
-- this is for the ones only you have.
--
-- On trust: this runs operator-written code on every endpoint with the
-- agent's rights. That is the same boundary a software package's command
-- already crosses deliberately, so it is gated on the same permission
-- rather than a new one -- authoring a custom sensor and authoring a
-- package command are the same act with the same blast radius, and
-- pretending otherwise by inventing a separate permission would imply a
-- distinction that does not exist.
CREATE TABLE IF NOT EXISTS custom_sensors (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',

    -- Per-OS command, same shape as a package: {"linux": "...", ...}. An OS
    -- with no entry simply never runs it, which is how a Windows-only
    -- sensor stays invisible to Linux hosts instead of failing on them.
    commands      JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- How often the endpoint runs it, and how long it may take. Both are
    -- per-sensor because a custom sensor is exactly where someone will
    -- write something far more expensive than the built-ins.
    interval_seconds INTEGER NOT NULL DEFAULT 900,
    timeout_seconds  INTEGER NOT NULL DEFAULT 30,

    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_custom_sensors_name ON custom_sensors (lower(name));

-- Console notifications: what the operator needs told, rather than what the
-- log happens to contain.
--
-- A deployment that half-failed at 3am is discoverable today only if someone
-- thinks to open Deployments and look. The audit log records it, but an
-- audit log is for answering questions afterwards, not for raising them --
-- nobody reads one hoping to be surprised.
--
-- Read state is per user, not per notification, because two operators
-- looking at the same fleet each need their own idea of what they have
-- seen; a shared "read" flag means whoever looks first silently clears it
-- for everybody else.
CREATE TABLE IF NOT EXISTS notifications (
    id         TEXT PRIMARY KEY,
    severity   TEXT NOT NULL DEFAULT 'info',   -- info | warning | critical
    title      TEXT NOT NULL,
    body       TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL DEFAULT '',       -- the module that raised it
    link       TEXT NOT NULL DEFAULT '',       -- where to go to act on it
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications (created_at DESC);

-- End-user notifications: messages shown to the person sitting at the
-- endpoint, as opposed to the operator watching the console.
--
-- These are two kinds, and the split earns its keep. A
-- *notice* tells someone something; a *restart* asks them to do something
-- disruptive and therefore has to negotiate -- a countdown, a deadline, and
-- a bounded set of postponements. Collapsing them into one "message with
-- optional buttons" produces a shape where every notice carries reboot
-- machinery it will never use.
CREATE TABLE IF NOT EXISTS eun_messages (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL DEFAULT 'notice',   -- notice | restart
    name        TEXT NOT NULL,
    title       TEXT NOT NULL,
    body        TEXT NOT NULL DEFAULT '',

    -- When the message stops being worth showing. A notice about Tuesday's
    -- maintenance is noise on Wednesday.
    deadline_at TIMESTAMPTZ,

    -- Restart-only. countdown_minutes is how long the person has once the
    -- final prompt appears; gentle_minutes is the softer warning shown
    -- before that, which is what stops a restart prompt being the first
    -- someone hears of it.
    allow_postpone   BOOLEAN NOT NULL DEFAULT true,
    countdown_minutes INTEGER NOT NULL DEFAULT 15,
    gentle_minutes    INTEGER NOT NULL DEFAULT 60,
    -- The postponement periods offered, in minutes. An array rather than
    -- a fixed set of columns, because "how many choices" is not a thing
    -- worth baking into the schema.
    postpone_minutes INTEGER[] NOT NULL DEFAULT '{60,240,480}',

    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT NOT NULL DEFAULT ''
);
-- Operator-defined buttons. Empty means the defaults for the kind, which is
-- what every message written before this column existed carries.
ALTER TABLE eun_messages ADD COLUMN IF NOT EXISTS buttons JSONB NOT NULL DEFAULT '[]';

CREATE INDEX IF NOT EXISTS idx_eun_messages_name ON eun_messages (lower(name));

CREATE TABLE IF NOT EXISTS notification_reads (
    notification_id TEXT NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    read_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (notification_id, user_id)
);

-- What a package is *for* is a real distinction and it earns its keep.
-- A software package installs, updates or removes something and is
-- verified by finding it installed afterwards; an action package just runs
-- a command and is never "installed" at all. mustra had only the first, so
-- a reboot had to masquerade as software -- which is why deploying one read
-- as "Install Reboot Computer", and why it needed a fake detection name to
-- avoid being reported as already present.
ALTER TABLE software_packages ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'software';
-- Adopting software from the fleet saved its package with an explicit
-- kind '', so the default above never applied (#119). Every path read ''
-- as software; say so.
UPDATE software_packages SET kind = 'software' WHERE kind = '';

-- command_timeout: how long this package's command may run before it is
-- killed. 0 means the agent's built-in default. It belongs on the
-- package because the right answer differs wildly -- flushing a DNS cache
-- should never take a minute, installing an office suite might take twenty.
ALTER TABLE software_packages ADD COLUMN IF NOT EXISTS command_timeout_seconds INTEGER NOT NULL DEFAULT 0;

-- expire_seconds: after this long, stop trying to deliver the
-- deployment. Without it a job aimed at a machine that is off stays
-- pending forever and eventually fires at a wildly inappropriate time.
-- 0 means it never expires.
ALTER TABLE software_packages ADD COLUMN IF NOT EXISTS expire_seconds INTEGER NOT NULL DEFAULT 0;

-- Parameterized packages: typed inputs substituted into the command at
-- deploy time, so "restart in N minutes" is one package rather
-- than one package per N.
-- [{"name":"delay","label":"Delay (seconds)","type":"numeric","default":"60",
--   "min":0,"max":86400,"required":true}]
ALTER TABLE software_packages ADD COLUMN IF NOT EXISTS parameters JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Carry the Self Service catalog into the package model, so a deployment
-- upgraded from before it keeps the items it published rather than
-- silently losing them. Each item is copied once (carried_to_packages,
-- above); after that the package is the only copy, and deleting it is
-- final.
INSERT INTO software_packages (id, name, description, category, icon, commands, detect, group_ids, self_service, allow_requests, enabled, source, created_by)
SELECT c.id, c.name, c.description, c.category, c.icon,
       (SELECT jsonb_object_agg(k, jsonb_build_object('install', v))
          FROM jsonb_each_text(c.packages) AS t(k, v)),
       jsonb_build_object('app_name', c.name, 'match', 'contains'),
       c.group_ids, true, c.allow_requests, c.enabled, 'manual', c.created_by
FROM catalog_items c
WHERE NOT c.carried_to_packages
  AND NOT EXISTS (SELECT 1 FROM software_packages p WHERE p.id = c.id)
  AND c.packages <> '{}'::jsonb;
UPDATE catalog_items SET carried_to_packages = true WHERE NOT carried_to_packages;

-- Someone asked for an item their machine isn't entitled to. Approving one
-- doesn't install anything by itself — it grants the entitlement, and the
-- person installs from Self Service when they're ready.
CREATE TABLE IF NOT EXISTS catalog_requests (
    id           TEXT PRIMARY KEY,
    item_id      TEXT NOT NULL REFERENCES catalog_items(id) ON DELETE CASCADE,
    agent_id     TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    requested_by TEXT NOT NULL DEFAULT '',   -- the local OS user who asked
    reason       TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'approved' | 'denied'
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at   TIMESTAMPTZ,
    decided_by   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_catalog_requests_status ON catalog_requests (status, requested_at DESC);

-- Everything mustra has done to a device, whoever started it: a patch job,
-- a Self Service install, an agent push. Self Service shows a machine its
-- own rows, which is what makes "what did IT just do to my laptop" an
-- answerable question rather than a mystery.
CREATE TABLE IF NOT EXISTS agent_actions (
    id           TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,              -- 'patch_apply' | 'catalog_install' | 'agent_deploy'
    summary      TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'started', -- 'started' | 'succeeded' | 'failed'
    detail       TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL DEFAULT '',
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_agent_actions_agent ON agent_actions (agent_id, started_at DESC);
-- Ties a per-device row to the deployment that caused it, so a deployment
-- can show exactly which machines it touched and how each one fared.
ALTER TABLE agent_actions ADD COLUMN IF NOT EXISTS run_id TEXT NOT NULL DEFAULT '';
-- A patch job's restart choice from the Apply dialog: '' (do not restart),
-- if_required or always, and how many minutes' warning the person gets.
-- Kept on the action so a job held for its maintenance window still
-- restarts the way it was asked to when it is finally dispatched.
ALTER TABLE agent_actions ADD COLUMN IF NOT EXISTS restart_mode TEXT NOT NULL DEFAULT '';
-- A patch job narrowed to some packages (a remediation from a threat
-- briefing); NULL applies everything pending. Kept on the action so a job
-- held for a maintenance window is narrowed the same way when it runs.
ALTER TABLE agent_actions ADD COLUMN IF NOT EXISTS patch_only JSONB;
ALTER TABLE agent_actions ADD COLUMN IF NOT EXISTS restart_warn_minutes INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_agent_actions_run ON agent_actions (run_id) WHERE run_id <> '';

-- One row per (agent, version) the moment that agent first reports it, so
-- "when did this box move to 0.3.0, and what was it running before" has an
-- answer. Only transitions are recorded, not every heartbeat: an agent that
-- reports the same version for a month contributes exactly one row.
CREATE TABLE IF NOT EXISTS agent_version_history (
    agent_id   TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    version    TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, version, first_seen)
);
CREATE INDEX IF NOT EXISTS idx_agent_version_history_agent ON agent_version_history (agent_id, first_seen DESC);

-- Computer groups: named, reusable slices of the fleet. A dynamic group is
-- a set of rules evaluated live against inventory and cached sensor data,
-- so membership is always current rather than a list someone has to
-- maintain. A static group is an explicit list of agent IDs, for the cases
-- where a rule can't express what you mean ("these four boxes, because I
-- said so"). `match` is how the rules combine: all (AND) or any (OR).
CREATE TABLE IF NOT EXISTS computer_groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL DEFAULT 'dynamic',   -- 'dynamic' | 'static'
    match_mode  TEXT NOT NULL DEFAULT 'all',       -- 'all' | 'any'
    rules       JSONB NOT NULL DEFAULT '[]'::jsonb,
    member_ids  TEXT[] NOT NULL DEFAULT '{}',      -- static groups only
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT NOT NULL DEFAULT ''
);

-- Every agent push the Deploy page has attempted, so "what did we deploy,
-- where, and did it work" survives the browser tab that started it. A row
-- is written when the push starts (status 'running') and updated when the
-- SSH session finishes; a row still 'running' long after started_at means
-- the server died mid-push, which is itself worth seeing.
CREATE TABLE IF NOT EXISTS agent_deployments (
    id            TEXT PRIMARY KEY,
    target        TEXT NOT NULL,              -- IP or hostname the push was aimed at
    hostname      TEXT NOT NULL DEFAULT '',   -- resolved name, when the scan found one
    site          TEXT NOT NULL DEFAULT '',
    credential    TEXT NOT NULL DEFAULT '',   -- the SSH username it authenticated as, never the secret
    status        TEXT NOT NULL DEFAULT 'running', -- 'running' | 'succeeded' | 'failed'
    error         TEXT NOT NULL DEFAULT '',
    output        TEXT NOT NULL DEFAULT '',
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at   TIMESTAMPTZ,
    started_by    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_agent_deployments_started ON agent_deployments (started_at DESC);

-- API tokens for programmatic access. Only a bcrypt hash is stored, so a
-- lost token can't be recovered from the database — it's shown once at
-- creation and never again. A token carries its own permission set (the
-- same fixed keys roles use) rather than impersonating a user's full
-- access, so a script that only needs to read inventory can hold a token
-- that can do nothing else. `prefix` is the token's first characters,
-- stored in the clear purely so the UI can show which token is which.
CREATE TABLE IF NOT EXISTS api_tokens (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    prefix       TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    permissions  TEXT[] NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by   TEXT NOT NULL DEFAULT '',
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked      BOOLEAN NOT NULL DEFAULT false
);

-- Every OIDC identity provider the console can sign in against. Replaces
-- the original single-IdP `oidc.*` settings rows (those are migrated into
-- this table on first boot after upgrading -- see migrateLegacyOIDCConfig).
-- `kind` only picks the login button's logo/wording; the protocol is plain
-- OIDC discovery regardless, so an IdP not on the list still works as
-- 'generic'. `id` is a URL slug: it appears in /login/sso/<id> and in the
-- provider's own redirect URI, /auth/callback/<id>.
CREATE TABLE IF NOT EXISTS oidc_providers (
    id            TEXT PRIMARY KEY,
    label         TEXT NOT NULL,
    kind          TEXT NOT NULL DEFAULT 'generic',
    issuer_url    TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    client_secret TEXT NOT NULL DEFAULT '',
    redirect_url  TEXT NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    sort_order    INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS agent_sensor_data (
    agent_id     TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    sensor       TEXT NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL,
    data         JSONB NOT NULL,
    PRIMARY KEY (agent_id, sensor)
);
-- Fleet-wide reads take one sensor kind across every endpoint (the Patches
-- page, dashboards, applicability, group matching). The primary key leads
-- with agent_id and cannot serve them, so each scanned every kind of every
-- endpoint: 75,000 rows at 5,000 endpoints, 137 ms where this takes 36.
CREATE INDEX IF NOT EXISTS idx_agent_sensor_data_sensor ON agent_sensor_data (sensor, agent_id);

-- Runtime-editable configuration (the admin Settings tab). Seeded from
-- env/flags on first boot (see server.go's settings-seed step), then the
-- database is authoritative — env vars only matter for the very first
-- startup or a from-scratch deploy. Secrets live here in plaintext
-- (OIDC client secret, SCIM token) or as a bcrypt hash (backdoor password) —
-- this table is never exposed outside the admin-only settings API, unlike
-- the SSH credential vault which is genuinely at-rest-encrypted because it
-- unlocks other hosts, not just this one.
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT NOT NULL DEFAULT ''
);

-- RBAC: roles carry a flat list of permission keys (see
-- internal/server/auth/permissions.go for the fixed set); a user's
-- effective permissions are the union of their directly-assigned roles and
-- the roles assigned to any group they belong to. "admin" and "user" are
-- builtin (is_builtin, undeletable/unrenamable) and reseeded with the
-- current full permission set on every startup so an admin can't
-- accidentally lock themselves out by editing the builtin admin role.
-- users.is_admin (legacy, predates this table) remains a fast-path
-- super-admin flag independent of role assignment — it's what makes the
-- backdoor account always fully privileged without needing a seeded role
-- assignment row.
CREATE TABLE IF NOT EXISTS roles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    permissions TEXT[] NOT NULL DEFAULT '{}',
    is_builtin  BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS group_roles (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id  TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, role_id)
);

-- Scheduled/recurring patch deployment jobs (the Patches tab's "schedule a
-- deployment" feature). A schedule targets a slice of the fleet (all
-- agents, one OS, one site, or a single agent — exactly one of
-- target_os/target_site/target_agent is set, or all empty meaning "every
-- agent") and either fires once (kind='once', run_at set, disabled after
-- it fires) or on a recurring cadence (kind='daily'/'weekly', evaluated
-- against time_of_day/weekday in UTC — see patchSchedulerLoop). next_run_at
-- is precomputed so the scheduler's poll is a cheap indexed lookup rather
-- than recomputing every schedule's next occurrence every tick.
CREATE TABLE IF NOT EXISTS patch_schedules (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    target_os     TEXT NOT NULL DEFAULT '',
    target_site   TEXT NOT NULL DEFAULT '',
    target_agent  TEXT NOT NULL DEFAULT '',
    -- target_vuln_id is added below via ALTER (this table shipped before
    -- it existed) -- see the comment near that statement for semantics.
    kind          TEXT NOT NULL,              -- 'once' | 'daily' | 'weekly'
    run_at        TIMESTAMPTZ,                -- 'once' only
    time_of_day   TEXT NOT NULL DEFAULT '',   -- 'HH:MM' UTC, 'daily'/'weekly' only
    weekday       INTEGER,                    -- 0 (Sunday) - 6, 'weekly' only
    enabled       BOOLEAN NOT NULL DEFAULT true,
    last_run_at   TIMESTAMPTZ,
    next_run_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_patch_schedules_next_run ON patch_schedules (next_run_at) WHERE enabled;

-- Added after patch_schedules already shipped: lets a schedule target
-- "whichever agents currently carry this CVE" (Risk & Compliance's
-- "Schedule…" button) instead of a fixed os/site/agent. Kept as an ALTER
-- rather than folded into the CREATE so an existing database still gets
-- the column, but placed after the table so a new one does too.
ALTER TABLE patch_schedules ADD COLUMN IF NOT EXISTS target_vuln_id TEXT NOT NULL DEFAULT '';

-- Also added later: a schedule frozen to a named set of endpoints, which is
-- what "Specific endpoints" in Deploy & Schedule creates. Empty means the
-- os/site/agent/vuln target above decides, exactly as before.
ALTER TABLE patch_schedules ADD COLUMN IF NOT EXISTS target_agents TEXT[] NOT NULL DEFAULT '{}';

-- History of every patch deployment fired, scheduled or ad-hoc ("Deploy
-- now"), for the Patches tab's recent-activity view.
CREATE TABLE IF NOT EXISTS patch_job_runs (
    id            TEXT PRIMARY KEY,
    schedule_id   TEXT REFERENCES patch_schedules(id) ON DELETE SET NULL,
    schedule_name TEXT NOT NULL DEFAULT '',  -- denormalized: survives the schedule being edited/deleted later
    target_desc   TEXT NOT NULL,
    agent_count   INTEGER NOT NULL DEFAULT 0,
    triggered_by  TEXT NOT NULL DEFAULT '',  -- username, or 'scheduler'
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_patch_job_runs_started_at ON patch_job_runs (started_at DESC);
-- "Notify me when it finishes": the run raises one notification when its
-- last job reaches a final state; notified_at makes that exactly once.
ALTER TABLE patch_job_runs ADD COLUMN IF NOT EXISTS notify_on_finish BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE patch_job_runs ADD COLUMN IF NOT EXISTS notified_at TIMESTAMPTZ;

-- Real vulnerability data (the Risk & Compliance feature): a background
-- job cross-references each agent's cached installed_apps sensor snapshot
-- against OSV.dev (osv.dev — free, keyless, no data source to "obtain",
-- see docs/ARCHITECTURE.md's Risk section for why). One row per
-- (agent, package, vulnerability) match currently known; the whole set for
-- a scanned agent is replaced on every scan, so a fixed package's row just
-- stops existing rather than needing a "resolved" flag.
CREATE TABLE IF NOT EXISTS agent_vulnerabilities (
    agent_id        TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    package_name    TEXT NOT NULL,
    package_version TEXT NOT NULL,
    vuln_id         TEXT NOT NULL,              -- OSV's own ID (often a GHSA-...; see cve_ids for the CVE alias)
    severity        TEXT NOT NULL DEFAULT '',   -- 'critical' | 'high' | 'medium' | 'low' | '' (unknown)
    checked_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, package_name, vuln_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_vulnerabilities_agent ON agent_vulnerabilities (agent_id);

-- Full vulnerability details (severity/summary/CVE aliases), fetched from
-- OSV once per vuln ID and cached indefinitely — a CVE's severity/summary
-- doesn't change after publication, and this is what lets a vulnerability
-- shared across many hosts/packages cost one OSV detail lookup instead of
-- one per match.
CREATE TABLE IF NOT EXISTS vuln_details_cache (
    vuln_id        TEXT PRIMARY KEY,
    severity       TEXT NOT NULL DEFAULT '',
    cvss_score     REAL,
    summary        TEXT NOT NULL DEFAULT '',
    cve_ids        TEXT[] NOT NULL DEFAULT '{}',
    -- fixed_versions is added below via ALTER (this table shipped before
    -- it existed) -- see the comment near that statement for semantics.
    fetched_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Added after vuln_details_cache already shipped: per-package fixed
-- version(s) from OSV's advisory data, for the Risk page's remediation
-- text. An ALTER so an existing database gains the column, placed after
-- the CREATE so a new database does too.
ALTER TABLE vuln_details_cache ADD COLUMN IF NOT EXISTS fixed_versions JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Ubuntu's own priority for an UBUNTU-CVE advisory, which grades Ubuntu
-- hosts' findings in place of CVSS ('' when the record has none). NULL
-- for details cached before this column: the scan fetches those again
-- when an Ubuntu host needs them.
ALTER TABLE vuln_details_cache ADD COLUMN IF NOT EXISTS ubuntu_priority TEXT;

-- Scan Management (Patches tab): named, reusable repo definitions an agent
-- scopes its patch scan/apply to instead of whatever's natively configured
-- on the host. os_family picks which package manager this list applies to
-- ('apt' or 'dnf'); repos is newline-separated -- full sources.list-style
-- lines for apt, bare repo IDs (already configured on the host, just
-- restricted to these) for dnf. No row here for a host means "use the
-- official/native repo config" (today's default behavior), unchanged.
CREATE TABLE IF NOT EXISTS patch_lists (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    os_family   TEXT NOT NULL,             -- 'apt' | 'dnf'
    repos       TEXT NOT NULL DEFAULT '',  -- newline-separated
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT NOT NULL DEFAULT ''
);

-- Which hosts use which patch list -- a many-to-one set of targeting rules
-- so one reusable patch list can be assigned to several different slices of
-- the fleet. target_platform matches the agent's actual distro flavor (e.g.
-- "debian", "ubuntu", "rhel" -- store.AgentRecord.Platform, NOT the coarse
-- runtime.GOOS "linux" that target_os means elsewhere in this schema).
-- A rule naming an agent applies to it whatever else it names; otherwise
-- its site and platform, where set, must both match. Resolution order when
-- more than one rule matches: agent-specific, then site and platform, then
-- site, then platform -- see ResolvePatchListForAgent.
CREATE TABLE IF NOT EXISTS patch_list_assignments (
    id             TEXT PRIMARY KEY,
    patch_list_id  TEXT NOT NULL REFERENCES patch_lists(id) ON DELETE CASCADE,
    target_platform TEXT NOT NULL DEFAULT '',
    target_site    TEXT NOT NULL DEFAULT '',
    target_agent   TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_patch_list_assignments_list ON patch_list_assignments (patch_list_id);

-- A saved question is one worth asking again; question history is every
-- question anyone asked, which doubles as the audit log for who looked at
-- what. Both are cheap and small — a question is a few fields and a filter,
-- never a result set.
CREATE TABLE IF NOT EXISTS saved_questions (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    get_fields  TEXT[] NOT NULL DEFAULT '{}',
    where_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
    match_all   BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS question_history (
    id       TEXT PRIMARY KEY,
    text     TEXT NOT NULL,
    asked_by TEXT NOT NULL DEFAULT '',
    asked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    matched  INTEGER NOT NULL DEFAULT 0,
    total    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_question_history_time ON question_history (asked_at DESC);

-- A standing export: this source, in this format, to this destination, on
-- this interval. History sources keep a cursor so a run sends what is new
-- rather than everything again, and the last error lives on the row so a
-- destination that has been failing all week is visible in the list rather
-- than buried in the server log.
CREATE TABLE IF NOT EXISTS export_configs (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    source            TEXT NOT NULL,
    saved_question_id TEXT NOT NULL DEFAULT '',
    format            TEXT NOT NULL DEFAULT 'json',
    destination       TEXT NOT NULL,
    target            TEXT NOT NULL DEFAULT '',
    webhook_style     TEXT NOT NULL DEFAULT '',
    headers           JSONB NOT NULL DEFAULT '{}'::jsonb,
    interval_minutes  INTEGER NOT NULL DEFAULT 0,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    cursor            TEXT NOT NULL DEFAULT '',
    last_run_at       TIMESTAMPTZ,
    last_row_count    INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by        TEXT NOT NULL DEFAULT ''
);

-- One detected difference between consecutive snapshots of a watched file.
-- Detection happens on the server rather than the endpoint on purpose: an
-- attacker who can rewrite /etc/sudoers can also rewrite a baseline file
-- sitting beside it, so the comparison is made somewhere they cannot reach.
CREATE TABLE IF NOT EXISTS integrity_changes (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    path        TEXT NOT NULL,
    kind        TEXT NOT NULL,             -- added | removed | modified
    what        TEXT NOT NULL DEFAULT '',  -- contents | permissions | ownership | ...
    was         TEXT NOT NULL DEFAULT '',
    now_value   TEXT NOT NULL DEFAULT '',
    -- Change mustra itself caused, during a deployment it ran. Labelled
    -- rather than dropped: the record stays complete, the list stays
    -- readable, and without this every patch run buries the real findings.
    expected    BOOLEAN NOT NULL DEFAULT false,
    because     TEXT NOT NULL DEFAULT '',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_integrity_changes_time ON integrity_changes (detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_integrity_changes_agent ON integrity_changes (agent_id, detected_at DESC);

-- How much an endpoint matters, which scales its risk score.
CREATE TABLE IF NOT EXISTS agent_criticality (
    agent_id   TEXT PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    level      TEXT NOT NULL DEFAULT 'medium',  -- low | medium | high | critical
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The distribution's own judgement on a finding. Debian backports security
-- fixes without changing the upstream version, so OSV keeps matching CVEs a
-- host already has the fix for; on a real fleet that buried the actionable
-- findings under several hundred that were not. Kept rather than deleted so
-- the judgement stays auditable, but excluded from counts.
ALTER TABLE agent_vulnerabilities ADD COLUMN IF NOT EXISTS suppressed BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE agent_vulnerabilities ADD COLUMN IF NOT EXISTS suppressed_reason TEXT NOT NULL DEFAULT '';

-- A staged rollout. Custom plans target computer groups in order (ring 1 is
-- what you can afford to break); dynamic plans take random percentages,
-- re-drawn per deployment, which is what catches a problem that only shows
-- up on some hardware.
CREATE TABLE IF NOT EXISTS deployment_plans (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL DEFAULT 'custom',   -- custom | dynamic
    rings      JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL DEFAULT ''
);

-- Live shell sessions, and every command run in them.
--
-- A remote root shell across a fleet has to be accountable to be
-- defensible. The command row is written *before* the command runs and
-- filled in afterwards, so a command that hangs or kills the agent still
-- leaves a record of having been issued — which is exactly the one anybody
-- investigating would want to find.
CREATE TABLE IF NOT EXISTS shell_sessions (
    id          TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    opened_by   TEXT NOT NULL DEFAULT '',
    opened_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at   TIMESTAMPTZ,
    working_dir TEXT NOT NULL DEFAULT '/'
);
CREATE INDEX IF NOT EXISTS idx_shell_sessions_time ON shell_sessions (opened_at DESC);

CREATE TABLE IF NOT EXISTS shell_commands (
    id         BIGSERIAL PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES shell_sessions(id) ON DELETE CASCADE,
    agent_id   TEXT NOT NULL,
    ran_by     TEXT NOT NULL DEFAULT '',
    command    TEXT NOT NULL,
    output     TEXT NOT NULL DEFAULT '',
    exit_code  INTEGER NOT NULL DEFAULT 0,
    ran_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_shell_commands_session ON shell_commands (session_id, ran_at DESC);
CREATE INDEX IF NOT EXISTS idx_shell_commands_time ON shell_commands (ran_at DESC);

-- Compliance policies and their results.
--
-- Results are stored per (endpoint, check) rather than as a score: a score
-- is derivable from results and results are not derivable from a score, and
-- the question people ask is "which machines fail this", not "what is our
-- number". "unknown" is a real state — a check whose rules could not be
-- evaluated must never be recorded as a pass.
CREATE TABLE IF NOT EXISTS compliance_policies (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    os         TEXT NOT NULL DEFAULT 'linux',
    source     TEXT NOT NULL DEFAULT 'builtin',   -- builtin | imported
    checks     JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS compliance_results (
    agent_id   TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    policy_id  TEXT NOT NULL,
    check_id   TEXT NOT NULL,
    title      TEXT NOT NULL DEFAULT '',
    severity   TEXT NOT NULL DEFAULT '',
    state      TEXT NOT NULL DEFAULT 'unknown',
    detail     TEXT NOT NULL DEFAULT '',
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, policy_id, check_id)
);
CREATE INDEX IF NOT EXISTS idx_compliance_results_state ON compliance_results (state, severity);

-- The audit spine: every significant action, in one uniform shape.
--
-- mustra already records actions in six module tables (deployments, shell
-- commands, question history, integrity changes, catalog requests, agent
-- actions). Each is right for its own module and none answers the question
-- asked after something goes wrong, which spans all of them. Writing here
-- as well is deliberate duplication: the module tables carry structure this
-- cannot, and this carries uniformity they cannot.
--
-- agent_id is nullable and NOT a foreign key on purpose. An audit record
-- must outlive the endpoint it refers to — the moment a machine is
-- decommissioned is exactly when its history matters most, and a cascade
-- delete would erase it.
CREATE TABLE IF NOT EXISTS audit_events (
    id       BIGSERIAL PRIMARY KEY,
    at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    action   TEXT NOT NULL,
    actor    TEXT NOT NULL DEFAULT '',
    target   TEXT NOT NULL DEFAULT '',
    agent_id TEXT,
    outcome  TEXT NOT NULL DEFAULT 'ok',
    severity TEXT NOT NULL DEFAULT 'info',
    detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_events_at ON audit_events (at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events (action, at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events (actor, at DESC);

-- Enforce: desired state.
--
-- A policy is a set of settings that must be true, each carrying the
-- command that makes it true again. Settings live as JSON on the policy for
-- the same reason compliance checks do: they are authored and edited as a
-- unit, and a row per setting would buy nothing but joins.
--
-- mode is the safety switch and it defaults to 'report'. An enforcement
-- engine changes machines on a timer with nobody watching, so a policy that
-- silently began doing that the moment it was saved would be a trap. You
-- write it, watch what it *would* do, and then turn it on.
CREATE TABLE IF NOT EXISTS enforce_policies (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    -- '' means any platform; otherwise the agent OS this applies to.
    os          TEXT NOT NULL DEFAULT '',
    -- NULL means the whole fleet, which is why losing a group cannot be
    -- allowed to look the same as never having had one: SET NULL alone
    -- would turn "these twelve servers" into "all thirty-nine" the moment
    -- somebody tidied up a group. See group_deleted below.
    group_id    TEXT REFERENCES computer_groups(id) ON DELETE SET NULL,
    mode        TEXT NOT NULL DEFAULT 'report',   -- report | enforce
    enabled     BOOLEAN NOT NULL DEFAULT true,
    settings    JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  TEXT NOT NULL DEFAULT '',
    last_run_at TIMESTAMPTZ
);

-- One setting's standing on one endpoint.
--
-- consecutive_failures is the load-bearing column. A remediation that has
-- failed three times in a row will fail a fourth, and without a counter it
-- would keep running every half hour on every affected endpoint forever —
-- an engine that generates load and log noise in exact proportion to how
-- broken it is. Past the ceiling the server stops sending it as enforceable
-- and the state becomes 'failing', which reads as "mustra has given up on
-- this until somebody changes something".
CREATE TABLE IF NOT EXISTS enforce_results (
    agent_id             TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    policy_id            TEXT NOT NULL REFERENCES enforce_policies(id) ON DELETE CASCADE,
    setting_id           TEXT NOT NULL,
    name                 TEXT NOT NULL DEFAULT '',
    severity             TEXT NOT NULL DEFAULT '',
    -- compliant | drifted | remediated | failed | failing | unknown
    state                TEXT NOT NULL DEFAULT 'unknown',
    detail               TEXT NOT NULL DEFAULT '',
    output               TEXT NOT NULL DEFAULT '',
    consecutive_failures INT NOT NULL DEFAULT 0,
    remediation_count    INT NOT NULL DEFAULT 0,
    checked_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_remediated_at   TIMESTAMPTZ,
    PRIMARY KEY (agent_id, policy_id, setting_id)
);
CREATE INDEX IF NOT EXISTS idx_enforce_results_state ON enforce_results (policy_id, state);

-- Playbooks: multi-step flows.
--
-- "Patch, wait for the reboot, verify, tell the person" is four things
-- mustra could already do and one thing it could not: do them in order, on
-- each endpoint, deciding at each step whether the next one still makes
-- sense. That last part is why a playbook is not a list of buttons.
--
-- Steps live as JSON on the playbook because they are authored and edited
-- as one thing, and because a step's fields differ wildly by kind — a row
-- per step would be a table of mostly-null columns.
--
-- The schedule columns mirror patch_schedules deliberately: same kinds,
-- same UTC HH:MM, same weekday convention, so computeNextRun serves both
-- and "daily at 03:00" cannot come to mean two different times.
CREATE TABLE IF NOT EXISTS playbooks (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    os          TEXT NOT NULL DEFAULT '',
    group_id    TEXT REFERENCES computer_groups(id) ON DELETE SET NULL,
    steps       JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    -- '' | once | daily | weekly
    schedule_kind TEXT NOT NULL DEFAULT '',
    time_of_day   TEXT NOT NULL DEFAULT '',
    weekday       INT,
    next_run_at   TIMESTAMPTZ,
    last_run_at   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_playbooks_due ON playbooks (next_run_at) WHERE enabled;

-- One execution of a playbook across its targets.
--
-- The playbook's name and step list are copied in rather than referenced.
-- A run is history, and history that rewrites itself when somebody edits
-- the playbook afterwards is not history — the whole point of opening a run
-- from three weeks ago is to see what it actually did.
CREATE TABLE IF NOT EXISTS playbook_runs (
    id           TEXT PRIMARY KEY,
    playbook_id  TEXT,
    name         TEXT NOT NULL DEFAULT '',
    steps        JSONB NOT NULL DEFAULT '[]'::jsonb,
    target_desc  TEXT NOT NULL DEFAULT '',
    agent_count  INT NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'running',  -- running | succeeded | partial | failed
    triggered_by TEXT NOT NULL DEFAULT '',
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_playbook_runs_started ON playbook_runs (started_at DESC);

-- One step's outcome on one endpoint.
--
-- Written as each step finishes rather than at the end of the run, because
-- the interesting moment for a flow like this is while it is still going:
-- an operator watching a rolling reboot wants to see endpoint seven reach
-- "waiting for it to come back" now, not in twenty minutes.
CREATE TABLE IF NOT EXISTS playbook_step_results (
    run_id      TEXT NOT NULL REFERENCES playbook_runs(id) ON DELETE CASCADE,
    agent_id    TEXT NOT NULL,
    hostname    TEXT NOT NULL DEFAULT '',
    step_index  INT NOT NULL,
    step_name   TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL DEFAULT '',
    -- running | succeeded | failed | skipped
    status      TEXT NOT NULL DEFAULT 'running',
    detail      TEXT NOT NULL DEFAULT '',
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    PRIMARY KEY (run_id, agent_id, step_index)
);

-- Reports: a document somebody who never opens the console can read.
--
-- Everything in mustra is already exportable, which is not the same thing.
-- An export is a stream of rows for a machine; a report is a page for a
-- person — sections with titles, counts rolled up, and a date on it.
--
-- Sections are JSON for the same reason steps and settings are: they are
-- authored as one thing, and their fields differ by source.
CREATE TABLE IF NOT EXISTS reports (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    sections    JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled     BOOLEAN NOT NULL DEFAULT true,

    -- Same schedule vocabulary as patch_schedules and playbooks, so
    -- "daily at 03:00" means one thing across the whole product.
    schedule_kind TEXT NOT NULL DEFAULT '',
    time_of_day   TEXT NOT NULL DEFAULT '',
    weekday       INT,
    next_run_at   TIMESTAMPTZ,
    last_run_at   TIMESTAMPTZ,
    last_error    TEXT NOT NULL DEFAULT '',

    -- Delivery reuses Connect's destinations. '' means the report is only
    -- ever read in the console.
    destination   TEXT NOT NULL DEFAULT '',   -- '' | webhook | file | syslog
    target        TEXT NOT NULL DEFAULT '',
    webhook_style TEXT NOT NULL DEFAULT '',   -- '' | discord | slack

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_reports_due ON reports (next_run_at) WHERE enabled;

-- One rendering, kept.
--
-- The rendered document is stored rather than regenerated on demand,
-- because the point of a recurring report is to be able to say what the
-- fleet looked like on the first of the month. Re-running today's query
-- against today's data answers a different question.
CREATE TABLE IF NOT EXISTS report_runs (
    id           TEXT PRIMARY KEY,
    -- Cascades: unlike a playbook run, a rendering is only meaningful as
    -- an instance of its report. Keeping documents whose definition is
    -- gone would leave rows nobody can re-run, re-read in context, or
    -- prune.
    report_id    TEXT REFERENCES reports(id) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT '',
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    generated_by TEXT NOT NULL DEFAULT '',
    section_count INT NOT NULL DEFAULT 0,
    row_count    INT NOT NULL DEFAULT 0,
    html         TEXT NOT NULL DEFAULT '',
    summary      TEXT NOT NULL DEFAULT '',
    delivered    BOOLEAN NOT NULL DEFAULT false,
    error        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_report_runs_report ON report_runs (report_id, generated_at DESC);

-- Real-time file events.
--
-- The companion to integrity_files' hash baseline: that table answers "has
-- this changed since last time", these rows answer "it changed at 03:14:07
-- and it was a create". Kept for a fortnight rather than forever — the
-- value of an event decays fast, and a table that only grows is one that
-- eventually has to be truncated in a hurry by somebody at 2am.
--
-- count is only meaningful on a 'suppressed' row, which is how a burst is
-- reported: past the agent's per-flush cap the events are counted instead
-- of sent, and saying "412 more" is honest where silence would make the
-- console claim a quiet minute.
CREATE TABLE IF NOT EXISTS file_events (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    path        TEXT NOT NULL DEFAULT '',
    op          TEXT NOT NULL,   -- create | write | remove | rename | chmod | suppressed
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    count       INT NOT NULL DEFAULT 1,
    -- The indicator this matched the moment it happened, if any. Real-time
    -- detection is exactly this column being non-empty before the next
    -- fifteen-minute hunt would have found it.
    matched_ioc TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_file_events_at ON file_events (at DESC);
CREATE INDEX IF NOT EXISTS idx_file_events_agent ON file_events (agent_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_file_events_matched ON file_events (matched_ioc, at DESC) WHERE matched_ioc <> '';

-- Real-time process events.
--
-- The companion to the processes sensor's snapshot: that answers "what is
-- running", these answer "what ran". Kept a week rather than the fortnight
-- file events get — a busy endpoint produces far more of these, and the
-- forensic question they answer ("what ran on this box the night it
-- started misbehaving") is usually asked within days.
--
-- source records the mechanism, because it decides what an empty feed
-- proves: 'netlink' sees every exec, 'poll' sees what was alive at a sample
-- point and nothing shorter-lived than the interval.
CREATE TABLE IF NOT EXISTS process_events (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    pid         INT NOT NULL DEFAULT 0,
    ppid        INT NOT NULL DEFAULT 0,
    name        TEXT NOT NULL DEFAULT '',
    cmdline     TEXT NOT NULL DEFAULT '',
    username    TEXT NOT NULL DEFAULT '',
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    source      TEXT NOT NULL DEFAULT '',
    -- A 'suppressed' or 'unidentified' row carries a count and no process.
    kind        TEXT NOT NULL DEFAULT 'start',  -- start | suppressed | unidentified
    count       INT NOT NULL DEFAULT 1,
    matched_ioc TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_process_events_at ON process_events (at DESC);
CREATE INDEX IF NOT EXISTS idx_process_events_agent ON process_events (agent_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_process_events_matched ON process_events (matched_ioc, at DESC) WHERE matched_ioc <> '';

-- Merging the timeline to the minute.
--
-- The agent collapses identical invocations inside its five-second flush,
-- which is as far as it can go without delaying detection. A command that
-- runs once a second still arrives as twelve rows a minute — measured on
-- this fleet, 2743 execs a minute became 1293 stored rows, which is better
-- and still far too many to keep.
--
-- So the server merges again, into minute buckets. It costs nothing in
-- detection latency: indicator matching happens in memory when the batch
-- arrives, before any of this. And it applies only to rows that matched
-- nothing — a start that matched an indicator is evidence, keeps its exact
-- timestamp, and is never folded into a count.
ALTER TABLE process_events ADD COLUMN IF NOT EXISTS bucket TIMESTAMPTZ;
ALTER TABLE process_events ADD COLUMN IF NOT EXISTS dedupe_key TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS uq_process_events_bucket
    ON process_events (agent_id, bucket, dedupe_key)
    WHERE kind = 'start' AND matched_ioc = '';

-- Targeting that lost its group.
--
-- enforce_policies and playbooks both mean "the whole fleet" by a NULL
-- group_id, so a deleted group would otherwise widen them from a handful of
-- machines to every one — silently, at the next scheduled run, with
-- remediation commands or a reboot step attached. The flag makes the two
-- cases distinguishable: a policy that never had a group still targets
-- everything, and one that lost its group targets nothing until somebody
-- chooses again.
--
-- Set when the group is deleted, alongside disabling the policy. Cleared
-- only by saving new targeting, which forces the choice to be made by a
-- person rather than inherited from a deletion.
ALTER TABLE enforce_policies ADD COLUMN IF NOT EXISTS group_deleted BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS group_deleted BOOLEAN NOT NULL DEFAULT false;

-- A preview is not history.
--
-- report_runs prunes to the newest thirty per report, and a preview was
-- stored like any other rendering — so thirty clicks of Preview evicted
-- every archived scheduled run, which is precisely the record the feature
-- exists to keep. Previews are kept too (the console shows the one you just
-- rendered) but they are pruned on their own, much shallower, shelf.
ALTER TABLE report_runs ADD COLUMN IF NOT EXISTS preview BOOLEAN NOT NULL DEFAULT false;

-- Re-point catalog requests at the package model.
--
-- Self Service requests are keyed by the id of the thing being asked for,
-- and that is now a software_packages row — but this column's foreign key
-- still named the superseded catalog_items table. So requesting anything
-- created through /api/software (a 'sw-' id, which never appears in
-- catalog_items) raised a foreign-key violation that reached the person as
-- a raw driver error instead of "request sent". Only the handful of ids the
-- backfill above copied into both tables could be requested at all, and
-- those were then listed through a join on the wrong table.
DELETE FROM catalog_requests r
 WHERE NOT EXISTS (SELECT 1 FROM software_packages p WHERE p.id = r.item_id);
ALTER TABLE catalog_requests DROP CONSTRAINT IF EXISTS catalog_requests_item_id_fkey;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'catalog_requests_item_id_package_fkey'
  ) THEN
    ALTER TABLE catalog_requests
      ADD CONSTRAINT catalog_requests_item_id_package_fkey
      FOREIGN KEY (item_id) REFERENCES software_packages(id) ON DELETE CASCADE;
  END IF;
END $$;

-- Custom collection configuration is additive for independently upgraded agents.
ALTER TABLE custom_sensors ADD COLUMN IF NOT EXISTS platforms JSONB NOT NULL DEFAULT '{}';
ALTER TABLE custom_sensors ADD COLUMN IF NOT EXISTS fields JSONB NOT NULL DEFAULT '[]';
ALTER TABLE custom_sensors ADD COLUMN IF NOT EXISTS max_age_seconds INTEGER NOT NULL DEFAULT 0;
ALTER TABLE saved_questions ADD COLUMN IF NOT EXISTS record_sensor TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS custom_sensor_success (
 agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
 sensor TEXT NOT NULL, collected_at TIMESTAMPTZ NOT NULL, data JSONB NOT NULL,
 PRIMARY KEY(agent_id,sensor)
);
CREATE TABLE IF NOT EXISTS custom_sensor_capabilities (
 agent_id TEXT PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
 version INTEGER NOT NULL
);

-- Deploy revisions remain available after publication so a scheduled run never
-- changes under an operator because its catalog entry was edited.
-- A package that must never be fired at "every online endpoint". Set on
-- anything whose effect cannot be undone by running it again -- removing the
-- agent, most obviously, which also removes the means of putting it back.
ALTER TABLE software_packages ADD COLUMN IF NOT EXISTS require_explicit_targets BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE software_packages ADD COLUMN IF NOT EXISTS deploy_revision TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS deploy_revisions (
 id TEXT PRIMARY KEY,
 package_id TEXT NOT NULL REFERENCES software_packages(id) ON DELETE RESTRICT,
 label TEXT NOT NULL,
 definition JSONB NOT NULL,
 published BOOLEAN NOT NULL DEFAULT false,
 created_by TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS deploy_revisions_package ON deploy_revisions(package_id, created_at DESC);
CREATE TABLE IF NOT EXISTS deploy_jobs (
 id TEXT PRIMARY KEY,
 run_id TEXT NOT NULL,
 agent_id TEXT NOT NULL,
 package_id TEXT NOT NULL,
 revision_id TEXT NOT NULL REFERENCES deploy_revisions(id),
 job JSONB NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued',
 detail TEXT NOT NULL DEFAULT '',
 cancel_requested BOOLEAN NOT NULL DEFAULT false,
 force_cancel BOOLEAN NOT NULL DEFAULT false,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS deploy_jobs_active ON deploy_jobs(status, updated_at);
CREATE INDEX IF NOT EXISTS deploy_jobs_run ON deploy_jobs(run_id, agent_id);
CREATE TABLE IF NOT EXISTS deploy_installations (
 agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
 package_id TEXT NOT NULL,
 revision_id TEXT NOT NULL,
 dependencies TEXT[] NOT NULL DEFAULT '{}',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(agent_id,package_id)
);
ALTER TABLE custom_sensors ADD COLUMN IF NOT EXISTS parameters JSONB NOT NULL DEFAULT '[]';
ALTER TABLE scheduled_actions ADD COLUMN IF NOT EXISTS revision_id TEXT NOT NULL DEFAULT '';
ALTER TABLE scheduled_actions ADD COLUMN IF NOT EXISTS follow_latest BOOLEAN NOT NULL DEFAULT false;
-- A schedule made from the Deploy window: hand-picked endpoints and computer
-- groups (resolved each time it fires), the deployment options a manual run
-- takes, and who to tell. Empty targets keep the older OS/site/agent filters.
ALTER TABLE scheduled_actions ADD COLUMN IF NOT EXISTS agent_ids TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE scheduled_actions ADD COLUMN IF NOT EXISTS group_ids TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE scheduled_actions ADD COLUMN IF NOT EXISTS allow_reboot BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE scheduled_actions ADD COLUMN IF NOT EXISTS force_remove BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE scheduled_actions ADD COLUMN IF NOT EXISTS expire_seconds INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scheduled_actions ADD COLUMN IF NOT EXISTS override_windows BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE scheduled_actions ADD COLUMN IF NOT EXISTS notify_message_id TEXT NOT NULL DEFAULT '';
ALTER TABLE scheduled_actions ADD COLUMN IF NOT EXISTS notify_on_finish BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE software_packages ADD COLUMN IF NOT EXISTS self_service_revision TEXT NOT NULL DEFAULT '';
ALTER TABLE software_packages ADD COLUMN IF NOT EXISTS self_service_follow_latest BOOLEAN NOT NULL DEFAULT false;
-- Where a software package's version comes from when it follows an
-- upstream project ("github:owner/repo", internal/server/software_follow.go);
-- empty means the version is typed in by hand.
ALTER TABLE software_packages ADD COLUMN IF NOT EXISTS version_source TEXT NOT NULL DEFAULT '';

-- Outcome history must not prevent ordinary endpoint pruning.
ALTER TABLE deploy_jobs DROP CONSTRAINT IF EXISTS deploy_jobs_agent_id_fkey;

-- Retirement preserves immutable definitions and files used by historical runs.
ALTER TABLE deploy_revisions ADD COLUMN IF NOT EXISTS retired boolean NOT NULL DEFAULT false;

-- Directory: the users, groups and computers of a domain, as last synced,
-- and who is a member of what. Impact joins this to each endpoint's
-- local_admins sensor to say who can reach what. Replaced wholesale on every
-- sync -- it is a cache of the directory, not a history of it.
CREATE TABLE IF NOT EXISTS directory_objects (
    sid               TEXT PRIMARY KEY,
    kind              TEXT NOT NULL,                 -- user | group | computer
    name              TEXT NOT NULL,                 -- sAMAccountName, computers without the trailing $
    display_name      TEXT NOT NULL DEFAULT '',
    dn                TEXT NOT NULL DEFAULT '',
    domain            TEXT NOT NULL DEFAULT '',      -- the NetBIOS name, as local_admins reports it
    enabled           BOOLEAN NOT NULL DEFAULT true,
    admin_count       BOOLEAN NOT NULL DEFAULT false, -- AD's adminCount: protected, i.e. privileged
    domain_controller BOOLEAN NOT NULL DEFAULT false,
    dns_host_name     TEXT NOT NULL DEFAULT '',
    operating_system  TEXT NOT NULL DEFAULT '',
    description       TEXT NOT NULL DEFAULT '',
    last_logon        TIMESTAMPTZ,
    synced_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS directory_objects_kind ON directory_objects(kind, name);
CREATE TABLE IF NOT EXISTS directory_members (
    group_sid  TEXT NOT NULL REFERENCES directory_objects(sid) ON DELETE CASCADE,
    member_sid TEXT NOT NULL,
    PRIMARY KEY (group_sid, member_sid)
);
CREATE INDEX IF NOT EXISTS directory_members_member ON directory_members(member_sid);

-- Reveal: sensitive-data rules, the scan each endpoint last ran for them,
-- and what matched. Matches are replaced per (rule, endpoint) on every
-- report -- a rescan is the whole truth about that endpoint -- but keep a
-- first_seen so a finding's age is known.
CREATE TABLE IF NOT EXISTS reveal_rules (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    description          TEXT NOT NULL DEFAULT '',
    kind                 TEXT NOT NULL DEFAULT 'rule',      -- rule | quick
    enabled              BOOLEAN NOT NULL DEFAULT true,
    group_ids            TEXT[] NOT NULL DEFAULT '{}',      -- empty = every endpoint
    roots                JSONB NOT NULL DEFAULT '{}',       -- {"windows":[...],"linux":[...],"darwin":[...]}
    exclude              TEXT[] NOT NULL DEFAULT '{}',
    extensions           TEXT[] NOT NULL DEFAULT '{}',
    max_size_bytes       BIGINT NOT NULL DEFAULT 5242880,
    modified_within_days INTEGER NOT NULL DEFAULT 0,
    pattern_ids          TEXT[] NOT NULL DEFAULT '{}',
    custom_patterns      JSONB NOT NULL DEFAULT '[]',
    min_matches          INTEGER NOT NULL DEFAULT 1,
    interval_hours       INTEGER NOT NULL DEFAULT 24,
    snippets             BOOLEAN NOT NULL DEFAULT true,
    created_by           TEXT NOT NULL DEFAULT '',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS reveal_scans (
    rule_id       TEXT NOT NULL REFERENCES reveal_rules(id) ON DELETE CASCADE,
    agent_id      TEXT NOT NULL,
    scan_id       TEXT NOT NULL,
    dispatched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ,
    files_seen    INTEGER NOT NULL DEFAULT 0,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    files_matched INTEGER NOT NULL DEFAULT 0,
    skipped       INTEGER NOT NULL DEFAULT 0,
    truncated     BOOLEAN NOT NULL DEFAULT false,
    error         TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (rule_id, agent_id)
);
CREATE TABLE IF NOT EXISTS reveal_matches (
    rule_id    TEXT NOT NULL REFERENCES reveal_rules(id) ON DELETE CASCADE,
    agent_id   TEXT NOT NULL,
    path       TEXT NOT NULL,
    pattern_id TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    confirmed  INTEGER NOT NULL DEFAULT 0,
    size       BIGINT NOT NULL DEFAULT 0,
    modified   TIMESTAMPTZ,
    snippet    TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, agent_id, path, pattern_id)
);
CREATE INDEX IF NOT EXISTS reveal_matches_agent ON reveal_matches(agent_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS reveal_matches_pattern ON reveal_matches(pattern_id);

-- Guide: the notification tray. One row per thing the console wants an
-- operator to know, keyed so a condition that persists is one item, not
-- one per evaluation. Guidance links to a fix; an observation is something
-- to look at. Dismissed stays dismissed while the condition persists;
-- resolved means the condition went away on its own.
CREATE TABLE IF NOT EXISTS guide_notifications (
    id           TEXT PRIMARY KEY,
    subject_key  TEXT NOT NULL UNIQUE,      -- source + what it is about
    source       TEXT NOT NULL,             -- deploy | certificates | agents | endpoint | reveal | impact | directory | vulnerabilities
    kind         TEXT NOT NULL,             -- guidance | observation
    severity     TEXT NOT NULL,             -- critical | high | medium | low
    title        TEXT NOT NULL,
    detail       TEXT NOT NULL DEFAULT '',
    link         TEXT NOT NULL DEFAULT '',
    count        INTEGER NOT NULL DEFAULT 1,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    dismissed_at TIMESTAMPTZ,
    dismissed_by TEXT NOT NULL DEFAULT '',
    resolved_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS guide_open ON guide_notifications(resolved_at, dismissed_at, severity);

-- Maintenance windows: when deployments and patching may run on the
-- endpoints a window covers. A window restricts only the endpoints in its
-- groups; an endpoint no window covers is unrestricted. Any open window
-- permits. A deployment may override windows, which is its own permission.
CREATE TABLE IF NOT EXISTS maintenance_windows (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    enabled          BOOLEAN NOT NULL DEFAULT true,
    group_ids        TEXT[] NOT NULL DEFAULT '{}',   -- empty = every endpoint
    weekdays         INTEGER[] NOT NULL DEFAULT '{}', -- 0 Sunday .. 6 Saturday; empty = every day
    start_time       TEXT NOT NULL,                  -- HH:MM in the window's zone
    duration_minutes INTEGER NOT NULL,
    timezone         TEXT NOT NULL DEFAULT 'UTC',
    applies_to       TEXT[] NOT NULL DEFAULT '{deploy,patch}',
    created_by       TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Maintenance windows, the fuller form: a platform, a recurrence (once,
-- daily, weekly, monthly on a date or the Nth weekday) every N, an
-- effective date, and endpoint local time or a chosen zone with or without
-- daylight saving. Existing rows read as before: recurrence '' is the
-- original weekdays-every-week form, in their zone, observing DST.
ALTER TABLE maintenance_windows ADD COLUMN IF NOT EXISTS number BIGSERIAL;
ALTER TABLE maintenance_windows ADD COLUMN IF NOT EXISTS platform TEXT NOT NULL DEFAULT '';
ALTER TABLE maintenance_windows ADD COLUMN IF NOT EXISTS recurrence TEXT NOT NULL DEFAULT '';
ALTER TABLE maintenance_windows ADD COLUMN IF NOT EXISTS interval_n INTEGER NOT NULL DEFAULT 1;
ALTER TABLE maintenance_windows ADD COLUMN IF NOT EXISTS start_date DATE;
ALTER TABLE maintenance_windows ADD COLUMN IF NOT EXISTS month_day INTEGER NOT NULL DEFAULT 0;
ALTER TABLE maintenance_windows ADD COLUMN IF NOT EXISTS month_week INTEGER NOT NULL DEFAULT 0;
ALTER TABLE maintenance_windows ADD COLUMN IF NOT EXISTS month_weekday INTEGER NOT NULL DEFAULT 0;
ALTER TABLE maintenance_windows ADD COLUMN IF NOT EXISTS time_base TEXT NOT NULL DEFAULT 'zone';
ALTER TABLE maintenance_windows ADD COLUMN IF NOT EXISTS observe_dst BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE maintenance_windows ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT '';

-- The endpoint's time zone as its agent reports it (IANA name when the
-- agent can tell, and the current UTC offset either way), for maintenance
-- windows in endpoint local time. Empty/NULL until a reporting agent.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS utc_offset_seconds INTEGER;

-- Deployment templates: the choices a deployment form remembers, so an
-- operator picks "quiet install, allow reboot, expire in a day" once.
CREATE TABLE IF NOT EXISTS deployment_templates (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    is_default       BOOLEAN NOT NULL DEFAULT false,
    package_id       TEXT NOT NULL DEFAULT '',
    operation        TEXT NOT NULL DEFAULT '',
    plan_id          TEXT NOT NULL DEFAULT '',
    parameters       JSONB NOT NULL DEFAULT '{}',
    allow_reboot     BOOLEAN NOT NULL DEFAULT false,
    force_remove     BOOLEAN NOT NULL DEFAULT false,
    expire_seconds   INTEGER NOT NULL DEFAULT 86400,
    override_windows BOOLEAN NOT NULL DEFAULT false,
    created_by       TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Patch lists (kind 'allow') and block lists (kind 'block'): rule-based
-- policy over which pending patches an endpoint may receive. Rules are
-- JSON (internal/patchpolicy.Rules). A list restricts only the endpoints
-- in its groups; empty group_ids covers every endpoint. Not to be confused
-- with patch_lists above, which scope a Linux host's repositories.
CREATE TABLE IF NOT EXISTS patch_policies (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,                  -- allow | block
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    group_ids   TEXT[] NOT NULL DEFAULT '{}',
    rules       JSONB NOT NULL DEFAULT '{}',
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- When the fleet first saw each pending patch. Feeds the "at least N days
-- old" rule and the superseded flag; updated as patches snapshots arrive.
CREATE TABLE IF NOT EXISTS patch_observations (
    os          TEXT NOT NULL,
    name        TEXT NOT NULL,
    new_version TEXT NOT NULL DEFAULT '',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (os, name, new_version)
);
-- agent_actions.status also carries the patch status taxonomy:
-- 'waiting' (for a maintenance window), 'downloading', 'installing'
-- (progress reported by the agent), 'pending_restart' (finished, reboot
-- outstanding), 'skipped' (nothing permitted by patch lists).
CREATE INDEX IF NOT EXISTS idx_agent_actions_waiting ON agent_actions (status) WHERE status = 'waiting';

-- Typed Enforce policies. kind is '' for a hand-written policy, else one
-- of internal/enforcekinds (windows_firewall, bitlocker, defender,
-- applocker); config is that kind's form, and settings is what it compiled
-- to -- the engine only ever reads settings.
ALTER TABLE enforce_policies ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT '';
ALTER TABLE enforce_policies ADD COLUMN IF NOT EXISTS config JSONB NOT NULL DEFAULT '{}';

-- BitLocker recovery passwords, escrowed from the security posture sensor
-- and stored only encrypted (vault). Reading one is its own permission and
-- is audited; the sensor cache never holds the password.
CREATE TABLE IF NOT EXISTS bitlocker_keys (
    agent_id       TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    mount          TEXT NOT NULL,
    key_id         TEXT NOT NULL,
    password_enc   BYTEA NOT NULL,
    first_escrowed TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, key_id)
);

-- Recorder events: registry, network, DNS and logon events as they
-- happen, the third real-time feed beside file_events and process_events.
-- One table for four kinds; fields carries the kind-specific columns as
-- JSON and summary is the one line a row shows. matched_signal is the
-- Signal that fired on this event, kept far longer than the timeline.
CREATE TABLE IF NOT EXISTS recorder_events (
    id             BIGSERIAL PRIMARY KEY,
    agent_id       TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    kind           TEXT NOT NULL,            -- registry | network | dns | logon | suppressed
    at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    count          INT NOT NULL DEFAULT 1,
    pid            INT NOT NULL DEFAULT 0,
    process        TEXT NOT NULL DEFAULT '',
    username       TEXT NOT NULL DEFAULT '',
    op             TEXT NOT NULL DEFAULT '',
    summary        TEXT NOT NULL DEFAULT '',
    fields         JSONB NOT NULL DEFAULT '{}',
    source         TEXT NOT NULL DEFAULT '',
    matched_signal TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_recorder_events_at ON recorder_events (at DESC);
CREATE INDEX IF NOT EXISTS idx_recorder_events_agent ON recorder_events (agent_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_recorder_events_kind ON recorder_events (kind, at DESC);
CREATE INDEX IF NOT EXISTS idx_recorder_events_matched ON recorder_events (matched_signal, at DESC) WHERE matched_signal <> '';

-- Signals: behavioural rules (internal/signals) evaluated live against
-- every process, file and recorder event. A finding is one signal on one
-- endpoint, counted, so a rule that fires a thousand times overnight is
-- one row saying so.
CREATE TABLE IF NOT EXISTS signals (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT 'warning',   -- info | warning | critical
    expression  TEXT NOT NULL,
    objects     TEXT[] NOT NULL DEFAULT '{}',      -- event kinds the expression reads
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS signal_findings (
    id           TEXT PRIMARY KEY,
    signal_id    TEXT NOT NULL REFERENCES signals(id) ON DELETE CASCADE,
    agent_id     TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    kind         TEXT NOT NULL DEFAULT '',
    summary      TEXT NOT NULL DEFAULT '',
    count        INT NOT NULL DEFAULT 1,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (signal_id, agent_id)
);
CREATE INDEX IF NOT EXISTS idx_signal_findings_seen ON signal_findings (last_seen DESC);

-- Exploit intelligence: CISA's Known Exploited Vulnerabilities catalogue
-- and FIRST's EPSS scores, replaced wholesale on each daily refresh. Both
-- are keyed by CVE; a vulnerability on the fleet is joined through the CVE
-- aliases OSV publishes for it.
CREATE TABLE IF NOT EXISTS kev_entries (
    cve             TEXT PRIMARY KEY,
    vendor          TEXT NOT NULL DEFAULT '',
    product         TEXT NOT NULL DEFAULT '',
    name            TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    required_action TEXT NOT NULL DEFAULT '',
    date_added      DATE,
    due_date        DATE,
    ransomware      BOOLEAN NOT NULL DEFAULT false,
    notes           TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS epss_scores (
    cve        TEXT PRIMARY KEY,
    epss       REAL NOT NULL,
    percentile REAL NOT NULL
);

-- When each endpoint was last vulnerability-scanned and what the scan
-- found, so a level can say "not scanned" honestly: a host with no rows in
-- agent_vulnerabilities is either clean or never looked at, and those are
-- different answers.
CREATE TABLE IF NOT EXISTS vuln_scan_status (
    agent_id       TEXT PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    scanned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    findings       INT NOT NULL DEFAULT 0,
    actionable     INT NOT NULL DEFAULT 0,
    worst_severity TEXT NOT NULL DEFAULT ''
);

-- Client configuration profiles: settings pushed to groups of agents, and
-- the upgrade ring the agents belong to. Highest priority wins where an
-- endpoint is covered by several; empty group_ids covers every endpoint.
-- agents.settings is what each agent reports it is running with, so drift
-- is measured rather than assumed.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS settings JSONB NOT NULL DEFAULT '{}';
CREATE TABLE IF NOT EXISTS client_profiles (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    priority         INT NOT NULL DEFAULT 0,
    group_ids        TEXT[] NOT NULL DEFAULT '{}',
    settings         JSONB NOT NULL DEFAULT '{}',   -- proto.AgentSettings
    upgrade_ring     INT NOT NULL DEFAULT 1,        -- 1 = first; 0 = deferral (never auto-upgraded)
    enabled          BOOLEAN NOT NULL DEFAULT true,
    created_by       TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Software Inventory & Usage (0.57.0). software_presence is the normalised
-- product on each endpoint with when it was first and last seen, kept after
-- it disappears (removed_at) so "first seen"/"removed" survive the sensor
-- snapshot being replaced. software_usage_days is process starts rolled up
-- per (endpoint, executable, UTC day) from process_events, which is only
-- kept for 48 hours; this table is what gives a 30-day usage history.
CREATE TABLE IF NOT EXISTS software_presence (
    agent_id      TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    product_key   TEXT NOT NULL,
    name          TEXT NOT NULL,
    vendor        TEXT NOT NULL DEFAULT '',
    version       TEXT NOT NULL DEFAULT '',
    executable    TEXT NOT NULL DEFAULT '',
    install_date  TEXT NOT NULL DEFAULT '',
    last_used_reported TIMESTAMPTZ,
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    removed_at    TIMESTAMPTZ,
    PRIMARY KEY (agent_id, product_key)
);
CREATE INDEX IF NOT EXISTS software_presence_key_idx ON software_presence (product_key) WHERE removed_at IS NULL;
CREATE TABLE IF NOT EXISTS software_usage_days (
    agent_id  TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    exe       TEXT NOT NULL,
    day       DATE NOT NULL,
    launches  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_id, exe, day)
);
CREATE INDEX IF NOT EXISTS software_usage_days_day_idx ON software_usage_days (day);
-- Tracked products: the ones an operator cares about enough to price.
-- cost_per_seat_cents × installed = estimated annual cost; × unused = waste.
CREATE TABLE IF NOT EXISTS tracked_products (
    id                  TEXT PRIMARY KEY,
    product_key         TEXT NOT NULL UNIQUE,
    name                TEXT NOT NULL,
    vendor              TEXT NOT NULL DEFAULT '',
    executables         TEXT[] NOT NULL DEFAULT '{}',
    cost_per_seat_cents BIGINT NOT NULL DEFAULT 0,
    currency            TEXT NOT NULL DEFAULT 'USD',
    package_id          TEXT NOT NULL DEFAULT '',   -- catalog package that removes/installs it
    notes               TEXT NOT NULL DEFAULT '',
    created_by          TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Dashboards and custom alerts (0.58.0). A dashboard is a list of panels,
-- each a report section (source, saved question, group-by, filter) plus
-- how to draw it. panel_samples is the count each panel produced at each
-- sampling, which is what an area/historical panel and "last 30 days" are
-- drawn from. dashboard_alerts are thresholds on a panel that surface in
-- the Guide tray while they hold.
CREATE TABLE IF NOT EXISTS dashboards (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    panels      JSONB NOT NULL DEFAULT '[]'::jsonb,
    shared      BOOLEAN NOT NULL DEFAULT true,
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS panel_samples (
    dashboard_id TEXT NOT NULL REFERENCES dashboards(id) ON DELETE CASCADE,
    panel_id     TEXT NOT NULL,
    at           TIMESTAMPTZ NOT NULL,
    value        DOUBLE PRECISION NOT NULL DEFAULT 0,
    series       JSONB NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (dashboard_id, panel_id, at)
);
CREATE TABLE IF NOT EXISTS dashboard_alerts (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    dashboard_id   TEXT NOT NULL REFERENCES dashboards(id) ON DELETE CASCADE,
    panel_id       TEXT NOT NULL,
    condition      JSONB NOT NULL DEFAULT '{}'::jsonb,
    severity       TEXT NOT NULL DEFAULT 'medium',
    enabled        BOOLEAN NOT NULL DEFAULT true,
    last_value     DOUBLE PRECISION,
    last_state     TEXT NOT NULL DEFAULT '',   -- '' | ok | triggered | error
    last_detail    TEXT NOT NULL DEFAULT '',
    last_evaluated TIMESTAMPTZ,
    created_by     TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Integrity Monitor management objects (0.59.0). A watchlist is a named
-- set of paths (and, on Windows, registry keys); a monitor applies one to
-- computer groups; the union of an endpoint's monitors is pushed to its
-- agent as its watch set. Labels are rules that classify a change as
-- expected or merely tag it, by path, kind, group, time window, or an
-- open maintenance window.
CREATE TABLE IF NOT EXISTS watchlists (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    template        TEXT NOT NULL DEFAULT '',
    paths           TEXT[] NOT NULL DEFAULT '{}',
    registry_keys   TEXT[] NOT NULL DEFAULT '{}',
    follow_symlinks BOOLEAN NOT NULL DEFAULT false,
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS integrity_monitors (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    watchlist_id TEXT NOT NULL REFERENCES watchlists(id) ON DELETE CASCADE,
    group_ids    TEXT[] NOT NULL DEFAULT '{}',
    enabled      BOOLEAN NOT NULL DEFAULT true,
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS integrity_labels (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    expected   BOOLEAN NOT NULL DEFAULT false,
    criteria   JSONB NOT NULL DEFAULT '{}'::jsonb,
    priority   INT NOT NULL DEFAULT 0,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE integrity_changes ADD COLUMN IF NOT EXISTS labels TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE integrity_changes ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ;
ALTER TABLE integrity_changes ADD COLUMN IF NOT EXISTS acknowledged_by TEXT NOT NULL DEFAULT '';
ALTER TABLE file_events ADD COLUMN IF NOT EXISTS labels TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS watch_revision TEXT NOT NULL DEFAULT '';

-- The watch set each endpoint's last integrity snapshot was taken under.
-- A path that is newly watched shows up in the next snapshot without a
-- predecessor; without this record every file under a new watchlist would
-- be reported as "added" — thousands of findings that are only "we started
-- looking". The diff treats such paths as baseline instead.
CREATE TABLE IF NOT EXISTS agent_watch_baseline (
    agent_id   TEXT PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    revision   TEXT NOT NULL DEFAULT '',
    roots      TEXT[] NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Access control beyond permissions (0.60.0).
--
-- A permission says what a role may do; these say what it may do it *to*
-- and *with*, and when a second person has to agree first.
--
--   management rights  roles.computer_group_ids — the endpoints a role may
--                      act on. Empty means the whole fleet, so existing
--                      roles keep working.
--   content sets       named collections of sensors, packages, dashboards
--                      and saved questions; a role holding none sees all.
--   action groups      a per-module ceiling on which endpoints may receive
--                      actions at all, independent of who is asking —
--                      this is what keeps a module away from the domain
--                      controllers no matter who holds deploy.manage.
--   approvals          an operation that matches a policy is parked as a
--                      request and runs only once somebody else approves.
ALTER TABLE roles ADD COLUMN IF NOT EXISTS computer_group_ids TEXT[] NOT NULL DEFAULT '{}';

CREATE TABLE IF NOT EXISTS content_sets (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    -- kind -> ids, e.g. {"sensors":["processes"],"packages":["sw-…"]}
    contents    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS role_content_sets (
    role_id        TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    content_set_id TEXT NOT NULL REFERENCES content_sets(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, content_set_id)
);

CREATE TABLE IF NOT EXISTS action_groups (
    module     TEXT PRIMARY KEY,   -- deploy | patches | playbooks | shell | enforce | reveal
    group_ids  TEXT[] NOT NULL DEFAULT '{}',
    enabled    BOOLEAN NOT NULL DEFAULT true,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS approval_policies (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    module      TEXT NOT NULL,              -- which kind of operation
    group_ids   TEXT[] NOT NULL DEFAULT '{}',-- only when it touches these groups; empty = any
    min_devices INT NOT NULL DEFAULT 0,      -- only when it targets at least this many
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS approval_requests (
    id           TEXT PRIMARY KEY,
    policy_id    TEXT NOT NULL DEFAULT '',
    policy_name  TEXT NOT NULL DEFAULT '',
    module       TEXT NOT NULL,
    summary      TEXT NOT NULL,
    -- The operation, verbatim, so approving replays exactly what was asked
    -- rather than something reconstructed from a description.
    method       TEXT NOT NULL,
    path         TEXT NOT NULL,
    body         BYTEA NOT NULL,
    agent_ids    TEXT[] NOT NULL DEFAULT '{}',
    device_count INT NOT NULL DEFAULT 0,
    requested_by TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    state        TEXT NOT NULL DEFAULT 'pending', -- pending | approved | denied | expired | failed
    decided_by   TEXT NOT NULL DEFAULT '',
    decided_at   TIMESTAMPTZ,
    decision_note TEXT NOT NULL DEFAULT '',
    outcome      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_approval_requests_state ON approval_requests (state, requested_at DESC);

-- Jump Gate on Direct Connect (0.61.0): just-in-time, just-enough endpoint
-- access.
--
-- A policy says what reaching an endpoint costs — a reason, an approval,
-- a time limit. A grant is one person's time-boxed permission to reach one
-- endpoint, created by a request and ended by the clock. The session rows
-- already recorded every command before it was sent; they now also carry
-- why the session existed and which grant allowed it, so a transcript
-- answers "who, on what, why, and who agreed" rather than only "what ran".
CREATE TABLE IF NOT EXISTS jump_policies (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    group_ids       TEXT[] NOT NULL DEFAULT '{}',  -- endpoints covered; empty = every endpoint
    require_approval BOOLEAN NOT NULL DEFAULT true,
    require_reason  BOOLEAN NOT NULL DEFAULT true,
    max_minutes     INT NOT NULL DEFAULT 30,
    priority        INT NOT NULL DEFAULT 0,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS jump_grants (
    id           TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    hostname     TEXT NOT NULL DEFAULT '',
    policy_id    TEXT NOT NULL DEFAULT '',
    policy_name  TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    max_minutes  INT NOT NULL DEFAULT 30,
    state        TEXT NOT NULL DEFAULT 'pending', -- pending | approved | denied | expired | revoked | used
    decided_by   TEXT NOT NULL DEFAULT '',
    decided_at   TIMESTAMPTZ,
    decision_note TEXT NOT NULL DEFAULT '',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_jump_grants_state ON jump_grants (state, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_jump_grants_who ON jump_grants (requested_by, agent_id, state);
ALTER TABLE shell_sessions ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '';
ALTER TABLE shell_sessions ADD COLUMN IF NOT EXISTS grant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE shell_sessions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- Asset retention and attributes (0.62.0).
--
-- An endpoint that stops answering used to be deleted outright, which
-- threw away the only record of what was on it. It is now *retired*
-- instead: the row and its sensor history stay, `managed` goes false, and
-- Last Seen says when it was last true. What a decommissioned machine ran
-- is exactly what somebody asks about months later, and re-registering
-- brings it back with its history intact.
--
-- Purging is separate and much slower: retired rows are removed only after
-- purge_after, which defaults to never.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS managed BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS retired_at TIMESTAMPTZ;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS retired_reason TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_agents_managed ON agents (managed) WHERE managed;

-- Custom attributes: what an operator knows about an endpoint that no
-- sensor can report — owner, cost centre, location, warranty, whether it
-- is allowed to be rebooted in the day.
CREATE TABLE IF NOT EXISTS asset_attributes (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,   -- the targeting key, e.g. "owner"
    label       TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'text', -- text | number | date | boolean | select
    options     TEXT[] NOT NULL DEFAULT '{}', -- for kind = select
    description TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS asset_attribute_values (
    agent_id     TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    attribute_id TEXT NOT NULL REFERENCES asset_attributes(id) ON DELETE CASCADE,
    value        TEXT NOT NULL DEFAULT '',
    set_by       TEXT NOT NULL DEFAULT '',
    set_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, attribute_id)
);
CREATE INDEX IF NOT EXISTS idx_asset_attr_values_attr ON asset_attribute_values (attribute_id);

-- Reveal rule sets and pattern pairs (0.63.0).
--
-- A rule set is the regime an operator actually works in: "PCI-DSS" is a
-- handful of rules aimed at a handful of groups, enabled or disabled as
-- one thing. Rules stay the unit of scanning; the set is the unit of
-- deciding.
ALTER TABLE reveal_rules ADD COLUMN IF NOT EXISTS require_pairs JSONB NOT NULL DEFAULT '[]'::jsonb;
CREATE TABLE IF NOT EXISTS reveal_rule_sets (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    regime      TEXT NOT NULL DEFAULT '',   -- PCI-DSS, HIPAA, GDPR, CCPA, custom
    description TEXT NOT NULL DEFAULT '',
    rule_ids    TEXT[] NOT NULL DEFAULT '{}',
    group_ids   TEXT[] NOT NULL DEFAULT '{}',
    enabled     BOOLEAN NOT NULL DEFAULT false,
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Confidence Score (0.64.0).
--
-- endpoint_health is the health score sampled over time. The score itself
-- already existed; nothing kept yesterday's, so "did this deployment make
-- these machines worse" had no way to be answered. Sampled rather than
-- derived because the performance sensor only keeps its latest snapshot.
CREATE TABLE IF NOT EXISTS endpoint_health (
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    at       TIMESTAMPTZ NOT NULL,
    score    INT NOT NULL,
    PRIMARY KEY (agent_id, at)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_health_at ON endpoint_health (at);

-- Engage surveys (0.65.0).
--
-- A survey is asked through the same channel as an end-user notification
-- but stores its answers separately, because the two are different data:
-- a notification's answer is one of three words the agent acts on, and a
-- survey's is whatever the person said.
CREATE TABLE IF NOT EXISTS surveys (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    title       TEXT NOT NULL,
    intro       TEXT NOT NULL DEFAULT '',
    questions   JSONB NOT NULL DEFAULT '[]'::jsonb,
    anonymous   BOOLEAN NOT NULL DEFAULT false,
    deadline_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT NOT NULL DEFAULT ''
);

-- agent_id is nullable on purpose: an anonymous survey stores no endpoint,
-- and a column that is merely ignored would still hold the answer to
-- "who said that". asked_at records when this person was asked, so a
-- response rate has a denominator that is not a guess.
CREATE TABLE IF NOT EXISTS survey_responses (
    id           TEXT PRIMARY KEY,
    survey_id    TEXT NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
    run_id       TEXT NOT NULL DEFAULT '',
    agent_id     TEXT,
    hostname     TEXT NOT NULL DEFAULT '',
    respondent   TEXT NOT NULL DEFAULT '',
    answers      JSONB NOT NULL DEFAULT '[]'::jsonb,
    declined     BOOLEAN NOT NULL DEFAULT false,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_survey_responses_survey ON survey_responses (survey_id, submitted_at DESC);

-- One row per endpoint the survey was sent to, whether or not it answered.
-- Without this the response rate would be "answers ÷ answers", which is
-- always 100% and always meaningless.
CREATE TABLE IF NOT EXISTS survey_sends (
    survey_id TEXT NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
    agent_id  TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    run_id    TEXT NOT NULL DEFAULT '',
    sent_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (survey_id, agent_id)
);

-- Playbook triggers (0.66.0).
--
-- Something other than a clock starting a playbook: a Guide item being
-- raised, or an outside system posting to a URL.
--
-- min_interval_seconds is not a nicety. A trigger on "critical
-- vulnerability found" would otherwise launch one run per finding, and a
-- feed refresh produces hundreds at once. The cooldown is per trigger and
-- has a floor, because a trigger with no cooldown is an outage waiting for
-- the first busy day.
CREATE TABLE IF NOT EXISTS playbook_triggers (
    id                   TEXT PRIMARY KEY,
    playbook_id          TEXT NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    kind                 TEXT NOT NULL,
    enabled              BOOLEAN NOT NULL DEFAULT true,
    source               TEXT NOT NULL DEFAULT '',
    severity             TEXT NOT NULL DEFAULT '',
    title_match          TEXT NOT NULL DEFAULT '',
    token                TEXT NOT NULL DEFAULT '',
    min_interval_seconds INT NOT NULL DEFAULT 300,
    last_fired_at        TIMESTAMPTZ,
    last_detail          TEXT NOT NULL DEFAULT '',
    fire_count           INT NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_playbook_triggers_kind ON playbook_triggers (kind, enabled);
-- A webhook token is the whole credential, so two triggers must never share
-- one. Partial, because event triggers legitimately have none.
CREATE UNIQUE INDEX IF NOT EXISTS idx_playbook_triggers_token
    ON playbook_triggers (token) WHERE token <> '';

-- A playbook run parked at an approval step (0.66.0).
--
-- One row per run, not per endpoint: asking forty people to approve the
-- same change forty times is not an approval gate, it is a denial of
-- service. The endpoints parked at the step are recorded so the run can be
-- resumed exactly where each of them stopped, including across a restart —
-- an approval that takes until tomorrow must not depend on a goroutine
-- still being alive.
CREATE TABLE IF NOT EXISTS playbook_run_pauses (
    run_id      TEXT PRIMARY KEY REFERENCES playbook_runs(id) ON DELETE CASCADE,
    playbook_id TEXT NOT NULL DEFAULT '',
    step_index  INT NOT NULL,
    step_name   TEXT NOT NULL DEFAULT '',
    agent_ids   TEXT[] NOT NULL DEFAULT '{}',
    state       TEXT NOT NULL DEFAULT 'pending',
    reason      TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL DEFAULT '',
    decided_by  TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    decided_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_playbook_run_pauses_state ON playbook_run_pauses (state);

-- =====================================================================
-- Security hardening. Everything below is idempotent: it is applied on
-- every start, to fresh databases and to ones upgraded from any earlier
-- release, so each statement is an IF NOT EXISTS / guarded change.
-- =====================================================================

-- Sessions are stored as SHA-256(cookie token) once `hashed` is true, and
-- carry last_seen_at for the server-side idle timeout. Existing rows are
-- hashed in place: the token a browser presents is hashed before lookup,
-- so this rewrite alone signs no one out. (The one-time sign-out on this
-- release comes from renaming the session cookie to __Host-mustra_session
-- when Secure cookies are on, not from this migration; the CHANGELOG notes
-- it.)
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS hashed BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();
UPDATE sessions SET token = encode(sha256(convert_to(token, 'UTF8')), 'hex'), hashed = true
WHERE NOT hashed;
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);

-- API tokens act within their creator's reach, so they record who that
-- is by id (usernames can change). Tokens minted before this column
-- existed are linked by the creator's username where it still resolves;
-- one that does not resolve is refused at use.
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS created_by_id TEXT NOT NULL DEFAULT '';
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS approval_exempt BOOLEAN NOT NULL DEFAULT false;
-- A token created by another token (tokens.manage) names it here, and
-- works only while every token up that chain is live: revoking a leaked
-- token takes the tokens it made with it.
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS parent_token_id TEXT NOT NULL DEFAULT '';
UPDATE api_tokens t SET created_by_id = u.id
FROM users u
WHERE t.created_by_id = '' AND t.created_by <> '' AND u.username = t.created_by;

-- A Direct Connect session is bound to the principal that opened it, by
-- id. Existing sessions are linked by username where it still resolves.
ALTER TABLE shell_sessions ADD COLUMN IF NOT EXISTS opened_by_id TEXT NOT NULL DEFAULT '';
UPDATE shell_sessions s SET opened_by_id = u.id
FROM users u
WHERE s.opened_by_id = '' AND s.opened_by <> '' AND u.username = s.opened_by;

-- SSO identities are keyed on (issuer, subject): a subject is unique only
-- within its issuer. users.external_id stays for SCIM's externalId.
CREATE TABLE IF NOT EXISTS oidc_identities (
    issuer      TEXT NOT NULL,
    subject     TEXT NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, subject)
);
CREATE INDEX IF NOT EXISTS idx_oidc_identities_user ON oidc_identities (user_id);

-- SCIM may change only the groups it provisioned. Groups with an IdP
-- externalId are SCIM's; console-created groups are not.
ALTER TABLE groups ADD COLUMN IF NOT EXISTS scim_managed BOOLEAN NOT NULL DEFAULT false;
UPDATE groups SET scim_managed = true
WHERE NOT scim_managed AND COALESCE(external_id, '') <> '';

-- Host keys confirmed for agent-push targets. A push to a target whose key
-- is unknown stops before authenticating and asks for confirmation; one
-- whose key differs from the stored one is refused.
CREATE TABLE IF NOT EXISTS ssh_known_hosts (
    target       TEXT PRIMARY KEY,
    key_type     TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    public_key   TEXT NOT NULL,
    confirmed_by TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===========================================================================
-- Agent identity and enrollment (0.80.0).
--
-- Kept in one clearly separated section: every statement is idempotent on
-- a fresh database and on an existing one, and nothing here alters a table
-- defined above.
--
-- enrollment_tokens: created by an administrator, presented once by a new
-- agent (or up to max_uses times, for mass deployment) before it expires.
-- Only a SHA-256 of the token is stored; the token itself is shown once.
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id           TEXT PRIMARY KEY,
    label        TEXT NOT NULL DEFAULT '',
    token_hash   TEXT NOT NULL UNIQUE,
    site         TEXT NOT NULL DEFAULT '',
    max_uses     INT NOT NULL DEFAULT 1,
    uses         INT NOT NULL DEFAULT 0,
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

-- agent_credentials: one per enrolled agent. The secret is 32 random bytes,
-- so a SHA-256 is the right hash (nothing to brute-force, and the broker's
-- auth callout runs it on every connection). No foreign key to agents: a
-- credential is issued at enrollment, before the agent's first
-- registration creates its inventory row, and it deliberately survives the
-- row being retired or purged.
CREATE TABLE IF NOT EXISTS agent_credentials (
    agent_id     TEXT PRIMARY KEY,
    secret_hash  TEXT NOT NULL,
    enrolled_via TEXT NOT NULL DEFAULT '',   -- 'token' | 'legacy'
    token_id     TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_auth_at TIMESTAMPTZ
);

-- A revoked credential is a tombstone, not a deleted row: revoked_at is set
-- and secret_hash cleared, so the ID can no longer authenticate and can
-- never be claimed again by legacy or token enrolment (the row used to be
-- deleted, which made a revoked ID free for its compromised host to take
-- back). Idempotent for databases created before the column existed.
ALTER TABLE agent_credentials ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

-- agent_legacy_seen: the last time an agent registered over the legacy
-- shared credential, which is what "needs re-enrollment" is based on.
CREATE TABLE IF NOT EXISTS agent_legacy_seen (
    agent_id     TEXT PRIMARY KEY,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- ===========================================================================

-- Playbook webhook tokens are stored as SHA-256(token) once token_hashed is
-- true, so reading the database no longer yields a working webhook URL.
-- Existing tokens are hashed in place and keep working: the server hashes
-- the presented token before looking it up. New rows are inserted with
-- token_hashed = true; a row an older server inserts gets hashed here on
-- the next start.
ALTER TABLE playbook_triggers ADD COLUMN IF NOT EXISTS token_hashed BOOLEAN NOT NULL DEFAULT false;
UPDATE playbook_triggers SET token = encode(sha256(convert_to(token, 'UTF8')), 'hex'), token_hashed = true
WHERE NOT token_hashed AND token <> '';

-- Short numbers for what people refer to: endpoints, deployments and
-- packages, like Tanium's numeric IDs. The text IDs stay the keys (an
-- agent's identity, its credential and its NATS subjects are built on
-- them); the number is what the console shows and what links may use.
-- Existing rows are numbered oldest first, once; new rows draw the next.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS num BIGINT;
CREATE SEQUENCE IF NOT EXISTS agents_num_seq;
UPDATE agents SET num = s.n FROM (
  SELECT agent_id, row_number() OVER (ORDER BY first_seen, agent_id) + (SELECT coalesce(max(num), 0) FROM agents) AS n
  FROM agents WHERE num IS NULL) s
WHERE agents.agent_id = s.agent_id;
SELECT setval('agents_num_seq', greatest((SELECT coalesce(max(num), 0) FROM agents), 1), (SELECT count(*) > 0 FROM agents WHERE num IS NOT NULL));
ALTER TABLE agents ALTER COLUMN num SET DEFAULT nextval('agents_num_seq');
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_num ON agents (num);

ALTER TABLE patch_job_runs ADD COLUMN IF NOT EXISTS num BIGINT;
CREATE SEQUENCE IF NOT EXISTS patch_job_runs_num_seq;
UPDATE patch_job_runs SET num = s.n FROM (
  SELECT id, row_number() OVER (ORDER BY started_at, id) + (SELECT coalesce(max(num), 0) FROM patch_job_runs) AS n
  FROM patch_job_runs WHERE num IS NULL) s
WHERE patch_job_runs.id = s.id;
SELECT setval('patch_job_runs_num_seq', greatest((SELECT coalesce(max(num), 0) FROM patch_job_runs), 1), (SELECT count(*) > 0 FROM patch_job_runs WHERE num IS NOT NULL));
ALTER TABLE patch_job_runs ALTER COLUMN num SET DEFAULT nextval('patch_job_runs_num_seq');
CREATE UNIQUE INDEX IF NOT EXISTS idx_patch_job_runs_num ON patch_job_runs (num);

ALTER TABLE software_packages ADD COLUMN IF NOT EXISTS num BIGINT;
CREATE SEQUENCE IF NOT EXISTS software_packages_num_seq;
UPDATE software_packages SET num = s.n FROM (
  SELECT id, row_number() OVER (ORDER BY created_at, id) + (SELECT coalesce(max(num), 0) FROM software_packages) AS n
  FROM software_packages WHERE num IS NULL) s
WHERE software_packages.id = s.id;
SELECT setval('software_packages_num_seq', greatest((SELECT coalesce(max(num), 0) FROM software_packages), 1), (SELECT count(*) > 0 FROM software_packages WHERE num IS NOT NULL));
ALTER TABLE software_packages ALTER COLUMN num SET DEFAULT nextval('software_packages_num_seq');
CREATE UNIQUE INDEX IF NOT EXISTS idx_software_packages_num ON software_packages (num);

ALTER TABLE reveal_rules ADD COLUMN IF NOT EXISTS num BIGINT;
CREATE SEQUENCE IF NOT EXISTS reveal_rules_num_seq;
UPDATE reveal_rules SET num = s.n FROM (
  SELECT id, row_number() OVER (ORDER BY created_at, id) + (SELECT coalesce(max(num), 0) FROM reveal_rules) AS n
  FROM reveal_rules WHERE num IS NULL) s
WHERE reveal_rules.id = s.id;
SELECT setval('reveal_rules_num_seq', greatest((SELECT coalesce(max(num), 0) FROM reveal_rules), 1), (SELECT count(*) > 0 FROM reveal_rules WHERE num IS NOT NULL));
ALTER TABLE reveal_rules ALTER COLUMN num SET DEFAULT nextval('reveal_rules_num_seq');
CREATE UNIQUE INDEX IF NOT EXISTS idx_reveal_rules_num ON reveal_rules (num);

-- Certificate renewal (Cert Manager): one row per certificate Mustra keeps
-- renewed on an endpoint. Paths are on the endpoint; key_path empty means
-- the key and certificate share cert_path (Pi-hole's tls.pem).
CREATE TABLE IF NOT EXISTS managed_certs (
    id             TEXT PRIMARY KEY,
    agent_id       TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    name           TEXT NOT NULL DEFAULT '',
    names          TEXT[] NOT NULL DEFAULT '{}',
    cert_path      TEXT NOT NULL,
    key_path       TEXT NOT NULL DEFAULT '',
    reload_cmd     TEXT NOT NULL DEFAULT '',
    verify_port    INT NOT NULL DEFAULT 0,
    ca             TEXT NOT NULL DEFAULT 'private',
    renew_days     INT NOT NULL DEFAULT 30,
    approval       TEXT NOT NULL DEFAULT 'auto',
    enabled        BOOLEAN NOT NULL DEFAULT true,
    state          TEXT NOT NULL DEFAULT 'idle',
    last_renewed_at TIMESTAMPTZ,
    last_attempt_at TIMESTAMPTZ,
    last_detail    TEXT NOT NULL DEFAULT '',
    expires_at     TIMESTAMPTZ,
    created_by     TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_managed_certs_agent ON managed_certs (agent_id);
-- Windows certificate store installs: bind to an IIS site ("iis", on
-- verify_port) or to Remote Desktop ("rdp").
ALTER TABLE managed_certs ADD COLUMN IF NOT EXISTS win_bind TEXT NOT NULL DEFAULT '';
ALTER TABLE managed_certs ADD COLUMN IF NOT EXISTS iis_site TEXT NOT NULL DEFAULT '';

-- Every certificate Mustra issued, and what became of it: the inventory of
-- what it put on endpoints, and the record revocation works from. A
-- managed certificate gets one row per issuance; a renewal supersedes the
-- one before. Only the public certificate is kept: the key never leaves
-- the endpoint. managed_cert_id is not a foreign key, so the history
-- outlives a certificate that is no longer managed.
CREATE TABLE IF NOT EXISTS cert_issuances (
    id              TEXT PRIMARY KEY,
    managed_cert_id TEXT NOT NULL DEFAULT '',
    agent_id        TEXT NOT NULL DEFAULT '',
    name            TEXT NOT NULL DEFAULT '',
    names           TEXT[] NOT NULL DEFAULT '{}',
    cert_path       TEXT NOT NULL DEFAULT '',
    ca              TEXT NOT NULL,
    serial          TEXT NOT NULL DEFAULT '',
    fingerprint     TEXT NOT NULL DEFAULT '',
    issuer          TEXT NOT NULL DEFAULT '',
    not_before      TIMESTAMPTZ,
    not_after       TIMESTAMPTZ,
    cert_pem        TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT 'issued',
    issued_by       TEXT NOT NULL DEFAULT '',
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    superseded_at   TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    revoked_by      TEXT NOT NULL DEFAULT '',
    revoke_reason   TEXT NOT NULL DEFAULT '',
    revoke_detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_cert_issuances_managed ON cert_issuances (managed_cert_id, issued_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_issuances_ca_serial ON cert_issuances (ca, serial) WHERE serial <> '';

-- Enterprise application credentials (Cert Manager → App Credentials):
-- client secrets, client certificates, SAML signing certificates and
-- service-account keys held by identity providers. A connection is an API
-- login to one provider (secret is vault-sealed); a credential is one
-- secret or certificate there, tracked for expiry and, depending on its
-- mode, renewed: remind only, renew and keep the new material for a
-- one-time download, or renew and push it to an endpoint.
CREATE TABLE IF NOT EXISTS app_cred_connections (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    name        TEXT NOT NULL,
    config      JSONB NOT NULL DEFAULT '{}',
    secret      TEXT NOT NULL DEFAULT '',
    last_ok_at  TIMESTAMPTZ,
    last_error  TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app_credentials (
    id                   TEXT PRIMARY KEY,
    connection_id        TEXT NOT NULL DEFAULT '',
    kind                 TEXT NOT NULL,
    app_id               TEXT NOT NULL DEFAULT '',
    app_name             TEXT NOT NULL DEFAULT '',
    cred_type            TEXT NOT NULL,
    external_id          TEXT NOT NULL DEFAULT '',
    display_name         TEXT NOT NULL DEFAULT '',
    expires_at           TIMESTAMPTZ,
    rotate_days          INT NOT NULL DEFAULT 0,
    renew_days           INT NOT NULL DEFAULT 30,
    mode                 TEXT NOT NULL DEFAULT 'remind',
    push_agent_id        TEXT NOT NULL DEFAULT '',
    push_path            TEXT NOT NULL DEFAULT '',
    push_key             TEXT NOT NULL DEFAULT '',
    push_reload          TEXT NOT NULL DEFAULT '',
    grace_days           INT NOT NULL DEFAULT 7,
    state                TEXT NOT NULL DEFAULT 'idle',
    last_detail          TEXT NOT NULL DEFAULT '',
    last_rotated_at      TIMESTAMPTZ,
    previous_external_id TEXT NOT NULL DEFAULT '',
    retire_after         TIMESTAMPTZ,
    material             TEXT NOT NULL DEFAULT '',
    material_until       TIMESTAMPTZ,
    notified_at          TIMESTAMPTZ,
    created_by           TEXT NOT NULL DEFAULT '',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_app_credentials_external ON app_credentials (connection_id, app_id, cred_type, external_id) WHERE connection_id <> '';

-- Expiry alerts (Cert Manager → Alerts): which threshold each certificate
-- or credential has been announced at, per expiry date, so each crossing
-- is sent once and a renewal (a new expiry) starts afresh.
CREATE TABLE IF NOT EXISTS expiry_alerts (
    item_key   TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    threshold  INT NOT NULL,
    title      TEXT NOT NULL DEFAULT '',
    days_left  INT NOT NULL DEFAULT 0,
    sent_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (item_key, expires_at, threshold)
);
CREATE INDEX IF NOT EXISTS idx_expiry_alerts_sent ON expiry_alerts (sent_at DESC);

-- Integrations (Administration → Integrations): event streaming to
-- webhooks, chat, Splunk, Loki and ServiceNow, and the Prometheus scrape
-- token. secret is vault-sealed; config holds everything that is not secret.
CREATE TABLE IF NOT EXISTS integrations (
    id            TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,
    name          TEXT NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    config        JSONB NOT NULL DEFAULT '{}',
    secret        TEXT NOT NULL DEFAULT '',
    events        TEXT[] NOT NULL DEFAULT '{alert}',
    min_severity  TEXT NOT NULL DEFAULT 'warning',
    last_ok_at    TIMESTAMPTZ,
    last_error    TEXT NOT NULL DEFAULT '',
    last_error_at TIMESTAMPTZ,
    sent          BIGINT NOT NULL DEFAULT 0,
    created_by    TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Remote desktop sessions that must end on time (0.85.0). Only sessions a
-- Jump Gate window or grant bounds are recorded: the server logs the
-- Guacamole session out when the window ends or the grant is revoked.
CREATE TABLE IF NOT EXISTS remote_sessions (
    id          TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    hostname    TEXT NOT NULL DEFAULT '',
    username    TEXT NOT NULL DEFAULT '',
    protocol    TEXT NOT NULL DEFAULT '',
    provider    TEXT NOT NULL DEFAULT '',
    grant_id    TEXT NOT NULL DEFAULT '',
    guac_token  TEXT NOT NULL DEFAULT '', -- vault-sealed Guacamole auth token
    opened_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    ended_at    TIMESTAMPTZ,
    end_reason  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_remote_sessions_open ON remote_sessions (expires_at) WHERE ended_at IS NULL;

-- Trusted roots pushed to endpoints' trust stores (0.86.0): one row per
-- endpoint and root certificate (SHA-256 fingerprint).
CREATE TABLE IF NOT EXISTS root_trust (
    agent_id    TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT '', -- installed | removed | failed | unsupported
    via         TEXT NOT NULL DEFAULT '', -- agent | mdm
    detail      TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, fingerprint)
);

-- Network discovery memory (0.86.0): every device endpoints have seen in
-- their neighbour tables, by MAC, with when it was first and last seen.
CREATE TABLE IF NOT EXISTS network_devices (
    mac         TEXT PRIMARY KEY,
    ip          TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL DEFAULT '',  -- reverse DNS
    name_at     TIMESTAMPTZ,               -- when the name was last looked up
    vendor      TEXT NOT NULL DEFAULT '',
    seen_by     TEXT[] NOT NULL DEFAULT '{}',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    label       TEXT NOT NULL DEFAULT '',
    ignored     BOOLEAN NOT NULL DEFAULT false,
    alerted     BOOLEAN NOT NULL DEFAULT false
);
-- Devices recorded by the first pass were already there: never "new".
ALTER TABLE network_devices ADD COLUMN IF NOT EXISTS baseline BOOLEAN NOT NULL DEFAULT false;

-- Backup status alerts (0.86.0): a guest whose backup is overdue, from
-- when, so each episode notifies once and its recovery once.
CREATE TABLE IF NOT EXISTS backup_alerts (
    guest_key  TEXT PRIMARY KEY, -- node/vmid
    since      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Microsoft Entra ID and Intune devices (0.86.0), synced from Microsoft
-- Graph and matched to Mustra endpoints. Keyed by the Entra device ID, or
-- by "intune:<id>" for an Intune device Entra does not know.
CREATE TABLE IF NOT EXISTS entra_devices (
    key              TEXT PRIMARY KEY,
    entra_device_id  TEXT NOT NULL DEFAULT '',
    intune_id        TEXT NOT NULL DEFAULT '',
    name             TEXT NOT NULL DEFAULT '',
    os               TEXT NOT NULL DEFAULT '',
    os_version       TEXT NOT NULL DEFAULT '',
    trust_type       TEXT NOT NULL DEFAULT '', -- AzureAd, ServerAd (hybrid), Workplace
    account_enabled  BOOLEAN,
    entra_compliant  BOOLEAN,
    last_sign_in     TIMESTAMPTZ,
    compliance_state TEXT NOT NULL DEFAULT '', -- Intune: compliant, noncompliant, unknown…
    last_sync        TIMESTAMPTZ,
    user_upn         TEXT NOT NULL DEFAULT '',
    serial           TEXT NOT NULL DEFAULT '',
    agent_id         TEXT NOT NULL DEFAULT '',
    synced_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_entra_devices_agent ON entra_devices (agent_id) WHERE agent_id <> '';

-- Hardening score history (0.86.0): one severity-weighted score per
-- endpoint, benchmark and day, for trends.
CREATE TABLE IF NOT EXISTS compliance_scores (
    agent_id  TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    policy_id TEXT NOT NULL,
    day       DATE NOT NULL,
    score     REAL NOT NULL,
    pass      INT NOT NULL DEFAULT 0,
    fail      INT NOT NULL DEFAULT 0,
    unknown   INT NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_id, policy_id, day)
);

-- Warranty expiry alerts (0.86.0): the warranty end date an endpoint was
-- last warned about, so each end date warns once.
CREATE TABLE IF NOT EXISTS warranty_alerts (
    agent_id     TEXT PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    warranty_end TEXT NOT NULL
);

-- Hardening exceptions (0.87.0): a benchmark check deliberately not
-- applied, by check title so it covers every benchmark version that has
-- it ("Ensure sshd PermitRootLogin is disabled." in CIS Debian 12 and 13).
-- An empty group_id means every endpoint; a group that no longer exists
-- matches nobody. The stored result keeps its real state; the exception
-- only takes the check out of the score.
CREATE TABLE IF NOT EXISTS compliance_exceptions (
    id         TEXT PRIMARY KEY,
    title      TEXT NOT NULL,
    group_id   TEXT NOT NULL DEFAULT '',
    reason     TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Retirement notes (0.87.2): why a published version was retired ("Superseded
-- by 2.0.0"), by whom and when.
ALTER TABLE deploy_revisions ADD COLUMN IF NOT EXISTS retired_note TEXT NOT NULL DEFAULT '';
ALTER TABLE deploy_revisions ADD COLUMN IF NOT EXISTS retired_by TEXT NOT NULL DEFAULT '';
ALTER TABLE deploy_revisions ADD COLUMN IF NOT EXISTS retired_at TIMESTAMPTZ;

-- Who last changed a package's details (0.87.2), for the package lists'
-- Modified By column.
ALTER TABLE software_packages ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT '';

-- Remote desktop sessions (0.92.0): every Guacamole session is tracked,
-- not only time-boxed ones, so it can carry a temporary sign-in account to
-- remove and a recording to find. last_seen_at is refreshed while the
-- session's tunnel is open; a session idle past a short grace is ended.
-- token_hash finds the session from the tunnel request without opening
-- the sealed token.
ALTER TABLE remote_sessions ADD COLUMN IF NOT EXISTS token_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE remote_sessions ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE remote_sessions ADD COLUMN IF NOT EXISTS recording TEXT NOT NULL DEFAULT '';
ALTER TABLE remote_sessions ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '';
ALTER TABLE remote_sessions ADD COLUMN IF NOT EXISTS jit_username TEXT NOT NULL DEFAULT '';
ALTER TABLE remote_sessions ADD COLUMN IF NOT EXISTS jit_state TEXT NOT NULL DEFAULT ''; -- '' | active | removed
ALTER TABLE remote_sessions ADD COLUMN IF NOT EXISTS jit_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE remote_sessions ADD COLUMN IF NOT EXISTS jit_error TEXT NOT NULL DEFAULT '';
ALTER TABLE remote_sessions ADD COLUMN IF NOT EXISTS jit_next_try_at TIMESTAMPTZ;
ALTER TABLE remote_sessions ADD COLUMN IF NOT EXISTS jit_removed_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_remote_sessions_token ON remote_sessions (token_hash) WHERE ended_at IS NULL AND token_hash <> '';
CREATE INDEX IF NOT EXISTS idx_remote_sessions_jit ON remote_sessions (jit_next_try_at) WHERE jit_state = 'active';
CREATE INDEX IF NOT EXISTS idx_remote_sessions_opened ON remote_sessions (opened_at DESC);

-- Backup systems the Backup status page reads (internal/server/backupsrc):
-- Proxmox Backup Server, Rubrik Security Cloud. secret is sealed by the
-- server; last_result is the newest successful read, kept so the page
-- shows something while the next poll runs.
CREATE TABLE IF NOT EXISTS backup_sources (
    id             TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,
    name           TEXT NOT NULL,
    url            TEXT NOT NULL,
    token_id       TEXT NOT NULL DEFAULT '',
    secret         TEXT NOT NULL DEFAULT '',
    fingerprint    TEXT NOT NULL DEFAULT '',
    datastore      TEXT NOT NULL DEFAULT '',
    enabled        BOOLEAN NOT NULL DEFAULT true,
    last_polled_at TIMESTAMPTZ,
    last_ok_at     TIMESTAMPTZ,
    last_error     TEXT NOT NULL DEFAULT '',
    last_result    JSONB,
    created_by     TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Threat briefings (internal/server/threats.go): a dashboard per actively
-- exploited vulnerability. Briefings for CISA KEV entries are built from
-- kev_entries on the fly; threat_briefs holds the ones written by hand
-- (several CVEs under one name, notes, mitigation, detection rules,
-- hunting questions). threat_counts keeps one row a day per briefing for
-- the trend; threat_alerts remembers which briefings have notified.
CREATE TABLE IF NOT EXISTS threat_briefs (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    cves        TEXT[] NOT NULL DEFAULT '{}',
    summary     TEXT NOT NULL DEFAULT '',
    mitigation  TEXT NOT NULL DEFAULT '',
    refs        JSONB NOT NULL DEFAULT '[]',
    rule        JSONB NOT NULL DEFAULT '{}',
    questions   JSONB NOT NULL DEFAULT '[]',
    archived    BOOLEAN NOT NULL DEFAULT false,
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS threat_counts (
    brief_key   TEXT NOT NULL,
    day         DATE NOT NULL,
    vulnerable  INT NOT NULL DEFAULT 0,
    present     INT NOT NULL DEFAULT 0,
    PRIMARY KEY (brief_key, day)
);
CREATE TABLE IF NOT EXISTS threat_alerts (
    brief_key   TEXT PRIMARY KEY,
    notified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    endpoints   INT NOT NULL DEFAULT 0
);
-- One row per briefing and endpoint the vulnerability scan confirms as
-- vulnerable (internal/server/threat_autoremediate.go): when it was first
-- found, the automatic patch attempts made for it, and whether its CISA
-- due date has been alerted. The row goes when the endpoint is no longer
-- vulnerable, so a later exposure starts afresh.
CREATE TABLE IF NOT EXISTS threat_exposures (
    brief_key        TEXT NOT NULL,
    agent_id         TEXT NOT NULL,
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts         INT NOT NULL DEFAULT 0,
    last_attempt     TIMESTAMPTZ,
    last_run_id      TEXT NOT NULL DEFAULT '',
    gave_up          BOOLEAN NOT NULL DEFAULT false,
    overdue_notified BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (brief_key, agent_id)
);

-- Two-step sign-in for local accounts (TOTP, RFC 6238). SSO accounts use
-- their identity provider's MFA, so these stay NULL for them.
--
-- totp_secret is the base32 secret sealed by the credential vault, bound to
-- the user ID. It is set while enrollment is pending and totp_enabled_at
-- is NULL until the first code is confirmed. totp_last_step is the newest
-- 30-second step accepted, so a code cannot be replayed within its window.
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step BIGINT NOT NULL DEFAULT 0;
-- Single-use recovery codes, stored as SHA-256 (each code carries 80 random
-- bits, so a slow hash adds nothing).
CREATE TABLE IF NOT EXISTS user_recovery_codes (
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   TIMESTAMPTZ,
    PRIMARY KEY (user_id, code_hash)
);
-- A password accepted and a second step owed: the browser holds the token
-- in a short-lived cookie; this row says whose it is, what is owed
-- ("totp" or "enroll"), where to go afterwards and how many codes were
-- tried. No session exists until the step is done.
CREATE TABLE IF NOT EXISTS login_challenges (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose    TEXT NOT NULL,
    next       TEXT NOT NULL DEFAULT '/',
    attempts   INT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_challenges_expires_at ON login_challenges (expires_at);

-- Reading the fleet became a permission (fleet.read), and the audit log
-- its own (audit.read). Before this, any signed-in account read
-- everything, roles or not. Once, on a database that existed before the
-- change, every role and API token gets both, and every account with no
-- role at all gets the built-in read-only role, so nobody loses what they
-- could see on upgrade. The marker row keeps it from running again: after
-- it, an account given no role sees nothing until it is given one. On a
-- new database there is nothing to grant yet and the marker is all it
-- writes; the built-in roles are seeded with the new permissions.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM settings WHERE key = 'migration.read_permissions') THEN
    UPDATE roles SET permissions = array_append(permissions, 'fleet.read')
     WHERE NOT ('fleet.read' = ANY(permissions));
    UPDATE roles SET permissions = array_append(permissions, 'audit.read')
     WHERE NOT ('audit.read' = ANY(permissions));
    UPDATE api_tokens SET permissions = array_append(permissions, 'fleet.read')
     WHERE NOT ('fleet.read' = ANY(permissions));
    UPDATE api_tokens SET permissions = array_append(permissions, 'audit.read')
     WHERE NOT ('audit.read' = ANY(permissions));
    IF EXISTS (SELECT 1 FROM roles WHERE id = 'role-user') THEN
      INSERT INTO user_roles (user_id, role_id)
      SELECT u.id, 'role-user' FROM users u
       WHERE NOT u.is_admin
         AND NOT EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id)
         AND NOT EXISTS (SELECT 1 FROM group_members gm JOIN group_roles gr ON gr.group_id = gm.group_id WHERE gm.user_id = u.id)
      ON CONFLICT DO NOTHING;
    END IF;
    INSERT INTO settings (key, value, updated_by) VALUES ('migration.read_permissions', 'done', 'schema')
    ON CONFLICT (key) DO NOTHING;
  END IF;
END $$;

-- Which vulnerability findings have been announced to integrations, and at
-- what tier, so each is announced once. Rows outlive the finding for a while
-- (last_seen): an endpoint back from a month offline is not news.
CREATE TABLE IF NOT EXISTS vuln_alerts (
    agent_id  TEXT NOT NULL,
    vuln_id   TEXT NOT NULL,
    tier_rank INTEGER NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, vuln_id)
);
CREATE INDEX IF NOT EXISTS idx_vuln_alerts_last_seen ON vuln_alerts (last_seen);

-- A report's own email wording.
ALTER TABLE reports ADD COLUMN IF NOT EXISTS email_template JSONB NOT NULL DEFAULT '{}';

-- When a deployment or patch run's completion was announced to integrations,
-- whether or not it asked for a console notification (notified_at). A run that
-- finished before this column existed is never announced: its last result has
-- already come in, and only a result triggers the check.
ALTER TABLE patch_job_runs ADD COLUMN IF NOT EXISTS completion_announced_at TIMESTAMPTZ;
