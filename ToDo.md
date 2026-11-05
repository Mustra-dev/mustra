# To do

Open work, kept here so it can be picked up. Add to it when deferring something, and remove an item when it ships: [CHANGELOG.md](CHANGELOG.md) records what did.

## Security hardening

- [ ] Ship the Python runtime and the Windows tray through the signed Go update path; today only the agent binary updates that way and the others need the installer re-run.
- [ ] Replace bash-language-server's vulnerable braces/micromatch/fast-glob chain in tools/script-service once a non-breaking release exists.
- [ ] Review the open CodeQL alerts in code scanning, fix what is real and dismiss the rest with a reason.
- [ ] Run inventory-and-patching mode on a real Home Assistant host. The add-on has been tested with a stand-in Supervisor only.

## Custom sensors

- [ ] Managed, version-pinned third-party Python dependencies.
- [ ] Python/WQL/Batch autocomplete where useful and reliable.
- [ ] Explicit transformations for multiple nested JSON arrays; avoid implicit Cartesian products that change the meaning of records and targeting.
- [ ] Evaluate remote WMI and event subscriptions separately from finite local inventory queries; they need distinct authorization and lifecycle semantics.

## Reveal

- [ ] An on-endpoint index. Every scan walks the files again; an Index hashes and indexes once and lets a rescan, a hash search and File Evidence all read the same table. It is also what would let a quick search answer in seconds on a large home directory.
- [ ] Pattern groups: two patterns within N characters of each other (a name next to an SSN) as one rule condition, which is how a false positive rate is actually driven down.
- [ ] Labels on matched files and an action from a finding (quarantine, delete, notify the owner), so a result is something to do rather than something to read.
- [ ] PDF text. Everything else people keep numbers in is read.

## Deploy

- [ ] Decide whether catalog package names should be unique. Nothing prevents two packages with the same name, which is how four entries called ShareX happened; the causes of that are fixed, but the shape is still possible. Uniqueness is not obviously right — the same application from two vendors is a real case — so this is a decision, not a fix.

## Sensor examples

- [ ] Expand standalone examples to typed schemas and closer built-in parity where useful. Current examples use text records and explicitly document omitted fields, agent state, and integrations; they are not exact collector copies.

## macOS

- [ ] Show which Macs are missing Full Disk Access in one place. The agent measures it now and each endpoint's Privileges tab reports it, which closed the worst of the gap — a lapsed grant used to be invisible until a sensor covering a protected path quietly returned nothing. What is still missing is the fleet-wide view: answering "which Macs need this" means opening each Mac in turn.
- [ ] Sign the agent and the Self Service app with a Developer ID certificate and notarize them. The binary is ad-hoc signed today.

## Endpoint notifications

- [ ] A macOS equivalent. The gap there is smaller — the agent already reaches the console user's session through `osascript`, so notifications are native — but there is no menu-bar item. A real `NSStatusItem` needs Cocoa, so cgo, so a darwin-only build path separate from the `CGO_ENABLED=0` matrix the other five targets are cross-compiled from.
- [ ] Let the toast carry a deadline countdown that updates in place. Windows supports it, and a restart prompt that silently goes stale is the kind of thing people learn to ignore.

## Scale

- [ ] Ingest sensor snapshots in parallel by agent (ordered per agent). The consumer is one goroutine, latency-bound at ~330 snapshots/s: a fleet starting together drains its first snapshots in 71 s at 2,000 endpoints and 148 s at 5,000. Steady state (15-minute interval) needs ~80/s at 5,000 and ~160/s at 10,000. Watch patch-observation upserts for lock ordering when it is parallel.
- [ ] Stream live-query deltas to the console instead of whole snapshots: an installed-apps query over 5,000 endpoints sends ~1.4 GB of cumulative snapshots to each viewer.
- [ ] Cache or precompute the Patches summary and dashboard sources; both decode every endpoint's cached snapshot per view (5,000 endpoints, four viewers: Patches p50 719 ms, Security posture dashboard 597 ms).
- [ ] Upsert software_presence by difference: every installed-apps snapshot rewrites ~800 rows (20 ms of Postgres each), which a fleet starting together pays 5,000 times at once.
- [ ] Batch heartbeat writes (one UPDATE per second for every agent heard from) before ~10,000 endpoints: one statement and commit per heartbeat is 1,000/s there, on a single consumer.

## Fleet integrations

- [ ] Entra ID / Intune: verified against a simulated Microsoft Graph only; check against a real tenant (paging sizes, throttling 429 + Retry-After, Intune devices without an Entra device ID).
- [ ] Warranty lookup from vendor APIs (Dell TechDirect, Lenovo, HP) instead of a hand-entered warranty end; needs per-vendor API keys.
- [ ] Interactive Slack/Teams buttons that decide in the chat itself (needs a registered app and a signed callback endpoint); today's buttons open /approve.
- [ ] Verify the Rubrik Security Cloud provider against a live account (it follows Rubrik's documentation and passes against a stand-in server).
- [ ] ServiceNow CMDB sync (configuration items from endpoints); today ServiceNow receives incidents only.
- [ ] Request/response schemas in the OpenAPI document; today bodies are described as JSON objects.

## Hardening

- [ ] Wazuh's CIS content has rules that can never pass as written (Debian "shadowed passwords" inverted, `ucredit … compare < 0` with a `(\d+)` capture, `ENCRYPT_METHOD` SHA512 *and* YESCRYPT). Consider reporting upstream, or a per-policy rule override in Mustra so a bad rule can be corrected rather than excepted.
- [ ] Exceptions by check title cover every benchmark sharing the title; add optional per-benchmark scoping if two benchmarks ever share a title with different meaning.
- [ ] Enforce has no import from a benchmark: the CIS Linux baseline policy was built by a script that copies each check's rules and adds a fix. A "create Enforce setting from this check" action would make that repeatable in the console.
- [ ] Windows account policy (password length, lockout) and advanced audit subcategories can only come from Group Policy; a typed Enforce kind for `auditpol`/`secedit` would let Mustra hold them on workgroup machines.

## Remote desktop

- [ ] Shadowing from the browser. Guacamole's RDP cannot shadow; a built-in viewer would need the agent to capture and relay the screen, with the consent prompt in the Self Service window and the tray. The command-line route shipped first because Windows already has the consent prompt.
- [ ] Run the Windows and macOS halves of temporary accounts on real machines: they are cross-compiled and reviewed, but only the Linux half (`MUSTRA_LIVE_JIT=1`) and the Guacamole SSH path have run for real.
- [ ] Play a recording in the console instead of only downloading the `.guac` file (guacamole-common-js's SessionRecording player).
- [ ] Track Guacamole's HTTP tunnel as well as its WebSocket one. Only the WebSocket refreshes `last_seen_at`, so a browser that falls back to the HTTP tunnel is ended three minutes in.
- [ ] Domain controllers: a temporary member of a scoped AD group, since a DC has no local accounts to create.
- [ ] Attended screen sharing in the agent (the signed-in user approves, input lock, clipboard, file transfer), so a session does not have to be an RDP login that signs the user out.
- [ ] macOS through Fleet: push the PPPC profile (Accessibility) and send `EnableRemoteDesktop` from Mustra's Fleet integration, so Screen Sharing needs no hands on the Mac. Apple doesn't let MDM grant Screen Recording to a third-party app silently.

## API reference

- [ ] Type the rows still built as maps inside typed responses: fields such as the jobs of `GET /api/deploy/jobs`, the plans of `POST /api/deploy/preview` and the rows of a dashboard panel are `[]map[string]any` or `map[string]any`.
- [ ] Check the spec against the official OAS 3.2 JSON Schema in CI. validated it by hand (Python `jsonschema` with `schema-base/2026-08-30` and the 3.2 dialect); `TestOpenAPIIsStructurallyValid` covers only the rules it spells out. CI would need the schemas vendored and a draft 2020-12 validator.
- [ ] Tag descriptions. The 81 tags come from path segments and have no `description` (Redocly's `tag-description` warning); 3.2's tag `summary` and `parent` could also nest the admin tags.
- [ ] A patch run can still be recorded with no actions when dispatch refuses every endpoint after the run is written. Two one-off applies to the same endpoint at once both pass the handler's open-job check; the second records its run, then `deployPatchesToAgents` refuses it as already patching and the handler answers 502, not 409. A bulk **Deploy now** whose every target is already patching does the same. The handler also ignores an error from `OpenPatchJobs`. Record the run only once an action row exists, or remove it when none was written.
- [ ] A Connect history row that starts at exactly the cursor's instant, but commits after the run that set the cursor, is never exported: the cursor skips rows at or before it. Closing that needs a tie-breaker (start plus row ID) in the cursor, not just the time.
- [ ] Integrity labels' "during maintenance" rule asks the window gate about kind `software`, which no window applies to, so the check always passes and the rule reduces to `hasWindow`: an endpoint any enabled window covers, open or not, in effect or not, matches at every hour, and an expected label on it hides all its changes. `hasWindow` also ignores a window's platform. Both should share `windowCheck`'s covering rule and ask whether a covering window is open.
- [ ] Playbook saves read a database error on a step's enforce policy, message or group as "no such …" and answer 400 (`validatePlaybookSteps`, `handleSavePlaybook`), as the Enforce handlers did before.
- [ ] Revoke an approved Self Service request. Since a decision is final, so the only way to withdraw an entitlement granted by mistake is to delete the package; deciding again used to overwrite it. Revocation needs its own action, audited, and a state other than `denied` so the history shows it was granted first.

## Windows

- [ ] Sign the Windows agent. Unsigned, its updater can be blocked by Defender attack surface reduction rules.
