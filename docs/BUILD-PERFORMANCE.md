# Build performance — 2026-09-11

## Observed CI baseline

A CI run on this date (in the repository's earlier, private history)
completed successfully in about 4m19s including scheduling. Its image build
step took 3m53s, while the separate agent compilation step took 2m38s.
Linux checks took about 1m27s as a job; macOS checks took about 1m04s after
roughly a minute waiting for a runner. The Windows build job took 2m03s.

The agent job's post-step failed to save the Go cache because the Linux
check job was reserving the same `setup-go` cache key. The new composite
build action isolates the cross-build cache and snapshots it per commit.
The existing native test/build checks remain in place.

Only two CI runs and no release runs were available in this repository.
No changed workflow has been pushed or run on GitHub during this work;
post-change hosted-runner and registry-push timings remain to be measured.

## Controlled local Docker measurements

Measured sequentially on Docker Desktop on Apple Silicon, with both
`linux/amd64` and `linux/arm64` images exported as an OCI archive. Baseline
and changed source trees were copied into temporary directories. Each
variant was primed before measuring an identical repeat and then appending
a comment to the embedded `app.js`. Version arguments stayed at their
constant defaults. Shared Go/Docker caches were not cleared.

| Scenario | Before | After |
| --- | ---: | ---: |
| Identical source-image rebuild | 2.17s | 1.61s |
| Console-only edit, source-image rebuild | 18.47s | 3.66s |

The console-edit result is about an 80% reduction in this warm-cache sample.
The agent stage was cached after the console edit. These are individual
local samples, not cold-build benchmarks or predicted GitHub timings.

Layer inspection showed that the two architectures previously carried
separate agent-layer digests, each about 39 MiB compressed. `COPY --link`
now gives both architectures the same agent-layer digest. This removes
one duplicate layer from multi-platform storage/transfers; a host pulling
only one architecture does not save that whole 39 MiB. Reproducible agent
builds (`-trimpath -buildvcs=false`) also allow otherwise unchanged payloads
to survive server-only commits when `AGENT_VERSION` stays fixed.

## Changes and next measurements

- `make dev-server` no longer invokes the agent matrix and omits the changing
  timestamp from its version flags. Build downloads explicitly as needed.
- CI/release builds six agents and two servers once on the native runner;
  Docker only packages those outputs. Release attachments use those same
  agents. Local source Docker builds also cross-compile natively.
- Separate agent inputs and late version arguments improve source-build
  cache reuse. The module and compilation caches remain shared locally.
- CI cancels superseded runs. Production operators can pull and replace just
  the server with the commands in `deploy/README.md`.

After the next push, compare the composite action's compile time, cache
restore/save time, image packaging/export time, and total workflow duration.
Measure both an initial cache population and a subsequent server-only
commit. For releases, include registry upload and deployment pull time.
Do not reduce platform coverage or parallelize six full compiler processes
without measuring runner memory/CPU contention first.

## Validation

`make check` passed (formatting, vet, build, and tests), as did `actionlint`
and `git diff --check`. Both source-built and packaged multi-platform
images were inspected for the correct server architecture, six agent
platforms, CA bundle, and shared agent-layer digest. Packaged binaries
matched the host outputs byte-for-byte with independent server/agent
versions. An agent rebuilt in another checkout with a console edit was
identical. Both packaged Linux servers executed `-h` successfully in
network-isolated containers (AMD64 execution used Docker Desktop emulation).
This is a runtime smoke check, not a full control-plane integration test.

A repeat of `make agents servers` with fixed identity and warm local Go
caches took 0.77s; packaging those outputs into two OCI images took 5.87s.
These local timings exclude GitHub cache transfers and registry publishing.
