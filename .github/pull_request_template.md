<!-- Security fixes: do not open a public PR. See SECURITY.md. -->

## What and why

<!-- What this changes, and why. Link the issue if there is one. -->

## Checklist

- [ ] Every commit is signed off (`git commit -s`): the [DCO](https://developercertificate.org/) is required, and CI checks it.
- [ ] `make check` is clean (gofmt, `go vet`, `go build`, `go test`).
- [ ] Tests cover the changed behavior, or the description says why they cannot.
- [ ] `CHANGELOG.md` has an `Unreleased` entry for user-visible changes, including any server/agent upgrade or migration needed.
- [ ] Schema changes work on a fresh database and on an upgraded one.
- [ ] New routes have a server-side permission check; new NATS subjects are added to `deploy/nats/nats.conf`.
- [ ] Agent changes cross-build for Linux, macOS and Windows (amd64 and arm64).
- [ ] Console changes were checked in both themes.
