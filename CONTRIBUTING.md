# Contributing to mustra

Bug reports, ideas, and patches are all welcome.

## Sign your commits (DCO)

Every contribution must carry a `Signed-off-by:` line. Git adds it for you:

```sh
git commit -s -m "your message"
```

That line is the [Developer Certificate of Origin](https://developercertificate.org/):
you're stating you wrote the change, or otherwise have the right to submit it
under this project's license.

**Why this matters here:** mustra is AGPL-3.0, and every contribution stays
under that license. The sign-off records, commit by commit, that each change
was yours to contribute under it: one line per commit, no CLA to sign.

Security fixes are the exception to working in public: report them
privately as described in [SECURITY.md](SECURITY.md). Everyone taking part
is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Take an issue before working on it

Assign an issue to yourself before you start on it, and open one first
for work that has none. Check its assignees and the open pull requests
before starting: two people fixing the same issue in the same hour is how
a finished pull request ends up closed as a duplicate.

## Before opening a pull request

- `make check` should be clean. It runs gofmt, `go vet`, `go build` and
  `go test`, which is exactly what CI runs on Linux and macOS.
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) has the local setup.
- Match the surrounding code: comments explain *why*, not *what*.
- Keep changes focused — one concern per pull request.
- Add an `Unreleased` entry to [CHANGELOG.md](CHANGELOG.md) for anything an
  operator would notice.

## License

Contributions are made under AGPL-3.0-only, the same license as the project.
