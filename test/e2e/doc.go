// Package e2e is the end-to-end test of a real compose stack: first-run
// setup, enrollment of systemd endpoints through the console's install
// one-liner, the attack checks of the security review, signed updates,
// software deployment, patching and a browser crawl of the console.
//
// The tests are behind the e2e build tag because they need a running stack
// (deploy/init.sh --start), Docker and, for the crawl, Node with
// Playwright. docs/DEVELOPMENT.md describes how to run them;
// .github/workflows/e2e.yml runs them on every pull request.
package e2e
