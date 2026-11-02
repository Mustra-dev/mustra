# Script editor assets

The console embeds a CodeMirror 6 editor with shell and PowerShell language
modes. The generated bundle and dependency licenses are committed under
`internal/server/static/vendor/`; normal Go builds and deployments need no
Node toolchain or network access for these assets.

To update the editor, edit `editor.js` or the pinned dependencies, then run
from this directory:

```sh
npm ci
npm run build
```

Commit the source, lockfile, generated bundle, and license notices together.
The server versions the bundle by content hash. Language modes provide highlighting. CodeMirror autocomplete displays results
from Bash Language Server and PowerShell Editor Services through the Go API;
there are no custom command lists. CodeMirror lint displays syntax errors and
advisories from ShellCheck and PSScriptAnalyzer. The save API repeats validation
before persistence. See `../script-service/README.md` for the service, limits,
PowerShell 5.1 compatibility, and real-engine tests.

Run the completion adapter regression tests with `npm test`.
