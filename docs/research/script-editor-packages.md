# Script editor package research

Verified against primary sources on 2026-09-11. This note distinguishes editor UI, syntax highlighting, syntax parsing, static analysis, and language-aware completion; adopting an editor does not automatically provide the other layers.

For mustra, the recommended direction is CodeMirror 6 for the editor, ShellCheck for shell analysis, and PSScriptAnalyzer for PowerShell analysis. Add Bash Language Server and PowerShell Editor Services for context-sensitive completion. The current `mvdan` syntax gate is a maintained dependency; the custom static completion lists are the part that does not deliver upstream-maintained language intelligence. The sections below provide the evidence and distinguish recommendations from the implementation already in the checkout.

## Browser editor findings

**Recommendation:** retain CodeMirror 6 for mustra's embedded sensor editor. It is a mainstream, actively maintained choice; switching to Monaco would not itself add shell or PowerShell validation. Evaluate language services separately. Monaco is a credible alternative if a broader VS Code-like editing experience becomes a product requirement.

### Maintenance and adoption snapshot

These are the npm registry's current `latest` versions and publication dates, read directly on the verification date. CodeMirror consists of independently versioned packages, so its wrapper version is not a useful proxy for core maintenance.

| Package | Latest | Published (UTC) | npm downloads, 2026-09-04 through 2026-09-10 |
| --- | --- | --- | ---: |
| `@codemirror/view` | 6.43.11 | 2026-09-03 | 10,623,909 |
| `@codemirror/legacy-modes` | 6.5.4 | 2026-09-02 | 2,774,317 |
| `@codemirror/lsp-client` | 6.2.5 | 2026-06-09 | 12,183 |
| `monaco-editor` | 0.56.0 | 2026-07-20 | 6,271,611 |
| `ace-builds` | 1.44.0 | 2026-05-11 | 990,120 |

Version/date sources: [CodeMirror view registry](https://registry.npmjs.org/@codemirror/view), [legacy modes registry](https://registry.npmjs.org/@codemirror/legacy-modes), [LSP client registry](https://registry.npmjs.org/@codemirror/lsp-client), [Monaco registry](https://registry.npmjs.org/monaco-editor), [Ace builds registry](https://registry.npmjs.org/ace-builds).

Download sources: npm's [view count](https://api.npmjs.org/downloads/point/2026-09-04:2026-09-10/@codemirror/view), [legacy modes count](https://api.npmjs.org/downloads/point/2026-09-04:2026-09-10/@codemirror/legacy-modes), [LSP client count](https://api.npmjs.org/downloads/point/2026-09-04:2026-09-10/@codemirror/lsp-client), [Monaco count](https://api.npmjs.org/downloads/point/2026-09-04:2026-09-10/monaco-editor), and [Ace count](https://api.npmjs.org/downloads/point/2026-09-04:2026-09-10/ace-builds).

Downloads are a comparable observation window, not unique developers, deployed sites, or market share. Transitive dependencies, CI, caching, and package granularity distort direct rankings. These numbers support calling CodeMirror and Monaco widely used; they do not establish one universally most-used editor. The newer CodeMirror LSP adapter has much less adoption than the editor core.

Concrete first-party adoption evidence for CodeMirror 6 includes [JupyterLab's current editor extension API](https://jupyterlab.readthedocs.io/en/latest/api/functions/codemirror.EditorExtensionRegistry.getDefaultExtensions.html), [Chrome DevTools' CodeMirror dependencies](https://github.com/ChromeDevTools/devtools-frontend/blob/main/front_end/third_party/codemirror.next/package.json), and [Replit's account of adopting it](https://replit.com/blog/codemirror). Monaco is Microsoft's editor component from VS Code, with an MIT license and a documented public API. [Monaco repository](https://github.com/microsoft/monaco-editor)

### CodeMirror 6

CodeMirror provides modular editing, completion UI, and lint UI. The shell and PowerShell implementations in `@codemirror/legacy-modes` are official ports of stream tokenizers, not full language-service packages. “Legacy” describes their origin; it does not mean the package is abandoned. The September 2026 registry publication confirms continuing package releases, without proving equal maintenance activity in every individual mode. [CodeMirror project](https://codemirror.net/), [legacy mode documentation](https://github.com/codemirror/legacy-modes)

CodeMirror's GitHub repositories were archived in April 2026 **because development moved** to `code.haverbeke.berlin`. Their README files explicitly direct readers there. Do not interpret the GitHub archive banner as end of maintenance. [Migration notice](https://github.com/codemirror/legacy-modes), [current project location](https://code.haverbeke.berlin/codemirror/legacy-modes)

There is now an official `@codemirror/lsp-client`. It connects the editor to a language server through an application-provided transport; a backend server can be proxied over WebSocket, or a suitable language server can run in the browser. Transport setup, reconnection, and server lifecycle remain integration work. This permits future language-aware assistance without replacing the editor. [Official client documentation](https://codemirror.net/docs/ref/#lsp-client), [client README](https://github.com/codemirror/lsp-client)

The project documents community help through its forum and issue tracker. The evidence establishes active open-source maintenance, not a contractual support SLA. [CodeMirror project](https://codemirror.net/)

### Monaco

Monaco is maintained under Microsoft's organization and is a mainstream choice with a documented public API. Its source includes [PowerShell language definitions](https://github.com/microsoft/monaco-editor/blob/main/src/languages/definitions/powershell/powershell.ts) and [shell language definitions](https://github.com/microsoft/monaco-editor/blob/main/src/languages/definitions/shell/shell.ts). These definitions provide tokenization rather than PowerShell or POSIX shell validation; the richer built-in language-feature packages are CSS, HTML, JSON, and TypeScript. [Current changelog](https://github.com/microsoft/monaco-editor/blob/main/CHANGELOG.md)

Advice that Monaco always requires a third-party LSP adapter is outdated: 0.55.0 added native LSP support and 0.56.0 exposes typed LSP client and transport APIs. A language server is still required for the corresponding language intelligence. The AMD build is deprecated; current integration should use supported ESM entry points. These changes make a switch substantive integration work in a console without a frontend bundler. [Monaco changelog](https://github.com/microsoft/monaco-editor/blob/main/CHANGELOG.md)

### Ace

Ace remains a maintained, established browser editor: its current package was published in May 2026, and its project documents broad language highlighting and an embedding API. It is community developed under the BSD license. There is no evidence here that switching from the existing CodeMirror implementation to Ace would improve validation or reduce language-service integration work. [Ace project](https://ace.c9.io/), [Ace repository](https://github.com/ajaxorg/ace)

## Validation and language-service packages

Checked on 2026-09-11. Release dates below come from the projects' live GitHub release APIs; branch activity was checked separately so an older release is not mistaken for abandonment. Stars and download counts are adoption signals, not unique-user counts or support guarantees.

| Component | Verified maintenance | Adoption and role |
| --- | --- | --- |
| ShellCheck | [v0.11.0, 2025-08-04](https://github.com/koalaman/shellcheck/releases/tag/v0.11.0); [default-branch commit 2026-06-11](https://api.github.com/repos/koalaman/shellcheck/commits?per_page=1) | About [40,000 GitHub stars](https://api.github.com/repos/koalaman/shellcheck). Included in [GitHub's Ubuntu 24.04 runner image](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md). Established static analyzer for sh/bash; suitable for syntax diagnostics and broader shell warnings. |
| `mvdan.cc/sh/v3` | [v3.14.1, 2026-09-06](https://github.com/mvdan/sh/releases/tag/v3.14.1); [default-branch commit 2026-09-09](https://api.github.com/repos/mvdan/sh/commits?per_page=1) | About [9,000 GitHub stars](https://api.github.com/repos/mvdan/sh). Contains the parser used by shfmt; its [syntax package](https://pkg.go.dev/mvdan.cc/sh/v3/syntax) can select POSIX syntax. A credible embedded Go parser, but not a replacement for ShellCheck's semantic analysis. |
| PSScriptAnalyzer | [1.25.0, 2026-03-20](https://github.com/PowerShell/PSScriptAnalyzer/releases/tag/1.25.0); [default-branch commit 2026-08-26](https://api.github.com/repos/PowerShell/PSScriptAnalyzer/commits?per_page=1) | Microsoft-authored. [PowerShell Gallery](https://www.powershellgallery.com/packages/PSScriptAnalyzer/1.25.0) reports 13,672,377 total package downloads and 5,856,499 downloads of 1.25.0. Used for diagnostics in the [official VS Code PowerShell extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode.PowerShell), and included in GitHub's runner image linked above. |
| PowerShell Editor Services | [v4.7.0, 2026-06-25](https://github.com/PowerShell/PowerShellEditorServices/releases/tag/v4.7.0); [default-branch commit 2026-09-09](https://api.github.com/repos/PowerShell/PowerShellEditorServices/commits?per_page=1) | The language-server backend used by the [official VS Code PowerShell extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode.PowerShell). Provides IntelliSense and integrates PSScriptAnalyzer. Strongest first-party option for full PowerShell editor intelligence. |
| Bash Language Server | [5.6.0, 2025-04-13](https://github.com/bash-lsp/bash-language-server/releases/tag/server-5.6.0), corroborated by [npm metadata](https://registry.npmjs.org/bash-language-server); [default-branch commit 2026-08-19](https://api.github.com/repos/bash-lsp/bash-language-server/commits?per_page=1) | Used by [Bash IDE for VS Code](https://marketplace.visualstudio.com/items?itemName=mads-hartmann.bash-ide-vscode), supports completion/navigation and connects to ShellCheck and shfmt. Community-maintained; recent development is visible despite the older stable release. |

### Implications for mustra

Recommendation: retain CodeMirror 6, use ShellCheck as the main upstream shell analyzer, and use PSScriptAnalyzer for PowerShell diagnostics. Use Bash Language Server and PowerShell Editor Services when richer, upstream-maintained completion is required. These are distinct roles: editor packages display information, analyzers diagnose source, and language services provide context-sensitive completion and navigation. The [Bash Language Server README](https://github.com/bash-lsp/bash-language-server) and [PowerShell Editor Services README](https://github.com/PowerShell/PowerShellEditorServices) document that composition.

The existing `mvdan` addition is maintained and defensible for a fast, embedded syntax gate. It does not need to be discarded as unsupported. For a broader editor experience, ShellCheck adds established lint rules, and language servers avoid making mustra maintain its own expanding vocabulary of commands. The current `tools/script-editor/completions.js` contains a hand-maintained static list; CodeMirror supplies the completion mechanism, not that language knowledge. This is an assessment of the current checkout, not an upstream claim.

Preserve the platform's actual interpreter when configuring analysis. For Linux/macOS, explicitly select sh using [ShellCheck's `--shell` option](https://github.com/koalaman/shellcheck/blob/master/shellcheck.1.md). A shebang must not change the tab's declared runtime. Treat parse failures as save-blocking errors; decide separately which lint warnings merit advisory display. This is a proposed product policy, not a claim that every ShellCheck warning is a syntax failure.

PowerShell's support boundary matters here: [PSScriptAnalyzer documentation](https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/overview?view=ps-modules) lists Windows PowerShell 5.1 and PowerShell 7.2.11+ on Windows/Linux/macOS. [PowerShell Editor Services](https://github.com/PowerShell/PowerShellEditorServices) targets supported PowerShell 7+ and supports Windows PowerShell 5.1 on a best-effort basis. Do not interpret a successful check under PowerShell 7 on Linux as proof that Windows-only modules and APIs exist on a Windows 5.1 endpoint.

These backend tools add deployment dependencies: ShellCheck is an executable; PSScriptAnalyzer is a PowerShell module; Bash Language Server requires Node; PowerShell Editor Services runs inside PowerShell. The official PowerShell extension provides only limited highlighting in a browser without a PowerShell backend, as its [platform support section](https://marketplace.visualstudio.com/items?itemName=ms-vscode.PowerShell) explains. An editor swap alone cannot supply full PowerShell validation. Supporting the language service on the control-plane side does not change which interpreter runs on managed endpoints.

Here, “supported” means maintained projects with published releases, documented compatibility, and issue/support channels. It does not imply a commercial SLA. The official PowerShell extension's [support policy](https://github.com/PowerShell/vscode-powershell/blob/main/SUPPORT.md) explicitly limits support to its listed documentation and issue channels.

This investigation adds research notes only; no application changes were made as part of the online verification.
