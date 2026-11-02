import { createMessageConnection, StreamMessageReader, StreamMessageWriter } from 'vscode-jsonrpc/node';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { startProcess, stopProcess } from './process.js';

const bashConfig = { backgroundAnalysisMaxFiles: 0, includeAllWorkspaceSymbols: false, explainshellEndpoint: '', shellcheckPath: '', shfmt: { path: '' } };
const powershellConfig = { scriptAnalysis: { enable: false }, enableProfileLoading: false };

export function lspOffset(script, position) {
  const lines = script.split('\n');
  if (!position || !Number.isInteger(position.line) || !Number.isInteger(position.character) || position.line < 0 || position.line >= lines.length || position.character < 0 || position.character > lines[position.line].length) throw new Error('Invalid completion position');
  return lines.slice(0, position.line).reduce((sum, text) => sum + text.length + 1, 0) + position.character;
}

export function completionItems(script, result) {
  const items = Array.isArray(result) ? result : result?.items || [];
  return items.slice(0, 200).map(item => {
    const edit = item.textEdit;
    const range = edit?.range || edit?.replace;
    return {
      label: item.label, detail: item.detail || '', kind: item.kind,
      text: edit?.newText ?? item.insertText ?? item.label,
      snippet: item.insertTextFormat === 2,
      ...(range ? { from: lspOffset(script, range.start), to: lspOffset(script, range.end) } : {}),
    };
  });
}

class CompletionWorker {
  constructor(platform) {
    this.platform = platform;
    this.lastUsed = Date.now();
    this.busy = false;
    this.version = 0;
    this.closed = false;
    this.ready = this.start();
    // Initialization can fail before the first caller awaits it.
    this.ready.catch(() => {});
  }
  async start() {
    this.cwd = await mkdtemp(join(tmpdir(), 'mustra-completion-'));
    if (this.closed) { await rm(this.cwd, { recursive: true, force: true }); throw new Error('Completion session closed'); }
    const windows = this.platform === 'windows';
    const args = windows
      ? ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', process.env.MUSTRA_PSES_SCRIPT || '/opt/pses/PowerShellEditorServices/Start-EditorServices.ps1', '-Stdio', '-LanguageServiceOnly', '-LogPath', this.cwd]
      : [fileURLToPath(new URL('./node_modules/bash-language-server/out/cli.js', import.meta.url)), 'start'];
    this.child = startProcess(windows ? 'pwsh' : process.execPath, args, this.cwd);
    this.child.on('error', () => this.close());
    this.child.on('exit', () => this.close());
    let output = 0;
    const boundOutput = data => { output += data.length; if (output > 8 * 1024 * 1024) this.close(); };
    this.child.stdout.on('data', boundOutput);
    this.child.stderr.on('data', boundOutput);
    this.resetOutput = () => { output = 0; };
    this.connection = createMessageConnection(new StreamMessageReader(this.child.stdout), new StreamMessageWriter(this.child.stdin));
    this.connection.onRequest('workspace/configuration', params => params.items.map(item => item.section === 'bashIde' ? bashConfig : powershellConfig));
    this.connection.onRequest('client/registerCapability', () => null);
    this.connection.onRequest('window/workDoneProgress/create', () => null);
    this.connection.onNotification('textDocument/publishDiagnostics', params => {
      if (params.uri === this.uri && params.version === this.documentReady?.version) {
        this.documentReady.resolve(); this.documentReady = null;
      }
    });
    this.connection.onClose(() => this.close());
    this.connection.listen();
    const rootUri = pathToFileURL(this.cwd).href;
    await this.connection.sendRequest('initialize', {
      processId: process.pid, rootUri, workspaceFolders: [{ uri: rootUri, name: 'Sensor' }],
      capabilities: { workspace: { configuration: true }, textDocument: { completion: { completionItem: { snippetSupport: true } } } },
      initializationOptions: { enableProfileLoading: false, initialWorkingDirectory: this.cwd, shellIntegrationScript: '' },
    });
    this.connection.sendNotification('initialized', {});
    this.connection.sendNotification('workspace/didChangeConfiguration', { settings: { bashIde: bashConfig, powershell: powershellConfig } });
    this.uri = pathToFileURL(join(this.cwd, windows ? 'sensor.ps1' : 'sensor.sh')).href;
  }
  async complete(script, position, signal) {
    if (this.busy) throw Object.assign(new Error('Completion is busy; try again'), { status: 429 });
    this.busy = true;
    this.lastUsed = Date.now();
    const timer = setTimeout(() => this.close(), 20000);
    const abort = () => this.close();
    signal?.addEventListener('abort', abort, { once: true });
    try {
      if (signal?.aborted) throw new Error('Completion cancelled');
      await this.ready;
      if (this.closed) throw new Error('Completion session closed');
      this.resetOutput();
      // Bash initializes configuration asynchronously and publishes the document
      // version when its syntax tree is ready. Do not complete against old text.
      const documentReady = this.platform === 'windows' ? Promise.resolve() : new Promise((resolve, reject) => {
        this.documentReady = { version: this.version + 1, resolve, reject };
      });
      if (!this.version) {
        this.connection.sendNotification('textDocument/didOpen', { textDocument: { uri: this.uri, languageId: this.platform === 'windows' ? 'powershell' : 'shellscript', version: ++this.version, text: script } });
      } else {
        this.connection.sendNotification('textDocument/didChange', { textDocument: { uri: this.uri, version: ++this.version }, contentChanges: [{ text: script }] });
      }
      await documentReady;
      const result = await this.connection.sendRequest('textDocument/completion', { textDocument: { uri: this.uri }, position, context: { triggerKind: 1 } });
      return completionItems(script, result);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      this.busy = false;
      this.lastUsed = Date.now();
    }
  }
  close() {
    if (this.closed) return;
    this.closed = true;
    this.documentReady?.reject(new Error('Completion session closed'));
    this.documentReady = null;
    this.connection?.dispose();
    if (this.child) stopProcess(this.child);
    if (this.cwd) rm(this.cwd, { recursive: true, force: true }).catch(() => {});
  }
}

export class CompletionSessions {
  constructor({ max = 4, idle = 120000 } = {}) {
    this.max = max;
    this.idle = idle;
    this.workers = new Map();
    this.timer = setInterval(() => this.prune(), 15000);
    this.timer.unref();
  }
  prune() {
    for (const [key, worker] of this.workers) {
      if (worker.closed || (!worker.busy && Date.now() - worker.lastUsed > this.idle)) { worker.close(); this.workers.delete(key); }
    }
  }
  async complete(session, platform, script, position, signal) {
    lspOffset(script, position);
    this.prune();
    const key = `${session}:${platform}`;
    let worker = this.workers.get(key);
    if (!worker) {
      if (this.workers.size >= this.max) {
        const oldest = [...this.workers].filter(([, w]) => !w.busy).sort((a, b) => a[1].lastUsed - b[1].lastUsed)[0];
        if (!oldest) throw Object.assign(new Error('Completion capacity reached'), { status: 429 });
        oldest[1].close(); this.workers.delete(oldest[0]);
      }
      worker = new CompletionWorker(platform);
      this.workers.set(key, worker);
    }
    return worker.complete(script, position, signal);
  }
  close() { clearInterval(this.timer); for (const worker of this.workers.values()) worker.close(); this.workers.clear(); }
}
