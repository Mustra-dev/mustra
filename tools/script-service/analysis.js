import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runProcess } from './process.js';

// ShellCheck columns count Unicode characters and expand tabs to 8 columns.
export function shellOffset(script, line, column) {
  const lines = script.split('\n');
  const index = Math.max(0, Math.min(line - 1, lines.length - 1));
  let offset = lines.slice(0, index).reduce((sum, text) => sum + text.length + 1, 0);
  let visual = 1;
  for (const char of lines[index]) {
    if (visual >= column) break;
    visual += char === '\t' ? 8 - ((visual - 1) % 8) : 1;
    offset += char.length;
  }
  return offset;
}

export async function analyze(platform, script, signal, language = platform === "windows" ? "powershell" : "shell") {
  if (!script.trim()) return [];
  if (language === 'go') return [{from:0,to:0,severity:'info',blocking:false,message:'Go is compiled for both architectures before saving. Single-file standard-library programs only.'}];
  const cwd = await mkdtemp(join(tmpdir(), 'mustra-analysis-'));
  try {
    if (language === 'python') {
      const program = `import ast,json,sys
s=sys.stdin.read()
d=[]
try: ast.parse(s)
except SyntaxError as e:
 lines=s.splitlines(keepends=True)
 offset=sum(len(x.encode('utf-16-le'))//2 for x in lines[:(e.lineno or 1)-1])+max(0,(e.offset or 1)-1)
 d=[dict(from_=offset,to=offset+1,severity='error',blocking=True,message=str(e))]
print(json.dumps([{'from' if k=='from_' else k:v for k,v in x.items()} for x in d]))`;
      const result = await runProcess(process.env.MUSTRA_PYTHON_ANALYZER || 'python3', ['-I', '-S', '-c', program], { input: script, cwd, signal });
      if (result.code !== 0) throw new Error('Python analyzer unavailable');
      return JSON.parse(result.stdout);
    }
    if (language === 'batch' || language === 'wql') return [{from:0,to:0,severity:'info',blocking:false,message:language === 'wql' ? 'Query classes and properties are checked on the selected endpoint.' : 'Batch has no complete pre-execution syntax validation; test on an endpoint.'}];
    if (language === 'powershell') {
      const result = await runProcess('pwsh', ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', fileURLToPath(new URL('./analyze.ps1', import.meta.url))], { input: JSON.stringify({ script }), cwd, signal });
      if (result.code !== 0) throw new Error('PowerShell analyzer unavailable');
      return JSON.parse(result.stdout).diagnostics;
    }
    if (language !== 'shell') throw new Error('Unsupported language');
    const result = await runProcess('shellcheck', ['--norc', '--shell=sh', '--format=json1', '-'], { input: script, cwd, signal });
    if (![0, 1].includes(result.code)) throw new Error('ShellCheck unavailable');
    return JSON.parse(result.stdout).comments.slice(0, 200).map(item => ({
      from: shellOffset(script, item.line, item.column), to: shellOffset(script, item.endLine, item.endColumn),
      blocking: item.level === 'error' && item.code >= 1000 && item.code < 1100,
      severity: item.level === 'info' || item.level === 'style' ? 'info' : 'warning',
      message: `SC${item.code}: ${item.message}`, source: 'ShellCheck',
    })).map(item => ({ ...item, severity: item.blocking ? 'error' : item.severity }));
  } finally { await rm(cwd, { recursive: true, force: true }); }
}
