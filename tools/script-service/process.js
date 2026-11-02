import { spawn } from 'node:child_process';

export function startProcess(command, args, cwd) {
  // No inherited service credentials, user profiles, or deployment environment.
  return spawn(command, args, {
    cwd, detached: process.platform !== 'win32', stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      PATH: process.env.PATH, HOME: cwd, TMPDIR: cwd,
      PSModulePath: process.env.PSModulePath || '/opt/microsoft/powershell/7/Modules',
      POWERSHELL_TELEMETRY_OPTOUT: '1', DOTNET_CLI_TELEMETRY_OPTOUT: '1',
      BASH_IDE_LOG_LEVEL: 'error', SHELLCHECK_PATH: '', SHFMT_PATH: '',
      BACKGROUND_ANALYSIS_MAX_FILES: '0', EXPLAINSHELL_ENDPOINT: '',
    },
  });
}

export function stopProcess(child) {
  if (!child.pid) return;
  try {
    if (process.platform === 'win32') child.kill('SIGKILL');
    else process.kill(-child.pid, 'SIGKILL');
  } catch (error) { if (error.code !== 'ESRCH') throw error; }
}

export function runProcess(command, args, { input, cwd, signal, timeout = 15000, maxOutput = 2 * 1024 * 1024 }) {
  return new Promise((resolve, reject) => {
    const child = startProcess(command, args, cwd);
    let stdout = '', size = 0, settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      stopProcess(child);
      if (error) { reject(error); }
      else resolve(value);
    };
    const abort = () => finish(new Error('Script analysis cancelled'));
    const timer = setTimeout(() => finish(new Error('Script analysis timed out')), timeout);
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) { abort(); return; }
    child.on('error', error => finish(error));
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', data => {
      size += data.length;
      if (size > maxOutput) finish(new Error('Script analysis output limit exceeded'));
      else stdout += data.toString();
    });
    // Source text can appear in diagnostics; never put subprocess output in logs.
    child.stderr.on('data', data => { size += data.length; if (size > maxOutput) finish(new Error('Script analysis output limit exceeded')); });
    child.stdin.on('error', error => finish(error));
    child.on('close', code => finish(null, { code, stdout }));
    child.stdin.end(input);
  });
}
