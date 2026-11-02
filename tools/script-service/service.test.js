import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createService } from './server.js';
import { completionItems, lspOffset } from './completion.js';
import { shellOffset } from './analysis.js';

async function listen(server) {
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return `http://127.0.0.1:${server.address().port}`;
}
const post = (base, path, body) => fetch(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

test('service accepts source data only and rejects unsupported/oversized requests', async t => {
  const calls = [];
  const server = createService({ analyzer: async (platform, script) => { calls.push({ platform, script }); return []; }, sessions: { close() {} } });
  t.after(() => { server.closeAllConnections(); server.close(); });
  const base = await listen(server);
  assert.equal((await post(base, '/validate', { commands: { windows: 'Write-Output "ok"' } })).status, 200);
  assert.deepEqual(calls, [{ platform: 'windows', script: 'Write-Output "ok"' }]);
  assert.equal((await post(base, '/validate', { commands: { python: 'pass' } })).status, 400);
  assert.equal((await post(base, '/validate', { commands: { linux: 'x'.repeat(256 * 1024 + 1) } })).status, 400);
  assert.equal((await post(base, '/execute', { command: 'whoami' })).status, 404);
  for (const body of [null, [], 'text']) assert.equal((await post(base, '/validate', body)).status, 400);
});

test('unavailable analyzer never reports a successful check', async t => {
  const server = createService({ analyzer: async () => { throw new Error('missing tool'); }, sessions: { close() {} } });
  t.after(() => { server.closeAllConnections(); server.close(); });
  assert.equal((await post(await listen(server), '/validate', { commands: { windows: 'Write-Output 1' } })).status, 503);
});

test('positions preserve UTF-16 and ShellCheck tab columns', () => {
  assert.equal(lspOffset('# 😀\nGet-Ch', { line: 1, character: 6 }), 11);
  assert.equal(shellOffset('# 😀\n\techo $var', 2, 14), 11);
  assert.throws(() => lspOffset('text', { line: 1, character: 0 }));
  assert.deepEqual(completionItems('Get-Ch', [{ label: 'Get-ChildItem', textEdit: { range: { start: { line: 0, character: 0 }, end: { line: 0, character: 6 } }, newText: 'Get-ChildItem' } }])[0], { label: 'Get-ChildItem', detail: '', kind: undefined, text: 'Get-ChildItem', snippet: false, from: 0, to: 6 });
});

test('Python validation carries language to the isolated analyzer', async () => {
  const seen=[];
  const server=createService({analyzer:async (...args)=>{seen.push([args[0],args[3]]);return [];}});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    const response=await fetch(`http://127.0.0.1:${server.address().port}/validate`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({commands:{windows:'print(1)'},languages:{windows:'python'}})});
    assert.equal(response.status,200);assert.deepEqual(seen,[['windows','python']]);
  } finally {server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
