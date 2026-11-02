import test from 'node:test';
import assert from 'node:assert/strict';
import { access } from 'node:fs/promises';
import { once } from 'node:events';
import { createService } from './server.js';

test('real analyzers and language services', { skip: process.env.MUSTRA_SCRIPT_TOOLS_INTEGRATION !== '1', timeout: 120000 }, async t => {
  const server = createService();
  t.after(() => { server.closeAllConnections(); server.close(); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = async (path, body) => {
    const response = await fetch(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const result = await response.json(); assert.equal(response.status, 200, JSON.stringify(result)); return result;
  };
  for (const platform of ['linux', 'darwin']) {
    const result = await post('/validate', { commands: { [platform]: '[CmdletBinding()]\nparam([int]$Days = 30)' } });
    assert(result.diagnostics[platform].some(d => d.blocking));
  }
  const warnings = await post('/validate', { commands: { linux: 'echo $HOME' } });
  assert(warnings.diagnostics.linux.some(d => d.message.startsWith('SC2086')));
  assert(warnings.diagnostics.linux.every(d => !d.blocking));
  const invalid = await post('/validate', { commands: { windows: 'param([int]$Days = )' } });
  assert(invalid.diagnostics.windows.some(d => d.blocking));
  const incompatible = await post('/validate', { commands: { windows: '$x = $true ? 1 : 2' } });
  assert(incompatible.diagnostics.windows.some(d => d.blocking && d.message.includes('PSUseCompatibleSyntax')));
  const marker = `/tmp/mustra-validation-must-not-execute-${process.pid}`;
  const valid = await post('/validate', { commands: { windows: `New-Item -Path '${marker}' -ItemType File | Out-Null`, linux: `touch '${marker}'` } });
  assert(Object.values(valid.diagnostics).flat().every(d => !d.blocking));
  await assert.rejects(access(marker));
  const complete = async (session, platform, script) => {
    const lines = script.split('\n');
    return (await post('/complete', { session, platform, script, position: { line: lines.length - 1, character: lines.at(-1).length } })).items;
  };
  const cmdlets = await complete('user-a:editor', 'windows', 'Get-Ch');
  assert(cmdlets.some(c => c.label.includes('Get-ChildItem')), JSON.stringify(cmdlets));
  const parameters = await complete('user-a:editor', 'windows', 'Get-ChildItem -Pa');
  assert(parameters.some(c => c.label.includes('Path')), JSON.stringify(parameters));
  const variables = await complete('user-a:editor', 'windows', '$sensorPrivateVariable = 1\n$sensorPriv');
  assert(variables.some(c => c.label.includes('sensorPrivateVariable')), JSON.stringify(variables));
  const otherUser = await complete('user-b:editor', 'windows', '$sensorPriv');
  assert(!otherUser.some(c => c.label.includes('sensorPrivateVariable')));
  const functions = await complete('user-a:editor', 'linux', 'sensor_report() { printf "ok"; }\nsensor_');
  assert(functions.some(c => c.label === 'sensor_report'), JSON.stringify(functions));
});

test('Python syntax is checked without execution; Batch and WQL report their limits', {skip: !process.env.MUSTRA_SCRIPT_TOOLS_INTEGRATION}, async () => {
  const { analyze } = await import('./analysis.js');
  const invalid=await analyze('windows','def broken(:\n pass',new AbortController().signal,'python');
  assert(invalid.some(d=>d.blocking));
  const valid=await analyze('linux','raise RuntimeError("must not execute")',new AbortController().signal,'python');
  assert.equal(valid.length,0);
  const recent=await analyze('linux','type Result[T = str] = list[T]',new AbortController().signal,'python');
  assert.equal(recent.length,0,'Python validation must use the bundled 3.13 grammar');
  for(const language of ['batch','wql']){
    const diagnostics=await analyze('windows','test',new AbortController().signal,language);
    assert(diagnostics.length && diagnostics.every(d=>!d.blocking));
  }
});

test('isolated Go builder compiles all six targets and rejects dependencies', { skip: process.env.MUSTRA_SCRIPT_TOOLS_INTEGRATION !== '1', timeout: 300000 }, async () => {
  const { runProcess } = await import('./process.js');
  const build = async request => {
    const result = await runProcess('/usr/local/bin/sensor-builder', [], { input: JSON.stringify(request), cwd: '/tmp', timeout: 50000, maxOutput: 24*1024*1024 });
    assert.equal(result.code, 0);
    return JSON.parse(result.stdout);
  };
  for (const os of ['linux','darwin','windows']) for (const arch of ['amd64','arm64']) {
    const result = await build({os,arch,source:'package main; import "fmt"; func main(){fmt.Println("ok")}'});
    assert.equal(result.error, undefined);
    assert.ok(Buffer.from(result.data,'base64').length > 0);
  }
  const result = await build({os:'linux',arch:'amd64',source:'package main; import _ "example.com/dependency";func main(){}'});
  assert.match(result.error,/standard-library/);
});
