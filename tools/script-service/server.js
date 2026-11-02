import http from 'node:http';
import { runProcess } from './process.js';
import { pathToFileURL } from 'node:url';
import { analyze } from './analysis.js';
import { CompletionSessions } from './completion.js';

const platforms = new Set(['linux', 'darwin', 'windows']);
export const maxScriptBytes = 256 * 1024;
export function checkScript(platform, script) {
  if (!platforms.has(platform) || typeof script !== 'string' || Buffer.byteLength(script) > maxScriptBytes) throw Object.assign(new Error('Invalid platform or script size'), { status: 400 });
}

export function createService({ analyzer = analyze, sessions = new CompletionSessions() } = {}) {
  let active = 0;
  let building = false;
  const server = http.createServer(async (req, res) => {
    const send = (status, body) => { if (!res.destroyed) { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); } };
    if (req.method === 'GET' && req.url === '/health') { send(200, { ok: true }); return; }
    if (req.method !== 'POST' || !['/validate', '/complete', '/build'].includes(req.url)) { send(404, { error: 'Not found' }); return; }
    if (active >= 4) { send(429, { error: 'Script tools are busy' }); return; }
    active++;
    const controller = new AbortController();
    const abort = () => { if (!res.writableEnded) controller.abort(); };
    res.on('close', abort);
    try {
      let size = 0;
      const chunks = [];
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 1024 * 1024) throw Object.assign(new Error('Request too large'), { status: 413 });
        chunks.push(chunk);
      }
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString()); } catch { throw Object.assign(new Error('Invalid JSON'), { status: 400 }); }
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw Object.assign(new Error('Invalid request'), { status: 400 });
      if (req.url === '/build') {
        checkScript(body.os, body.source);
        if (!['amd64', 'arm64'].includes(body.arch)) throw Object.assign(new Error('Invalid architecture'), {status:400});
        if (building) throw Object.assign(new Error('Go builder busy; retry shortly'), {status:429});
        building = true;
        try {
          const result = await runProcess('/usr/local/bin/sensor-builder', [], {input:JSON.stringify(body), cwd:'/tmp', signal:controller.signal, timeout:50000, maxOutput:24*1024*1024});
          if (result.code !== 0) throw new Error('Builder unavailable');
          send(200, JSON.parse(result.stdout));
        } finally { building = false; }
      } else if (req.url === '/validate') {
        if (!body.commands || Array.isArray(body.commands) || typeof body.commands !== 'object' || Object.keys(body.commands).length > 3) throw Object.assign(new Error('Invalid commands'), { status: 400 });
        const diagnostics = {};
        for (const [platform, script] of Object.entries(body.commands)) checkScript(platform, script);
        // Sequential analysis bounds the number of expensive processes per request.
        for (const [platform, script] of Object.entries(body.commands)) diagnostics[platform] = await analyzer(platform, script, controller.signal, body.languages?.[platform]);
        send(200, { diagnostics });
      } else {
        checkScript(body.platform, body.script);
        if (typeof body.session !== 'string' || !/^[\w:-]{1,180}$/.test(body.session)) throw Object.assign(new Error('Invalid editor session'), { status: 400 });
        const items = await sessions.complete(body.session, body.platform, body.script, body.position, controller.signal);
        send(200, { items });
      }
    } catch (error) { send(error.status || 503, { error: error.status ? error.message : 'Script tools unavailable; try again shortly' }); }
    finally { active--; res.removeListener('close', abort); }
  });
  server.requestTimeout = 30000;
  server.headersTimeout = 10000;
  server.on('close', () => sessions.close());
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = createService();
  server.listen(Number(process.env.PORT || 8091), process.env.HOST || '127.0.0.1', () => console.log('Script tools ready'));
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { server.close(); server.closeAllConnections(); });
}
