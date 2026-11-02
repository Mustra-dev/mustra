// Development-only bridge: expose localhost to a host-run Go server while the
// language engines stay on an internal network with no external route.
import http from 'node:http';
import { pipeline } from 'node:stream';

const upstream = new URL(process.env.UPSTREAM_URL || 'http://script-tools:8091');
const server = http.createServer((req, res) => {
  if (!((req.method === 'POST' && ['/validate', '/complete', '/build'].includes(req.url)) || (req.method === 'GET' && req.url === '/health'))) { res.writeHead(404).end(); return; }
  const target = http.request(new URL(req.url, upstream), { method: req.method, headers: { 'Content-Type': 'application/json' }, timeout: 55000 }, response => {
    res.writeHead(response.statusCode, { 'Content-Type': 'application/json' });
    pipeline(response, res, () => {});
  });
  target.on('timeout', () => target.destroy());
  target.on('error', () => { if (!res.headersSent) res.writeHead(503); res.end(); });
  res.on('close', () => target.destroy());
  pipeline(req, target, () => {});
});
server.requestTimeout = 60000;
server.headersTimeout = 10000;
server.listen(Number(process.env.PORT || 8091), '0.0.0.0');
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { server.close(); server.closeAllConnections(); });
