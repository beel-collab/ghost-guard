#!/usr/bin/env node
/** Shared Worker logic, adapted to Node 22+ HTTP and per-process rate storage. */
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import worker from '../src/worker.js';
import { MemoryRateLimiter } from '../src/rate-limit.js';
import { LocalLabelQueue } from '../src/webhook.js';

const script = await readFile(new URL('../public/ghost-guard/turnstile.js', import.meta.url), 'utf8');

function stripHopByHop(headers) {
  const nominated = (headers.get('connection') || '').split(',').map((name) => name.trim()).filter(Boolean);
  for (const name of [...nominated, 'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade']) {
    headers.delete(name);
  }
}

export function createGuardServer(env = process.env) {
  const workerEnv = {
    ...env,
    GHOST_ORIGIN: (env.GHOST_ORIGIN || 'http://127.0.0.1:2368').replace(/\/+$/, ''),
    LOCAL_RATE_LIMITER: new MemoryRateLimiter(),
    LOCAL_MEMBER_LABELLER: new LocalLabelQueue(),
    ASSETS: {
      fetch: async (request) => new Response(request.method === 'HEAD' ? null : script, {
        headers: { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'public, max-age=300', 'x-content-type-options': 'nosniff' },
      }),
    },
  };

  return http.createServer(async (req, res) => {
    try {
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 1024 * 1024) {
          res.writeHead(413, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ errors: [{ message: 'Request is too large.' }] }));
          return;
        }
        chunks.push(chunk);
      }
      const body = Buffer.concat(chunks);
      const headers = new Headers();
      for (const [key, value] of Object.entries(req.headers)) {
        if (value) headers.set(key, Array.isArray(value) ? value.join(', ') : value);
      }
      // Use the entry the trusted proxy added: the rightmost one. Proxies that
      // append (nginx's $proxy_add_x_forwarded_for) keep client-sent values on
      // the left; proxies that overwrite leave a single entry.
      const ip = env.TRUST_PROXY === 'true'
        ? String(req.headers['x-forwarded-for'] || req.socket.remoteAddress).split(',').at(-1).trim()
        : req.socket.remoteAddress;
      stripHopByHop(headers);
      headers.delete('content-length');
      headers.set('CF-Connecting-IP', ip || 'unknown');
      headers.set('X-Forwarded-For', ip || 'unknown');
      headers.delete('X-Ghost-Signup-Shield');
      const socketProtocol = req.socket.encrypted ? 'https' : 'http';
      const forwardedProtocol = String(req.headers['x-forwarded-proto'] || '').trim().toLowerCase();
      headers.set('X-Forwarded-Proto', env.TRUST_PROXY === 'true' && ['http', 'https'].includes(forwardedProtocol)
        ? forwardedProtocol : socketProtocol);
      headers.set('Accept-Encoding', 'identity');
      const method = req.method || 'GET';
      const request = new Request(`http://${req.headers.host || 'localhost'}${req.url}`, {
        method,
        headers,
        body: method === 'GET' || method === 'HEAD' || !body.length ? undefined : body,
      });
      const response = await worker.fetch(request, workerEnv);
      const responseBody = method === 'HEAD' || response.body === null ? null : Buffer.from(await response.arrayBuffer());
      const responseHeaders = new Headers(response.headers);
      stripHopByHop(responseHeaders);
      const outgoing = Object.fromEntries(responseHeaders);
      // Native fetch decodes these encodings but keeps their upstream headers.
      // Normalize even if an origin ignores our Accept-Encoding: identity.
      if (responseBody !== null) {
        const encodings = (response.headers.get('content-encoding') || '').split(',').map((value) => value.trim().toLowerCase());
        if (encodings.every((value) => ['gzip', 'x-gzip', 'deflate', 'br'].includes(value))) {
          delete outgoing['content-encoding'];
        }
        outgoing['content-length'] = String(responseBody.length);
      }
      const cookies = responseHeaders.getSetCookie();
      if (cookies.length) outgoing['set-cookie'] = cookies;
      res.writeHead(response.status, outgoing);
      res.end(responseBody ?? undefined);
    } catch (error) {
      // Avoid logging request URLs/bodies, which may contain magic-link tokens.
      console.error('ghost-guard proxy error:', error.message);
      res.writeHead(502, { 'content-type': 'text/plain' });
      res.end('signup-shield proxy error');
    }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT || 8787);
  createGuardServer().listen(port, () => console.log(`ghost-guard sidecar listening on :${port}`));
}
