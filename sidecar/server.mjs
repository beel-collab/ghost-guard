#!/usr/bin/env node
/** Shared Worker logic, adapted to Node 22+ HTTP and per-process rate storage. */
import http from 'node:http';
import net from 'node:net';
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

function plainAddress(value) {
  const address = String(value || '').trim();
  return address.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i)?.[1] ?? address;
}

// TRUSTED_PROXIES: comma-separated addresses or CIDR ranges, e.g.
// "127.0.0.1,172.16.0.0/12". Throws on an entry it cannot parse.
export function parseTrustedProxies(value) {
  const list = new net.BlockList();
  for (const entry of String(value || '').split(',').map((item) => item.trim()).filter(Boolean)) {
    const [address, prefix, extra] = entry.split('/');
    const version = net.isIP(address);
    const type = version === 6 ? 'ipv6' : 'ipv4';
    const bits = Number(prefix);
    if (!version || extra !== undefined || (prefix !== undefined && (!/^\d+$/.test(prefix) || bits > (version === 6 ? 128 : 32)))) {
      throw new Error(`TRUSTED_PROXIES: invalid entry "${entry}"`);
    }
    if (prefix === undefined) list.addAddress(address, type);
    else list.addSubnet(address, bits, type);
  }
  return list;
}

// Decides which peers may set X-Forwarded-For/-Proto and which XFF entries are
// our own proxies. TRUST_PROXY=true (legacy) trusts every peer and uses the
// rightmost entry.
function proxyTrust(env) {
  if (env.TRUSTED_PROXIES) {
    const list = parseTrustedProxies(env.TRUSTED_PROXIES);
    const listed = (value) => {
      const address = plainAddress(value);
      const version = net.isIP(address);
      return version !== 0 && list.check(address, version === 6 ? 'ipv6' : 'ipv4');
    };
    return { peer: listed, hop: listed };
  }
  if (env.TRUST_PROXY === 'true') {
    console.warn('ghost-guard: TRUST_PROXY=true trusts X-Forwarded-For from any peer; set TRUSTED_PROXIES to your proxy addresses instead');
    return { peer: () => true, hop: () => false };
  }
  return { peer: () => false, hop: () => false };
}

// Walk X-Forwarded-For from the right past our own proxies; the first other
// entry is the client. Untrusted peers are the client themselves.
function resolveClient(req, trust) {
  const peer = plainAddress(req.socket.remoteAddress);
  if (!trust.peer(peer)) return { ip: peer, trusted: false };
  const hops = String(req.headers['x-forwarded-for'] || '').split(',').map(plainAddress).filter(Boolean);
  for (let i = hops.length - 1; i >= 0; i--) {
    if (!trust.hop(hops[i])) return { ip: hops[i], trusted: true };
  }
  return { ip: hops[0] || peer, trusted: true };
}

export function createGuardServer(env = process.env) {
  const trust = proxyTrust(env);
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
      const { ip, trusted } = resolveClient(req, trust);
      stripHopByHop(headers);
      headers.delete('content-length');
      headers.set('CF-Connecting-IP', ip || 'unknown');
      headers.set('X-Forwarded-For', ip || 'unknown');
      headers.delete('X-Ghost-Signup-Shield');
      const socketProtocol = req.socket.encrypted ? 'https' : 'http';
      const forwardedProtocol = String(req.headers['x-forwarded-proto'] || '').trim().toLowerCase();
      headers.set('X-Forwarded-Proto', trusted && ['http', 'https'].includes(forwardedProtocol)
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
