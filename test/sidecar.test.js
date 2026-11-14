import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { gzipSync, deflateSync, brotliCompressSync } from 'node:zlib';
import { createGuardServer } from '../sidecar/server.mjs';

async function listen(t, server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
async function setup(t, env = {}) {
  const calls = [];
  const origin = await listen(t, http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    calls.push({ url: req.url, method: req.method, headers: req.headers, body });
    if (req.method === 'GET' && req.url.startsWith('/members/?')) {
      res.writeHead(302, { location: '/', 'set-cookie': ['session=one; Path=/; HttpOnly', 'other=two; Path=/'] });
      res.end();
    } else {
      res.writeHead(201, { 'content-type': 'application/json' });
      res.end('{}');
    }
  }));
  const guard = await listen(t, createGuardServer({ GHOST_ORIGIN: origin, ...env }));
  return { calls, guard };
}
const send = (guard, body, headers = {}) => fetch(`${guard}/members/api/send-magic-link/`, {
  method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify({ email: 'reader@work.example', emailType: 'signup', ...body }),
});

test('sidecar shares signup limits, does not trust spoofed client IPs, and leaves signin untouched', async (t) => {
  const { guard, calls } = await setup(t, { SIGNUP_IP_LIMIT: '1' });
  assert.equal((await send(guard, {}, { 'CF-Connecting-IP': '192.0.2.1', 'X-Forwarded-For': '192.0.2.1' })).status, 201);
  const blocked = await send(guard, { email: 'other@work.example' }, { 'CF-Connecting-IP': '192.0.2.2', 'X-Forwarded-For': '192.0.2.2' });
  assert.equal(blocked.status, 429);
  assert.ok(Number(blocked.headers.get('retry-after')) > 3590);
  const signin = await send(guard, { emailType: 'signin' });
  assert.equal(signin.status, 201);
  assert.equal(calls.length, 2);
  assert.equal(JSON.parse(calls[1].body).emailType, 'signin');
});

test('trusted proxy mode honors the explicitly overwritten X-Forwarded-For', async (t) => {
  const { guard } = await setup(t, { SIGNUP_IP_LIMIT: '1', TRUST_PROXY: 'true' });
  assert.equal((await send(guard, {}, { 'X-Forwarded-For': '192.0.2.1' })).status, 201);
  assert.equal((await send(guard, { email: 'other@work.example' }, { 'X-Forwarded-For': '192.0.2.2' })).status, 201);
  assert.equal((await send(guard, { email: 'third@work.example' }, { 'X-Forwarded-For': '192.0.2.1' })).status, 429);
});

test('sidecar verifies signup tokens through the shared handler, including its trusted hostname and action', async (t) => {
  const originalFetch = globalThis.fetch;
  let verificationCount = 0;
  t.mock.method(globalThis, 'fetch', async (input, init) => {
    if (String(input) === 'https://challenges.cloudflare.com/turnstile/v0/siteverify') {
      verificationCount++;
      const token = new URLSearchParams(init.body).get('response');
      return Response.json({ success: token === 'valid', hostname: '127.0.0.1', action: 'ghost_signup' });
    }
    return originalFetch(input, init);
  });
  const { guard, calls } = await setup(t, { TURNSTILE_SECRET: 'secret' });
  assert.equal((await send(guard, {})).status, 400);
  assert.equal((await send(guard, {}, { 'cf-turnstile-response': 'bad' })).status, 400);
  assert.equal(calls.length, 0);
  assert.equal((await send(guard, { 'cf-turnstile-response': 'valid' })).status, 201);
  assert.equal(calls.length, 1);
  assert.equal(verificationCount, 2);
});

test('sidecar serves the injection script and confirmation still works with no JS, preserving cookies', async (t) => {
  const { guard, calls } = await setup(t, { TURNSTILE_SECRET: 'secret' });
  const script = await fetch(`${guard}/ghost-guard/turnstile.js`);
  assert.equal(script.status, 200);
  assert.match(script.headers.get('content-type'), /javascript/);
  assert.match(await script.text(), /window.fetch =/);
  const url = `${guard}/members/?token=abc&action=signup`;
  const page = await fetch(url, { headers: { 'X-Ghost-Signup-Shield': 'sidecar-local' } });
  assert.equal(page.status, 200);
  assert.doesNotMatch(await page.text(), /<script|turnstile|\.submit\(/i);
  assert.equal(calls.length, 0);
  const confirmed = await fetch(url, { method: 'POST', body: new URLSearchParams({ token: 'abc', action: 'signup' }), redirect: 'manual' });
  assert.equal(confirmed.status, 302);
  assert.deepEqual(confirmed.headers.getSetCookie(), ['session=one; Path=/; HttpOnly', 'other=two; Path=/']);
  assert.equal(calls[0].method, 'GET');
  assert.equal((await fetch(url, { method: 'HEAD' })).status, 200);
});

for (const [encoding, compress] of [['gzip', gzipSync], ['deflate', deflateSync], ['br', brotliCompressSync]]) {
  test(`sidecar relays ${encoding} origin responses with matching body and headers`, async (t) => {
    const payload = JSON.stringify({ site: { title: 'Publication', plans: Array(80).fill({ name: 'Membership' }) } });
    const compressed = compress(Buffer.from(payload));
    let acceptedEncoding;
    const origin = await listen(t, http.createServer((req, res) => {
      acceptedEncoding = req.headers['accept-encoding'];
      // Deliberately compress even though the sidecar requests identity.
      res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': encoding, 'content-length': String(compressed.length) });
      res.end(compressed);
    }));
    const guard = await listen(t, createGuardServer({ GHOST_ORIGIN: origin }));
    const response = await fetch(`${guard}/members/api/site/`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-encoding'), null);
    assert.equal(Number(response.headers.get('content-length')), Buffer.byteLength(payload));
    assert.equal(await response.text(), payload);
    assert.equal(acceptedEncoding, 'identity');
    const head = await fetch(`${guard}/members/api/site/`, { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(head.headers.get('content-encoding'), encoding);
    assert.equal(Number(head.headers.get('content-length')), compressed.length);
    assert.equal(await head.text(), '');
  });
}

test('trusted HTTPS scheme survives signup and confirmation behind an HTTP sidecar', async (t) => {
  const seen = [];
  const origin = await listen(t, http.createServer(async (req, res) => {
    for await (const chunk of req) { void chunk; }
    seen.push(req.headers['x-forwarded-proto']);
    // Model Ghost's SSL redirect, which runs before the members handler.
    if (req.headers['x-forwarded-proto'] !== 'https') {
      res.writeHead(301, { location: `https://${req.headers.host}${req.url}` });
    } else if (req.method === 'POST') {
      res.writeHead(201, { 'content-type': 'application/json' });
    } else {
      res.writeHead(302, { location: '/' });
    }
    res.end();
  }));
  const guard = await listen(t, createGuardServer({ GHOST_ORIGIN: origin, TRUST_PROXY: 'true' }));
  assert.equal((await send(guard, {}, { 'X-Forwarded-Proto': 'https' })).status, 201);
  const confirmation = await fetch(`${guard}/members/?token=abc&action=signup`, {
    method: 'POST', body: new URLSearchParams({ token: 'abc', action: 'signup' }),
    headers: { 'X-Forwarded-Proto': 'https' }, redirect: 'manual',
  });
  assert.equal(confirmation.status, 302);
  assert.equal(confirmation.headers.get('location'), '/');
  assert.deepEqual(seen, ['https', 'https']);
});

test('untrusted clients cannot forge the forwarded protocol', async (t) => {
  const { guard, calls } = await setup(t);
  assert.equal((await send(guard, {}, { 'X-Forwarded-Proto': 'https' })).status, 201);
  assert.equal(calls[0].headers['x-forwarded-proto'], 'http');
});

test('sidecar applies IP attempts before verifying case-variant signup requests', async (t) => {
  const { guard, calls } = await setup(t, { TURNSTILE_SECRET: 'secret', SIGNUP_IP_LIMIT: '1' });
  const sendMixedCase = () => fetch(`${guard}/Members/API/Send-Magic-Link/`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'reader@work.example', emailType: 'signup' }),
  });
  assert.equal((await sendMixedCase()).status, 400);
  assert.equal((await sendMixedCase()).status, 429);
  assert.equal(calls.length, 0);
});
