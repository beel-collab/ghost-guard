import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { gzipSync, deflateSync, brotliCompressSync } from 'node:zlib';
import { createGuardServer, parseTrustedProxies } from '../sidecar/server.mjs';

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

test('trusted proxy mode uses the entry the proxy appended, not client-sent ones', async (t) => {
  const { guard, calls } = await setup(t, { SIGNUP_IP_LIMIT: '1', TRUST_PROXY: 'true' });
  // nginx $proxy_add_x_forwarded_for appends the real peer after client values.
  assert.equal((await send(guard, {}, { 'X-Forwarded-For': '203.0.113.1, 192.0.2.1' })).status, 201);
  assert.equal(calls[0].headers['x-forwarded-for'], '192.0.2.1');
  assert.equal((await send(guard, { email: 'other@work.example' }, { 'X-Forwarded-For': '203.0.113.2, 192.0.2.1' })).status, 429);
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

test('upstream X-Forwarded-For is always rebuilt from the resolved client IP', async (t) => {
  const { guard, calls } = await setup(t);
  assert.equal((await send(guard, { emailType: 'signin' }, { 'X-Forwarded-For': '203.0.113.99', 'CF-Connecting-IP': '203.0.113.88' })).status, 201);
  assert.equal(calls[0].headers['x-forwarded-for'], calls[0].headers['cf-connecting-ip']);
  assert.notEqual(calls[0].headers['x-forwarded-for'], '203.0.113.99');
  const trusted = await setup(t, { TRUST_PROXY: 'true' });
  assert.equal((await send(trusted.guard, {}, { 'X-Forwarded-For': '192.0.2.1' })).status, 201);
  assert.equal(trusted.calls[0].headers['x-forwarded-for'], '192.0.2.1');
});

for (const emailType of ['signup', 'signin']) {
  test(`chunked ${emailType} requests discard hop headers and retain their JSON body`, async (t) => {
    const { guard, calls } = await setup(t);
    const body = JSON.stringify({ email: 'reader@work.example', emailType });
    const response = await new Promise((resolve, reject) => {
      const request = http.request(`${guard}/members/api/send-magic-link/`, {
        method: 'POST', headers: { 'content-type': 'application/json', connection: 'x-discard, keep-alive', 'x-discard': 'private-hop', 'x-retain': 'end-to-end' },
      }, (res) => {
        res.resume();
        res.on('end', () => resolve(res));
      });
      request.on('error', reject);
      request.write(body.slice(0, 15));
      request.end(body.slice(15));
    });
    assert.equal(response.statusCode, 201);
    assert.equal(calls[0].body, body);
    assert.equal(calls[0].headers['x-discard'], undefined);
    assert.equal(calls[0].headers['x-retain'], 'end-to-end');
  });
}

test('response hop headers are not relayed to the client', async (t) => {
  const origin = await listen(t, http.createServer((_req, res) => {
    res.writeHead(200, { connection: 'x-discard, close', 'x-discard': 'upstream-hop', 'content-type': 'application/json' });
    res.end('{}');
  }));
  const guard = await listen(t, createGuardServer({ GHOST_ORIGIN: origin }));
  const response = await fetch(`${guard}/members/api/site/`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-discard'), null);
  assert.equal(await response.text(), '{}');
});

test('TRUSTED_PROXIES: only a listed peer may set the client IP and scheme', async (t) => {
  const listed = await setup(t, { SIGNUP_IP_LIMIT: '1', TRUSTED_PROXIES: '127.0.0.1' });
  assert.equal((await send(listed.guard, {}, { 'X-Forwarded-For': '192.0.2.1', 'X-Forwarded-Proto': 'https' })).status, 201);
  assert.equal(listed.calls[0].headers['x-forwarded-for'], '192.0.2.1');
  assert.equal(listed.calls[0].headers['x-forwarded-proto'], 'https');

  // The test client connects from 127.0.0.1, which is not in this list.
  const unlisted = await setup(t, { SIGNUP_IP_LIMIT: '1', TRUSTED_PROXIES: '10.0.0.0/8' });
  assert.equal((await send(unlisted.guard, {}, { 'X-Forwarded-For': '192.0.2.1', 'X-Forwarded-Proto': 'https' })).status, 201);
  assert.equal(unlisted.calls[0].headers['x-forwarded-for'], '127.0.0.1');
  assert.equal(unlisted.calls[0].headers['x-forwarded-proto'], 'http');
  assert.equal((await send(unlisted.guard, { email: 'other@work.example' }, { 'X-Forwarded-For': '192.0.2.2' })).status, 429);
});

test('TRUSTED_PROXIES: the client is the rightmost entry that is not one of our proxies', async (t) => {
  const { guard, calls } = await setup(t, { TRUSTED_PROXIES: '127.0.0.1, 198.51.100.0/24' });
  // Client-sent value, then the real client, then a trusted load balancer.
  await send(guard, { emailType: 'signin' }, { 'X-Forwarded-For': '203.0.113.9, 192.0.2.9, 198.51.100.5' });
  assert.equal(calls[0].headers['x-forwarded-for'], '192.0.2.9');
});

test('TRUSTED_PROXIES rejects entries it cannot parse', () => {
  for (const bad of ['nginx', '10.0.0.0/33', '::1/129', '10.0.0.0/8/1', '10.0.0.0/x']) {
    assert.throws(() => parseTrustedProxies(bad), /TRUSTED_PROXIES/);
    assert.throws(() => createGuardServer({ TRUSTED_PROXIES: bad }), /TRUSTED_PROXIES/);
  }
  assert.doesNotThrow(() => parseTrustedProxies('127.0.0.1, ::1, 172.16.0.0/12, fd00::/8'));
});

test('legacy TRUST_PROXY=true warns at startup', (t) => {
  const warnings = t.mock.method(console, 'warn', () => {});
  createGuardServer({ TRUST_PROXY: 'true' });
  assert.match(String(warnings.mock.calls[0].arguments), /TRUSTED_PROXIES/);
});

test('TRUSTED_PROXIES: ports are stripped and junk entries fall back to the peer', async (t) => {
  const { guard, calls } = await setup(t, { TRUSTED_PROXIES: '127.0.0.1' });
  await send(guard, { emailType: 'signin' }, { 'X-Forwarded-For': '192.0.2.1:5555' });
  await send(guard, { emailType: 'signin' }, { 'X-Forwarded-For': '[2001:db8::1]:443' });
  await send(guard, { emailType: 'signin' }, { 'X-Forwarded-For': 'unknown' });
  assert.deepEqual(calls.map((call) => call.headers['x-forwarded-for']), ['192.0.2.1', '2001:db8::1', '127.0.0.1']);
});

test('a port in X-Forwarded-For does not create a fresh IP quota', async (t) => {
  const { guard } = await setup(t, { SIGNUP_IP_LIMIT: '1', TRUSTED_PROXIES: '127.0.0.1' });
  assert.equal((await send(guard, {}, { 'X-Forwarded-For': '192.0.2.1:1000' })).status, 201);
  assert.equal((await send(guard, { email: 'other@work.example' }, { 'X-Forwarded-For': '192.0.2.1:2000' })).status, 429);
});

test('forwarded headers from an unlisted peer log one warning', async (t) => {
  const warnings = t.mock.method(console, 'warn', () => {});
  const { guard } = await setup(t, { TRUSTED_PROXIES: '10.0.0.1' });
  await send(guard, { emailType: 'signin' }, { 'X-Forwarded-For': '192.0.2.1' });
  await send(guard, { emailType: 'signin' }, { 'X-Forwarded-Proto': 'https' });
  assert.equal(warnings.mock.callCount(), 1);
  assert.match(String(warnings.mock.calls[0].arguments), /127\.0\.0\.1.*TRUSTED_PROXIES/);
});
