import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
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
