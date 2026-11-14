import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';
import { MemoryRateLimiter } from '../src/rate-limit.js';

const endpoint = 'https://blog.example/members/api/send-magic-link/';
const verified = { success: true, hostname: 'blog.example', action: 'ghost_signup' };
const envFor = (overrides = {}) => ({ GHOST_ORIGIN: 'https://origin.example', LOCAL_RATE_LIMITER: new MemoryRateLimiter(), ...overrides });
function signup(body = {}, headers = {}, url = endpoint) {
  return new Request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'CF-Connecting-IP': '192.0.2.1', ...headers },
    body: JSON.stringify({ email: 'reader@work.example', emailType: 'signup', ...body }),
  });
}
function mockFetch(t, result = verified) {
  const calls = { verification: [], origin: [] };
  t.mock.method(globalThis, 'fetch', async (input, init) => {
    if (String(input) === 'https://challenges.cloudflare.com/turnstile/v0/siteverify') {
      calls.verification.push(init);
      if (result instanceof Error) throw result;
      return Response.json(result);
    }
    calls.origin.push(input instanceof Request ? input : new Request(input, init));
    return Response.json({ sent: true }, { status: 201 });
  });
  return calls;
}

test('signup without a secret skips Turnstile and keeps other Portal fields', async (t) => {
  const calls = mockFetch(t);
  const response = await worker.fetch(signup({ name: 'Reader', newsletters: [{ id: 'n1' }] }), envFor());
  assert.equal(response.status, 201);
  assert.equal(calls.verification.length, 0);
  assert.deepEqual(await calls.origin[0].json(), { email: 'reader@work.example', emailType: 'signup', name: 'Reader', newsletters: [{ id: 'n1' }] });
});

for (const source of ['header', 'body']) {
  test(`valid ${source} token is verified and removed before forwarding`, async (t) => {
    const calls = mockFetch(t);
    const request = source === 'header' ? signup({}, { 'cf-turnstile-response': 'valid-token' }) : signup({ 'cf-turnstile-response': 'valid-token' });
    const response = await worker.fetch(request, envFor({ TURNSTILE_SECRET: 'secret' }));
    assert.equal(response.status, 201);
    const fields = new URLSearchParams(calls.verification[0].body);
    assert.equal(fields.get('secret'), 'secret');
    assert.equal(fields.get('response'), 'valid-token');
    assert.equal(fields.get('remoteip'), '192.0.2.1');
    assert.equal(calls.origin[0].headers.has('cf-turnstile-response'), false);
    assert.equal(Object.hasOwn(await calls.origin[0].json(), 'cf-turnstile-response'), false);
  });
}

for (const emailType of ['signup', 'subscribe', undefined, 'SIGNIN', 'unknown']) {
  test(`signup classification protects ${String(emailType)} without a token`, async (t) => {
    const calls = mockFetch(t);
    const response = await worker.fetch(signup({ emailType }), envFor({ TURNSTILE_SECRET: 'secret' }));
    assert.equal(response.status, 400);
    assert.match((await response.json()).errors[0].message, /verify/);
    assert.equal(calls.origin.length, 0);
    assert.equal(calls.verification.length, 0);
  });
}

for (const result of [{ success: false }, { ...verified, hostname: 'attacker.example' }, { ...verified, action: 'other' }, new Error('network failure')]) {
  test(`Turnstile fails closed for ${JSON.stringify(result)}`, async (t) => {
    const calls = mockFetch(t, result);
    const response = await worker.fetch(signup({}, { 'cf-turnstile-response': 'bad-token' }), envFor({ TURNSTILE_SECRET: 'secret' }));
    assert.equal(response.status, 400);
    assert.equal(calls.origin.length, 0);
  });
}

test('explicit signin passes through byte for byte, without Turnstile or rate storage', async (t) => {
  const calls = mockFetch(t);
  const raw = '{ "email": "reader@work.example", "emailType": "signin", "includeOTC": true }';
  const request = new Request(endpoint, { method: 'POST', body: raw, headers: { 'content-type': 'application/json', 'x-custom': 'kept' } });
  assert.equal((await worker.fetch(request, { GHOST_ORIGIN: 'https://origin.example', TURNSTILE_SECRET: 'secret' })).status, 201);
  assert.equal(await calls.origin[0].text(), raw);
  assert.equal(calls.origin[0].headers.get('x-custom'), 'kept');
  assert.equal(calls.verification.length, 0);
});

test('default IP quota is shared across email addresses; trailing slash is optional', async (t) => {
  const calls = mockFetch(t);
  const env = envFor();
  for (let i = 0; i < 5; i++) assert.equal((await worker.fetch(signup({ email: `reader${i}@work.example` }), env)).status, 201);
  const response = await worker.fetch(signup({ email: 'sixth@work.example' }, {}, endpoint.slice(0, -1)), env);
  assert.equal(response.status, 429);
  assert.ok(Number(response.headers.get('retry-after')) > 3590);
  assert.match((await response.json()).errors[0].message, /Too many/);
  assert.equal(calls.origin.length, 5);
});

test('email quota normalizes case and whitespace and applies across IPs', async (t) => {
  const calls = mockFetch(t);
  const env = envFor();
  for (let i = 0; i < 3; i++) {
    assert.equal((await worker.fetch(signup({}, { 'CF-Connecting-IP': `192.0.2.${i}` }), env)).status, 201);
  }
  const response = await worker.fetch(signup({ email: ' Reader@Work.Example ' }, { 'CF-Connecting-IP': '192.0.2.99' }), env);
  assert.equal(response.status, 429);
  assert.ok(Number(response.headers.get('retry-after')) > 86390);
  assert.equal(calls.origin.length, 3);
});

test('invalid challenges do not consume another reader\'s email quota', async (t) => {
  const calls = mockFetch(t);
  const env = envFor({ TURNSTILE_SECRET: 'secret', SIGNUP_EMAIL_LIMIT: '1' });
  for (let i = 0; i < 4; i++) assert.equal((await worker.fetch(signup(), env)).status, 400);
  assert.equal((await worker.fetch(signup({}, { 'cf-turnstile-response': 'valid' }), env)).status, 201);
  assert.equal(calls.origin.length, 1);
});

test('missing rate storage fails closed instead of silently disabling protection', async (t) => {
  const calls = mockFetch(t);
  const response = await worker.fetch(signup(), { GHOST_ORIGIN: 'https://origin.example' });
  assert.equal(response.status, 503);
  assert.equal(calls.origin.length, 0);
});

test('malformed JSON cannot bypass signup protection', async (t) => {
  const calls = mockFetch(t);
  for (const body of ['{', 'null', '[]', '"signin"']) {
    assert.equal((await worker.fetch(new Request(endpoint, { method: 'POST', body }), envFor())).status, 400);
  }
  assert.equal(calls.origin.length, 0);
});

test('all signup confirmation pages require a form POST and have no script or auto-submit', async (t) => {
  const calls = mockFetch(t);
  for (const action of ['signup', 'subscribe', 'signup-paid']) {
    const url = `https://blog.example/members/?token=abc&action=${action}`;
    const response = await worker.fetch(new Request(url), envFor({ TURNSTILE_SECRET: 'secret', TURNSTILE_SITE_KEY: 'old-key' }));
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.match(html, /<form method="post"/);
    assert.match(html, /Confirm signup/);
    assert.doesNotMatch(html, /<script|turnstile|onload=|\.submit\(|requestSubmit|http-equiv="refresh"/i);
    assert.equal(response.headers.get('cache-control'), 'no-store, no-cache, must-revalidate');
    const head = await worker.fetch(new Request(url, { method: 'HEAD' }), envFor());
    assert.equal(head.status, 200);
    assert.equal(await head.text(), '');
  }
  assert.equal(calls.origin.length, 0);
});

test('confirmation POST and signin magic links do not need Turnstile', async (t) => {
  const calls = mockFetch(t);
  const env = envFor({ TURNSTILE_SECRET: 'secret' });
  assert.equal((await worker.fetch(new Request('https://blog.example/members/?token=abc&action=signup', {
    method: 'POST', body: new URLSearchParams({ token: 'abc', action: 'signup' }),
  }), env)).status, 201);
  assert.equal(calls.origin[0].method, 'GET');
  assert.equal(new URL(calls.origin[0].url).searchParams.get('token'), 'abc');
  await worker.fetch(new Request('https://blog.example/members/?token=abc&action=signin'), env);
  assert.equal(calls.origin.length, 2);
  assert.equal(calls.verification.length, 0);
});

test('legacy unsubscribe configuration can only label, preserving and deduplicating labels', async (t) => {
  const calls = mockFetch(t);
  const body = JSON.stringify({ member: { current: { id: 'm1', email: 'reader@work.example', status: 'free', labels: [{ name: 'existing' }, { name: 'signup-shield-review' }] } } });
  const timestamp = String(Date.now());
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode('webhook-secret'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const hash = [...new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body + timestamp)))].map((b) => b.toString(16).padStart(2, '0')).join('');
  const response = await worker.fetch(new Request('https://blog.example/signup-shield/webhooks/member-added', {
    method: 'POST', body, headers: { 'X-Ghost-Signature': `sha256=${hash}, t=${timestamp}` },
  }), envFor({ CLEANUP_ENABLED: 'true', ADMIN_API_URL: 'https://admin.example', ADMIN_API_KEY: 'id:0123456789abcdef', WEBHOOK_SECRET: 'webhook-secret', CLEANUP_MODE: 'unsubscribe' }));
  assert.equal(response.status, 200);
  assert.equal((await response.json()).action, 'label');
  assert.equal(calls.origin[0].method, 'PUT');
  assert.deepEqual(await calls.origin[0].json(), { members: [{ labels: [{ name: 'existing' }, { name: 'signup-shield-review' }] }] });
});

test('webhook refuses missing signing configuration and invalid signatures', async (t) => {
  const calls = mockFetch(t);
  const env = envFor({ CLEANUP_ENABLED: 'true', ADMIN_API_URL: 'https://admin.example', ADMIN_API_KEY: 'id:0123456789abcdef' });
  const request = () => new Request('https://blog.example/signup-shield/webhooks/member-added', { method: 'POST', body: '{}' });
  assert.equal((await worker.fetch(request(), env)).status, 503);
  assert.equal((await worker.fetch(request(), { ...env, WEBHOOK_SECRET: 'secret' })).status, 401);
  assert.equal(calls.origin.length, 0);
});

for (const path of ['/members/api/Send-Magic-Link/', '/MEMBERS/API/SEND-MAGIC-LINK', '/Members/api/send-magic-link/']) {
  test(`case-variant signup route is protected: ${path}`, async (t) => {
    const calls = mockFetch(t);
    const env = envFor({ TURNSTILE_SECRET: 'secret', SIGNUP_IP_LIMIT: '1' });
    const url = `https://blog.example${path}`;
    assert.equal((await worker.fetch(signup({}, {}, url), env)).status, 400);
    assert.equal((await worker.fetch(signup({}, {}, url), env)).status, 429);
    assert.equal(calls.verification.length, 0);
    assert.equal(calls.origin.length, 0);
  });
}

test('case-variant confirmation paths still require a click', async (t) => {
  const calls = mockFetch(t);
  for (const path of ['/Members/', '/MEMBERS']) {
    const response = await worker.fetch(new Request(`https://blog.example${path}?token=abc&action=signup`), envFor());
    assert.equal(response.status, 200);
    assert.match(await response.text(), /<form method="post"/);
  }
  assert.equal(calls.origin.length, 0);
});

test('origin forwarding cannot replace authority through a network-path reference', async (t) => {
  const calls = mockFetch(t);
  const env = envFor({ GHOST_ORIGIN: 'https://origin.example:8443', CONFIRM_SECRET: 'private-secret' });
  for (const path of ['//collector.invalid/capture?token=abc', '///collector.invalid/capture', '/members/api/site/?x=1']) {
    const response = await worker.fetch(new Request(`https://blog.example${path}`, { headers: { cookie: 'session=private' } }), env);
    assert.equal(response.status, 201);
    const forwarded = calls.origin.at(-1);
    const target = new URL(forwarded.url);
    assert.equal(target.origin, 'https://origin.example:8443');
    assert.equal(target.pathname + target.search, path);
    assert.equal(forwarded.headers.get('host'), 'origin.example:8443');
  }
});

test('IP attempts throttle invalid-token floods before additional Siteverify calls', async (t) => {
  const calls = mockFetch(t, { success: false });
  const env = envFor({ TURNSTILE_SECRET: 'secret', SIGNUP_IP_LIMIT: '1' });
  assert.equal((await worker.fetch(signup({}, { 'cf-turnstile-response': 'bad' }), env)).status, 400);
  for (let i = 0; i < 9; i++) {
    const response = await worker.fetch(signup({}, { 'cf-turnstile-response': 'bad' }), env);
    assert.equal(response.status, 429);
    assert.ok(Number(response.headers.get('retry-after')) > 3590);
  }
  assert.equal(calls.verification.length, 1);
  assert.equal(calls.origin.length, 0);
  assert.equal(env.LOCAL_RATE_LIMITER.counters.size, 1);
  assert.ok([...env.LOCAL_RATE_LIMITER.counters.keys()].every((key) => key.startsWith('ip:')));
});

test('missing-token floods consume only the sender IP quota, leaving the reader email quota available', async (t) => {
  const calls = mockFetch(t);
  const env = envFor({ TURNSTILE_SECRET: 'secret', SIGNUP_IP_LIMIT: '1', SIGNUP_EMAIL_LIMIT: '1' });
  assert.equal((await worker.fetch(signup(), env)).status, 400);
  assert.equal((await worker.fetch(signup(), env)).status, 429);
  assert.equal((await worker.fetch(signup({}, { 'CF-Connecting-IP': '192.0.2.2', 'cf-turnstile-response': 'valid' }), env)).status, 201);
  assert.equal(calls.verification.length, 1);
  assert.equal(calls.origin.length, 1);
});

test('email-quota rejections still count as IP attempts', async (t) => {
  const calls = mockFetch(t);
  const env = envFor({ SIGNUP_IP_LIMIT: '3', SIGNUP_EMAIL_LIMIT: '1' });
  assert.equal((await worker.fetch(signup(), env)).status, 201);
  assert.equal((await worker.fetch(signup(), env)).status, 429);
  assert.equal((await worker.fetch(signup({ email: 'other@work.example' }), env)).status, 201);
  assert.equal((await worker.fetch(signup({ email: 'third@work.example' }), env)).status, 429);
  assert.equal(calls.origin.length, 2);
});
