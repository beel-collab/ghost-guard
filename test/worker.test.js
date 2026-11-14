import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { ghostBasePath } from '../src/worker.js';
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
    assert.equal(response.headers.get('content-security-policy'), "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'");
    assert.equal(response.headers.get('x-frame-options'), 'DENY');
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

test('webhook refuses missing signing configuration and invalid signatures', async (t) => {
  const calls = mockFetch(t);
  const env = envFor({ CLEANUP_ENABLED: 'true', ADMIN_API_URL: 'https://admin.example', ADMIN_API_KEY: 'aaaaaaaaaaaaaaaaaaaaaaaa:' + '0123456789abcdef'.repeat(4) });
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

for (const [name, env] of [['an external origin', envFor()], ['same-zone routing', envFor({ GHOST_ORIGIN: undefined })]]) {
  test(`Ghost receives the resolved client IP, not client-sent X-Forwarded-For, via ${name}`, async (t) => {
    const calls = mockFetch(t);
    const spoofed = { 'X-Forwarded-For': '203.0.113.7' };
    await worker.fetch(signup({ emailType: 'signin' }, spoofed), env);
    await worker.fetch(new Request('https://blog.example/about/', { headers: { 'CF-Connecting-IP': '192.0.2.1', ...spoofed } }), env);
    assert.deepEqual(calls.origin.map((request) => request.headers.get('x-forwarded-for')), ['192.0.2.1', '192.0.2.1']);
  });
}

// Ghost installed in a subfolder, e.g. example.com/blog.

const host = (request) => new URL(request.url).host;

test('signup protection does not depend on the base path, including doubled slashes', async (t) => {
  // Express routes /blog//members/… and /members//api/… to Ghost's handler.
  const paths = ['/blog/members/api/send-magic-link/', '/Blog/Members/API/Send-Magic-Link', '/blog//members/api/send-magic-link',
    '/blog/members//api/send-magic-link', '/members//api/send-magic-link', '//members/api/send-magic-link/'];
  for (const base of [undefined, '/blog', '/blgo', '/blog/..']) {
    t.mock.method(console, 'error', () => {});
    for (const path of paths) {
      const calls = mockFetch(t, { success: false });
      const response = await worker.fetch(signup({}, { 'cf-turnstile-response': 'token' }, `https://blog.example${path}`), envFor({ GHOST_BASE_PATH: base, TURNSTILE_SECRET: 'secret' }));
      assert.equal(response.status, 400, `${base} ${path}`);
      assert.equal(calls.verification.length, 1);
      assert.equal(calls.origin.length, 0);
      t.mock.restoreAll();
    }
  }
});

test('magic links get the confirmation page at any members path, whatever the base path', async (t) => {
  const calls = mockFetch(t);
  for (const base of [undefined, '/blog', '/blgo']) {
    for (const url of ['https://blog.example/blog/members/?token=abc&action=signup', 'https://blog.example/Blog//Members?token=abc&action=subscribe', 'https://blog.example/members/?token=abc&action=signup']) {
      const response = await worker.fetch(new Request(url), envFor({ GHOST_BASE_PATH: base }));
      assert.equal(response.status, 200, `${base} ${url}`);
      assert.match(await response.text(), /Confirm signup/);
    }
  }
  assert.equal(calls.origin.length, 0);
  // The human confirmation is forwarded to Ghost at the subfolder path.
  await worker.fetch(new Request('https://blog.example/blog/members/?token=abc&action=signup', {
    method: 'POST', body: new URLSearchParams({ token: 'abc', action: 'signup' }),
  }), envFor({ GHOST_BASE_PATH: '/blog' }));
  assert.equal(host(calls.origin[0]), 'origin.example');
  assert.equal(new URL(calls.origin[0].url).pathname, '/blog/members/');
});

test('subfolder install: Ghost pages use GHOST_ORIGIN, the rest of the hostname its zone origin', async (t) => {
  const calls = mockFetch(t);
  const env = envFor({ GHOST_BASE_PATH: 'blog' });
  for (const path of ['/blog', '/blog/some-post/', '/BLOG/ghost/', '/pricing', '/blogs/x', '/']) {
    await worker.fetch(new Request(`https://blog.example${path}`, { headers: { 'CF-Connecting-IP': '192.0.2.1', 'X-Forwarded-For': '203.0.113.7' } }), env);
  }
  assert.deepEqual(calls.origin.map(host), ['origin.example', 'origin.example', 'origin.example', 'blog.example', 'blog.example', 'blog.example']);
  assert.ok(calls.origin.every((request) => request.headers.get('x-forwarded-for') === '192.0.2.1'));
});

test('an invalid base path keeps the rest of the site on its zone origin and logs once', async (t) => {
  const calls = mockFetch(t);
  const errors = t.mock.method(console, 'error', () => {});
  const env = envFor({ GHOST_BASE_PATH: '/blog/..' });
  await worker.fetch(new Request('https://blog.example/about/'), env);
  await worker.fetch(new Request('https://blog.example/blog/post/'), env);
  assert.deepEqual(calls.origin.map(host), ['blog.example', 'blog.example']);
  assert.ok(errors.mock.callCount() <= 1);
  // The sidecar has no zone origin: it always uses GHOST_ORIGIN.
  await worker.fetch(new Request('https://blog.example/about/'), { ...env, SIDECAR: true });
  assert.equal(host(calls.origin[2]), 'origin.example');
});

test('a malformed confirmation form is rejected without calling Ghost', async (t) => {
  const calls = mockFetch(t);
  const response = await worker.fetch(new Request('https://blog.example/members/?token=abc&action=signup', {
    method: 'POST',
    headers: { 'content-type': 'multipart/form-data; boundary=----bound' },
    body: 'not a form',
  }), envFor());
  assert.equal(response.status, 400);
  assert.match(await response.text(), /confirmation form was invalid/);
  assert.equal(calls.origin.length, 0);
});

test('the Turnstile script path ignores case and repeated slashes', async () => {
  let seen = '';
  const env = envFor({
    ASSETS: {
      fetch: async (request) => {
        seen = new URL(request.url).pathname;
        return new Response('ok');
      },
    },
  });
  for (const path of ['/Ghost-Guard/Turnstile.JS', '/ghost-guard//turnstile.js', '/ghost-guard/turnstile.js/']) {
    const response = await worker.fetch(new Request(`https://blog.example${path}`), env);
    assert.equal(response.status, 200, path);
    assert.equal(seen, '/ghost-guard/turnstile.js');
  }
});

test('GHOST_BASE_PATH is normalized and rejects values a path could never match', () => {
  for (const [value, expected] of [[undefined, ''], ['', ''], ['/', ''], ['blog', '/blog'], ['/Blog/', '/blog'], [' /news/blog// ', '/news/blog'], ['/actualit%C3%A9s', '/actualit%c3%a9s'], ['/news+views', '/news+views']]) {
    assert.equal(ghostBasePath({ GHOST_BASE_PATH: value }), expected);
  }
  for (const value of ['/blog?x=1', '/blog#top', '/my blog', 'https://example.com/blog', '/..', '/blog/..', '.', '/./blog', '/blog//x', '/blog%']) {
    assert.throws(() => ghostBasePath({ GHOST_BASE_PATH: value }), /GHOST_BASE_PATH/, value);
  }
});

test('subfolder install: lookalike protected paths on the root app are checked, then reach the root app', async (t) => {
  const calls = mockFetch(t, { success: true, hostname: 'blog.example', action: 'ghost_signup' });
  const env = envFor({ GHOST_BASE_PATH: '/blog', CONFIRM_SECRET: 'confirm-secret' });
  await worker.fetch(new Request('https://blog.example/api/teams/7/members?token=abc'), env);
  await worker.fetch(new Request('https://blog.example/app/members?token=abc&action=signup', {
    method: 'POST', body: new URLSearchParams({ token: 'abc', action: 'signup' }),
  }), env);
  await worker.fetch(signup({}, {}, 'https://blog.example/x/members/api/send-magic-link'), env);
  assert.deepEqual(calls.origin.map(host), ['blog.example', 'blog.example', 'blog.example']);
  assert.ok(calls.origin.every((request) => request.headers.get('X-Ghost-Signup-Shield') === null));
  // Ghost's own paths still reach GHOST_ORIGIN.
  await worker.fetch(signup({}, {}, 'https://blog.example/blog/members/api/send-magic-link'), env);
  assert.equal(host(calls.origin[3]), 'origin.example');
});
