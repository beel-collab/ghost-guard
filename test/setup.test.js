import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';
import { MemoryRateLimiter } from '../src/rate-limit.js';
import {
  SetupStore, SETUP_FAILURE_LIMIT, mergeCodeInjection, mergeConfig, GUARD_START, GUARD_END,
} from '../src/setup.js';

const ZONE = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const ACCOUNT = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const SITEKEY = '0x4AAAAAABBBBBCCCCCDDDDD';
const TURNSTILE_SECRET = 'turnstile-secret-SENTINEL';
const SETUP_TOKEN = 'setup-token-SENTINEL-value';
const CF_TOKEN = 'cf-token-SENTINEL-value';
const ADMIN_ID = '0123456789abcdef01234567';
const ADMIN_SECRET = 'deadbeef'.repeat(8);
const ADMIN_KEY = `${ADMIN_ID}:${ADMIN_SECRET}`;
const CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'";

function memoryStore() {
  const data = new Map();
  const store = new SetupStore({
    storage: {
      async get(key) { return data.get(key); },
      async put(key, value) { data.set(key, value); },
      async delete(key) { data.delete(key); },
    },
  });
  return {
    data,
    SETUP_STORE: {
      idFromName(name) { return name; },
      get() { return { fetch: (input, init) => store.fetch(new Request(input, init)) }; },
    },
  };
}

function baseEnv(store, overrides = {}) {
  return {
    SETUP_TOKEN,
    SETUP_STORE: store.SETUP_STORE,
    LOCAL_RATE_LIMITER: new MemoryRateLimiter(),
    GHOST_ORIGIN: 'https://origin.example',
    ...overrides,
  };
}

function formRequest(path, fields, { ip = '192.0.2.10', token = SETUP_TOKEN } = {}) {
  const body = new URLSearchParams();
  if (token != null) body.set('setup_token', token);
  for (const [key, value] of Object.entries(fields)) {
    if (value != null) body.set(key, value);
  }
  return new Request(`https://ghost-guard.tester.workers.dev${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': ip },
    body,
  });
}

const happyFields = {
  intent: 'run',
  ghost_url: 'https://example.com/blog',
  admin_api_key: ADMIN_KEY,
  cf_api_token: CF_TOKEN,
  webhook: 'on',
};

function world() {
  const state = {
    head: '<!-- keep-before --><script>analytics</script><!-- keep-after -->',
    routes: [],
    widgets: [],
    webhooks: [],
    secrets: [],
    calls: [],
    failWidgets: false,
    failSecrets: false,
    scriptStatus: 200,
    scriptBody: 'window.__ghostGuardTurnstile = true;',
    webhookRejectIntegration: false,
    routePosts: 0,
    widgetPosts: 0,
    webhookPosts: 0,
  };
  return state;
}

function install(t, state) {
  t.mock.method(globalThis, 'fetch', async (input, init = {}) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    const method = (init.method || 'GET').toUpperCase();
    const bodyText = init.body == null ? '' : String(init.body);
    const headers = new Headers(init.headers || {});
    state.calls.push({ url, method, bodyText, authorization: headers.get('authorization') });
    const json = (payload, status = 200) => Response.json(payload, { status });
    if (url.hostname === 'api.cloudflare.com') {
      assert.equal(headers.get('authorization'), `Bearer ${CF_TOKEN}`);
      if (url.pathname === '/client/v4/zones') {
        const name = url.searchParams.get('name');
        const result = name === 'example.com' ? [{ id: ZONE, name: 'example.com', account: { id: ACCOUNT, name: 'Example' } }] : [];
        return json({ success: true, result });
      }
      if (url.pathname === `/client/v4/zones/${ZONE}/workers/routes` && method === 'GET') {
        return json({ success: true, result: state.routes });
      }
      if (url.pathname === `/client/v4/zones/${ZONE}/workers/routes` && method === 'POST') {
        state.routePosts += 1;
        const route = { id: 'route-1', ...JSON.parse(bodyText) };
        state.routes.push(route);
        return json({ success: true, result: route }, 201);
      }
      if (url.pathname === `/client/v4/accounts/${ACCOUNT}/challenges/widgets` && method === 'GET') {
        return json({
          success: true,
          result: state.widgets.map(({ secret, ...widget }) => widget),
          result_info: { total_pages: 1 },
        });
      }
      if (url.pathname === `/client/v4/accounts/${ACCOUNT}/challenges/widgets` && method === 'POST') {
        if (state.failWidgets) return json({ success: false, errors: [{ message: 'Turnstile permission was denied' }] }, 403);
        state.widgetPosts += 1;
        const widget = { sitekey: SITEKEY, secret: TURNSTILE_SECRET, ...JSON.parse(bodyText) };
        state.widgets.push(widget);
        return json({ success: true, result: widget }, 201);
      }
      const widgetGet = url.pathname.match(/^\/client\/v4\/accounts\/[^/]+\/challenges\/widgets\/([^/]+)$/);
      if (widgetGet && method === 'GET') {
        const widget = state.widgets.find((item) => item.sitekey === decodeURIComponent(widgetGet[1]));
        return json({ success: true, result: widget });
      }
      if (url.pathname.endsWith('/secrets') && method === 'PUT') {
        if (state.failSecrets) return json({ success: false, errors: [{ message: 'Workers Scripts edit was denied' }] }, 403);
        const secret = JSON.parse(bodyText);
        state.secrets.push(secret);
        return json({ success: true, result: { name: secret.name, type: secret.type } });
      }
      throw new Error(`Unexpected Cloudflare call ${method} ${url.pathname}`);
    }
    if (url.hostname === 'example.com' && url.pathname.endsWith('/ghost/api/admin/settings/')) {
      assert.match(headers.get('authorization') || '', /^Ghost /);
      if (method === 'GET') return json({ settings: [{ key: 'codeinjection_head', value: state.head }, { key: 'title', value: 'Example' }] });
      const parsed = JSON.parse(bodyText);
      assert.deepEqual(parsed.settings.map((item) => item.key), ['codeinjection_head']);
      state.head = parsed.settings[0].value;
      return json({ settings: parsed.settings });
    }
    if (url.hostname === 'example.com' && url.pathname.includes('/ghost/api/admin/webhooks')) {
      assert.match(headers.get('authorization') || '', /^Ghost /);
      if (method === 'GET') return json({ webhooks: state.webhooks, meta: { pagination: { pages: 1 } } });
      const parsed = JSON.parse(bodyText);
      const webhook = parsed.webhooks[0];
      if (method === 'POST' && state.webhookRejectIntegration && webhook.integration_id) {
        state.webhookPosts += 1;
        return json({ errors: [{ message: 'Validation error' }] }, 422);
      }
      if (method === 'POST') {
        state.webhookPosts += 1;
        const saved = { id: 'webhook-1', ...webhook };
        state.webhooks.push(saved);
        return json({ webhooks: [saved] }, 201);
      }
      throw new Error(`Unexpected webhook ${method}`);
    }
    if (url.hostname === 'challenges.cloudflare.com') {
      assert.equal(new URLSearchParams(bodyText).get('secret'), TURNSTILE_SECRET);
      return json({ success: false, 'error-codes': ['invalid-input-response'] });
    }
    if (url.hostname === 'example.com' && url.pathname === '/ghost-guard/turnstile.js') {
      assert.equal(headers.get('authorization'), null);
      return new Response(state.scriptBody, { status: state.scriptStatus, headers: { 'content-type': 'text/javascript' } });
    }
    if (url.hostname === 'example.com' && url.pathname === '/blog/members/' && method === 'GET') {
      assert.equal(url.searchParams.get('token'), 'x');
      assert.equal(url.searchParams.get('action'), 'signup');
      assert.equal(headers.get('authorization'), null);
      return new Response('<html><h1>Confirm signup</h1></html>', { status: 200, headers: { 'content-type': 'text/html' } });
    }
    if (url.hostname === 'example.com' && url.pathname === '/blog/members/api/send-magic-link/' && method === 'POST') {
      assert.equal(headers.get('authorization'), null);
      const payload = JSON.parse(bodyText);
      assert.equal(payload.emailType, 'signin');
      assert.equal(payload.email, 'ghost-guard-setup-check@example.invalid');
      return json({ success: true }, 201);
    }
    throw new Error(`Unexpected fetch ${method} ${url.href}`);
  });
}

function assertNoSecrets(html, extra = []) {
  for (const secret of [SETUP_TOKEN, CF_TOKEN, ADMIN_KEY, ADMIN_SECRET, TURNSTILE_SECRET, ...extra]) {
    assert.equal(html.includes(secret), false, secret);
  }
}

test('setup stays locked without a valid token and rate-limits failures', async (t) => {
  const state = world();
  install(t, state);
  const store = memoryStore();
  const env = baseEnv(store);
  const get = await worker.fetch(new Request('https://blog.example/Ghost-Guard//Setup/'), env);
  assert.equal(get.status, 200);
  assert.match(await get.text(), /Setup token/);
  assert.equal(get.headers.get('content-security-policy'), CSP);
  assert.equal(get.headers.get('x-frame-options'), 'DENY');
  const missing = await worker.fetch(formRequest('/ghost-guard/setup', { intent: 'run', ghost_url: 'https://example.com' }, { token: '' }), env);
  assert.equal(missing.status, 401);
  for (let i = 0; i < SETUP_FAILURE_LIMIT; i++) {
    const response = await worker.fetch(formRequest('/ghost-guard/setup', happyFields, { token: 'wrong-token', ip: '192.0.2.20' }), env);
    assert.equal(response.status, 401);
    assertNoSecrets(await response.text());
  }
  const limited = await worker.fetch(formRequest('/ghost-guard/setup', happyFields, { ip: '192.0.2.20' }), env);
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers.get('retry-after')) > 0);
  assert.match(await limited.text(), /Too many setup attempts/);
  const other = await worker.fetch(formRequest('/ghost-guard/setup', { intent: 'run', ghost_url: 'https://example.com' }, { token: 'wrong-token', ip: '192.0.2.21' }), env);
  assert.equal(other.status, 401);
  assert.equal(state.calls.length, 0);
});

test('a generated setup token is logged once and never written into the page', async (t) => {
  const logs = [];
  t.mock.method(console, 'log', (...args) => logs.push(args.join(' ')));
  const store = memoryStore();
  const env = baseEnv(store, { SETUP_TOKEN: '' });
  const first = await worker.fetch(new Request('https://blog.example/ghost-guard/setup'), env);
  const html = await first.text();
  assert.match(logs[0], /npx wrangler secret put SETUP_TOKEN/);
  const token = logs[0].match(/Token: ([a-f0-9]{64})/)?.[1];
  assert.ok(token);
  assert.equal(html.includes(token), false);
  assert.match(html, /wrangler tail/);
  await worker.fetch(new Request('https://blog.example/ghost-guard/setup'), env);
  assert.equal(logs.length, 1);
});

test('setup performs each step, and a re-run reuses routes, widgets and webhooks', async (t) => {
  const state = world();
  install(t, state);
  const store = memoryStore();
  const env = baseEnv(store);
  const first = await worker.fetch(formRequest('/Ghost-Guard//Setup/', happyFields), env);
  assert.equal(first.status, 200);
  const html = await first.text();
  assert.match(html, /Setup complete/);
  for (const title of ['Cloudflare zone', 'Worker route', 'Turnstile widget', 'Ghost code injection', 'Save configuration', 'Webhook labeller', 'Route reachable', 'Turnstile widget', 'Code injection snippet', 'Confirmation page', 'Sign-in passthrough', 'Webhook']) {
    assert.match(html, new RegExp(title));
  }
  assert.match(html, /OK/);
  assertNoSecrets(html);
  assert.equal(state.routePosts, 1);
  assert.equal(state.widgetPosts, 1);
  assert.equal(state.webhookPosts, 1);
  assert.equal(state.routes[0].pattern, 'example.com/*');
  assert.equal(state.routes[0].script, 'ghost-guard');
  assert.equal(state.widgets[0].name, 'ghost-guard-example.com');
  assert.deepEqual(state.widgets[0].domains, ['example.com']);
  assert.equal(state.webhooks[0].event, 'member.added');
  assert.equal(state.webhooks[0].target_url, 'https://example.com/signup-shield/webhooks/member-added');
  assert.equal(state.webhooks[0].integration_id, ADMIN_ID);
  assert.equal((state.head.match(/ghost-guard:start/g) || []).length, 1);
  assert.match(state.head, /keep-before/);
  assert.match(state.head, /<script>analytics<\/script>/);
  assert.match(state.head, /keep-after/);
  assert.match(state.head, new RegExp(`data-sitekey="${SITEKEY}"`));
  assert.deepEqual(state.secrets.map((secret) => secret.name).sort(), ['ADMIN_API_KEY', 'TURNSTILE_SECRET', 'WEBHOOK_SECRET']);
  const saved = store.data.get('config');
  assert.equal(saved.complete, true);
  assert.equal(saved.turnstileSecret, TURNSTILE_SECRET);
  assert.equal(saved.adminApiKey, ADMIN_KEY);
  assert.equal(saved.webhookSecret, state.webhooks[0].secret);
  assert.equal(saved.ghostBasePath, '/blog');
  assert.equal(saved.cleanupEnabled, 'true');
  assert.equal(JSON.stringify([...store.data.values()]).includes(CF_TOKEN), false);
  assertNoSecrets(html, [saved.webhookSecret]);

  const secretPuts = state.secrets.length;
  const second = await worker.fetch(formRequest('/ghost-guard/setup', happyFields), env);
  assert.equal(second.status, 200);
  assert.match(await second.text(), /Setup complete/);
  assert.equal(state.routePosts, 1);
  assert.equal(state.widgetPosts, 1);
  assert.equal(state.webhookPosts, 1);
  assert.equal(state.routes.length, 1);
  assert.equal(state.widgets.length, 1);
  assert.equal(state.webhooks.length, 1);
  assert.equal((state.head.match(/ghost-guard:start/g) || []).length, 1);
  assert.match(state.head, /analytics/);
  assert.equal(state.secrets.length, secretPuts * 2);
  assert.equal(state.calls.filter((call) => call.url.pathname.includes('/ghost/api/admin/members')).length, 0);

  const gate = await worker.fetch(new Request('https://example.com/ghost-guard/setup'), env);
  const gateHtml = await gate.text();
  assert.match(gateHtml, /already complete/);
  assert.doesNotMatch(gateHtml, /Route reachable|admin_api_key|cf_api_token/);
  assertNoSecrets(gateHtml, [saved.webhookSecret]);
  const status = await worker.fetch(formRequest('/ghost-guard/setup', { intent: 'view' }), env);
  const statusHtml = await status.text();
  assert.match(statusHtml, /Route reachable/);
  assertNoSecrets(statusHtml, [saved.webhookSecret]);
});

test('webhook creation retries without an integration id, and a disabled labeller stores no admin key', async (t) => {
  const state = world();
  state.webhookRejectIntegration = true;
  install(t, state);
  const store = memoryStore();
  const created = await worker.fetch(formRequest('/ghost-guard/setup', happyFields), baseEnv(store));
  assert.match(await created.text(), /Setup complete/);
  assert.equal(state.webhookPosts, 2);
  assert.equal(state.webhooks.length, 1);
  assert.equal(state.webhooks[0].integration_id, undefined);
  const off = world();
  install(t, off);
  const offStore = memoryStore();
  const { webhook, ...fields } = happyFields;
  void webhook;
  const response = await worker.fetch(formRequest('/ghost-guard/setup', fields), baseEnv(offStore));
  assert.match(await response.text(), /Webhook labeller is off/);
  assert.equal(off.webhookPosts, 0);
  assert.equal(offStore.data.get('config').adminApiKey, '');
  assert.equal(offStore.data.get('config').webhookSecret, '');
  assert.equal(off.secrets.map((secret) => secret.name).includes('ADMIN_API_KEY'), false);
});

test('a failed Turnstile step reports that step and keeps the route for a later re-run', async (t) => {
  const state = world();
  state.failWidgets = true;
  install(t, state);
  const store = memoryStore();
  const env = baseEnv(store);
  const failed = await worker.fetch(formRequest('/ghost-guard/setup', happyFields), env);
  const html = await failed.text();
  assert.match(html, /Setup did not finish/);
  assert.match(html, /Turnstile widget/);
  assert.match(html, /Needs attention/);
  assert.match(html, /Turnstile permission was denied/);
  assert.match(html, /Worker route/);
  assertNoSecrets(html);
  assert.equal(state.routePosts, 1);
  assert.equal(state.widgetPosts, 0);
  assert.equal(state.head.includes('ghost-guard:start'), false);
  assert.equal(store.data.get('config'), undefined);
  state.failWidgets = false;
  const again = await worker.fetch(formRequest('/ghost-guard/setup', happyFields), env);
  assert.match(await again.text(), /Setup complete/);
  assert.equal(state.routePosts, 1);
  assert.equal(state.widgetPosts, 1);
  assert.equal(state.routes.length, 1);
});

test('Worker secret updates are optional when the setup store holds the config', async (t) => {
  const state = world();
  state.failSecrets = true;
  install(t, state);
  const store = memoryStore();
  const response = await worker.fetch(formRequest('/ghost-guard/setup', happyFields), baseEnv(store));
  const html = await response.text();
  assert.match(html, /Setup complete/);
  assert.match(html, /Workers Scripts edit was denied/);
  assert.equal(store.data.get('config').turnstileSecret, TURNSTILE_SECRET);
  assertNoSecrets(html, [store.data.get('config').webhookSecret]);
});

test('route check is red from workers.dev when the script is not served, and green on the site itself', async (t) => {
  const missed = world();
  missed.scriptStatus = 404;
  missed.scriptBody = '<html>origin</html>';
  install(t, missed);
  const red = await worker.fetch(formRequest('/ghost-guard/setup', happyFields), baseEnv(memoryStore()));
  const redHtml = await red.text();
  assert.match(redHtml, /Needs attention[\s\S]*Route reachable|Route reachable[\s\S]*Needs attention/);
  assert.match(redHtml, /Fix:/);
  const served = world();
  served.scriptStatus = 404;
  served.scriptBody = '<html>origin</html>';
  install(t, served);
  const request = new Request('https://example.com/ghost-guard/setup', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': '192.0.2.10' },
    body: new URLSearchParams({ ...happyFields, setup_token: SETUP_TOKEN }),
  });
  const green = await worker.fetch(request, baseEnv(memoryStore()));
  const greenHtml = await green.text();
  assert.match(greenHtml, /skips the Worker/);
  assert.match(greenHtml, /Route reachable/);
  assert.doesNotMatch(greenHtml.split('Route reachable')[1].slice(0, 220), /Needs attention/);
});

test('stored config fills unset settings and environment values win', async (t) => {
  const calls = [];
  t.mock.method(globalThis, 'fetch', async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    if (String(request.url) === 'https://challenges.cloudflare.com/turnstile/v0/siteverify') {
      calls.push({ kind: 'verify', secret: new URLSearchParams(init.body).get('secret') });
      return Response.json({ success: true, hostname: 'blog.example', action: 'ghost_signup' });
    }
    calls.push({ kind: 'forward', host: new URL(request.url).host, pathname: new URL(request.url).pathname });
    return Response.json({ ok: true }, { status: 201 });
  });
  const store = memoryStore();
  store.data.set('config', { ghostBasePath: '/blog', turnstileSecret: 'stored-secret', cleanupEnabled: 'true', adminApiUrl: 'https://stored.example' });
  const env = baseEnv(store, { SETUP_TOKEN: 'x', TURNSTILE_SECRET: undefined, GHOST_BASE_PATH: undefined, CLEANUP_ENABLED: 'false', ADMIN_API_URL: '' });
  const signup = await worker.fetch(new Request('https://blog.example/members/api/send-magic-link/', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'CF-Connecting-IP': '192.0.2.1', 'cf-turnstile-response': 'token' },
    body: JSON.stringify({ email: 'reader@work.example', emailType: 'signup' }),
  }), env);
  assert.equal(signup.status, 201);
  assert.equal(calls.find((call) => call.kind === 'verify').secret, 'stored-secret');
  await worker.fetch(new Request('https://blog.example/about/'), env);
  await worker.fetch(new Request('https://blog.example/blog/post/'), env);
  assert.deepEqual(calls.filter((call) => call.kind === 'forward' && call.pathname !== '/members/api/send-magic-link/').map((call) => call.host), ['blog.example', 'origin.example']);
  const override = baseEnv(store, { TURNSTILE_SECRET: 'env-secret', GHOST_BASE_PATH: '/news' });
  calls.length = 0;
  await worker.fetch(new Request('https://blog.example/members/api/send-magic-link/', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'CF-Connecting-IP': '192.0.2.2', 'cf-turnstile-response': 'token' },
    body: JSON.stringify({ email: 'other@work.example', emailType: 'signup' }),
  }), override);
  assert.equal(calls.find((call) => call.kind === 'verify').secret, 'env-secret');
  await worker.fetch(new Request('https://blog.example/blog/post/'), override);
  await worker.fetch(new Request('https://blog.example/news/post/'), override);
  assert.deepEqual(calls.filter((call) => call.kind === 'forward' && !call.pathname.endsWith('/send-magic-link/')).map((call) => call.host), ['blog.example', 'origin.example']);
});

test('code injection replaces only the marked block', () => {
  const existing = `before\n${GUARD_START}\nOLD\n${GUARD_END}\nmiddle\n${GUARD_START}\nAGAIN\n${GUARD_END}\nafter`;
  const merged = mergeCodeInjection(existing, 'sitekey');
  assert.equal((merged.match(/ghost-guard:start/g) || []).length, 1);
  assert.match(merged, /before/);
  assert.match(merged, /middle/);
  assert.match(merged, /after/);
  assert.doesNotMatch(merged, /OLD|AGAIN/);
  assert.match(merged, /data-sitekey="sitekey"/);
  assert.equal(mergeConfig({ CLEANUP_ENABLED: 'false', ADMIN_API_URL: '', TURNSTILE_SECRET: 'env' }, {
    cleanupEnabled: 'true', adminApiUrl: 'https://stored.example', turnstileSecret: 'stored',
  }).TURNSTILE_SECRET, 'env');
});

test('bad setup input does not call Cloudflare', async (t) => {
  const state = world();
  install(t, state);
  const env = baseEnv(memoryStore());
  const response = await worker.fetch(formRequest('/ghost-guard/setup', { ...happyFields, ghost_base_path: '/blog/..' }), env);
  assert.equal(response.status, 400);
  assert.match(await response.text(), /GHOST_BASE_PATH/);
  assert.equal(state.calls.length, 0);
  const type = await worker.fetch(new Request('https://blog.example/ghost-guard/setup', {
    method: 'POST',
    headers: { 'content-type': 'text/plain', 'CF-Connecting-IP': '192.0.2.10' },
    body: 'setup_token=x',
  }), env);
  assert.equal(type.status, 400);
});
