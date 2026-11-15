import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';
import { MemoryRateLimiter } from '../src/rate-limit.js';
import {
  SetupStore, SETUP_FAILURE_LIMIT, codeInjectionSnippet, conflictingRoutes, GUARD_START, GUARD_END,
} from '../src/setup.js';
import { mergeConfig } from '../src/config.js';

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
  const storage = {
    alarm: null,
    async get(key) { return data.get(key); },
    async put(key, value) { data.set(key, value); },
    async delete(keys) { for (const key of Array.isArray(keys) ? keys : [keys]) data.delete(key); },
    async getAlarm() { return storage.alarm; },
    async setAlarm(time) { storage.alarm = time; },
    async list({ prefix, startAfter = '', limit }) {
      return new Map([...data].filter(([key]) => key.startsWith(prefix) && key > startAfter).sort(([a], [b]) => a.localeCompare(b)).slice(0, limit));
    },
  };
  const store = new SetupStore({ storage });
  return {
    data, storage,
    fire() { storage.alarm = null; return store.alarm(); },
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
  webhook_secret: 'chosen-webhook-secret-SENTINEL',
};

function world() {
  const state = {
    routes: [],
    widgets: [],
    calls: [],
    failWidgets: false,
    scriptStatus: 200,
    scriptBody: 'window.__ghostGuardTurnstile = true;',
    signinStatus: 201,
    signinBody: { success: true },
    routePosts: 0,
    widgetPosts: 0,
  };
  return state;
}

function install(t, state) {
  t.mock.method(globalThis, 'fetch', async (input, init = {}) => {
    const request = input instanceof Request ? input : null;
    const url = new URL(request ? request.url : input);
    const method = (request?.method || init.method || 'GET').toUpperCase();
    const bodyText = request ? await request.text() : init.body == null ? '' : String(init.body);
    const headers = new Headers(request?.headers || init.headers || {});
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
      const rotate = url.pathname.match(/^\/client\/v4\/accounts\/[^/]+\/challenges\/widgets\/([^/]+)\/rotate_secret$/);
      if (rotate && method === 'POST') {
        state.rotations = (state.rotations || 0) + 1;
        const widget = state.widgets.find((item) => item.sitekey === decodeURIComponent(rotate[1]));
        widget.secret = TURNSTILE_SECRET;
        return json({ success: true, result: { sitekey: widget.sitekey, secret: widget.secret } });
      }
      const widgetGet = url.pathname.match(/^\/client\/v4\/accounts\/[^/]+\/challenges\/widgets\/([^/]+)$/);
      if (widgetGet && method === 'GET') {
        const widget = state.widgets.find((item) => item.sitekey === decodeURIComponent(widgetGet[1]));
        return json({ success: true, result: widget });
      }
      throw new Error(`Unexpected Cloudflare call ${method} ${url.pathname}`);
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
    if (['example.com', 'origin.example'].includes(url.hostname) && url.pathname === '/blog/members/api/send-magic-link/' && method === 'POST') {
      assert.equal(headers.get('authorization'), null);
      const payload = JSON.parse(bodyText);
      assert.equal(payload.emailType, 'signin');
      assert.equal(payload.email, 'ghost-guard-setup-check@example.invalid');
      return json(state.signinBody, state.signinStatus);
    }
    throw new Error(`Unexpected fetch ${method} ${url.href}`);
  });
}

function assertNoSecrets(html, extra = []) {
  for (const secret of [SETUP_TOKEN, CF_TOKEN, ADMIN_KEY, ADMIN_SECRET, TURNSTILE_SECRET, happyFields.webhook_secret, ...extra]) {
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

test('a generated setup token is logged on every visit and never written into the page', async (t) => {
  const logs = [];
  t.mock.method(console, 'log', (...args) => logs.push(args.join(' ')));
  const store = memoryStore();
  const env = baseEnv(store, { SETUP_TOKEN: '' });
  const first = await worker.fetch(new Request('https://blog.example/ghost-guard/setup'), env);
  const html = await first.text();
  assert.match(logs[0], /npx wrangler secret put SETUP_TOKEN/);
  const token = logs[0].match(/Setup token: ([a-f0-9]{64})/)?.[1];
  assert.ok(token);
  assert.equal(html.includes(token), false);
  assert.match(html, /wrangler tail/);
  // An operator who starts `wrangler tail` after the first visit still sees it.
  await worker.fetch(new Request('https://blog.example/ghost-guard/setup'), env);
  assert.equal(logs.length, 2);
  assert.ok(logs[1].includes(token));
});


test('setup prepares Cloudflare without Ghost writes or Worker secret deployments, then activates explicitly', async (t) => {
  const state = world();
  install(t, state);
  const store = memoryStore();
  const env = baseEnv(store);
  const response = await worker.fetch(formRequest('/ghost-guard/setup', happyFields), env);
  const html = await response.text();
  assert.match(html, /Cloudflare ready/);
  assert.match(html, /Install the Ghost snippet/);
  assert.match(html, /Activate signup protection/);
  assert.match(html, /Member added/);
  assert.match(html, /https:\/\/example.com\/signup-shield\/webhooks\/member-added/);
  assert.match(html, /data-sitekey=&quot;0x4AAAAAABBBBBCCCCCDDDDD&quot;/);
  assertNoSecrets(html);
  assert.equal(store.data.get('config').turnstileEnabled, false);
  assert.equal(store.data.get('config').adminApiKey, ADMIN_KEY);
  assert.equal(store.data.get('config').adminApiUrl, 'https://origin.example/blog');
  assert.equal(store.data.get('config').webhookSecret, happyFields.webhook_secret);
  assert.equal(state.calls.some(call => call.url.pathname.includes('/ghost/api/admin/')), false);
  assert.equal(state.calls.some(call => call.url.pathname.endsWith('/secrets')), false);
  assert.equal(JSON.stringify([...store.data.values()]).includes(CF_TOKEN), false);

  const missingCheckbox = await worker.fetch(formRequest('/ghost-guard/setup', {intent:'activate'}), env);
  assert.equal(missingCheckbox.status, 400);
  const unauthorized = await worker.fetch(formRequest('/ghost-guard/setup', {intent:'activate',snippet_installed:'on'}, {token:'wrong'}), env);
  assert.equal(unauthorized.status, 401);
  assert.equal(store.data.get('config').turnstileEnabled, false);
  const activated = await worker.fetch(formRequest('/ghost-guard/setup', activationFields(store)), env);
  assert.match(await activated.text(), /Turnstile signup protection is active/);
  assert.equal(store.data.get('config').turnstileEnabled, true);
  const blocked = await worker.fetch(signup(), env);
  assert.equal(blocked.status, 400);

  const rerun = await worker.fetch(formRequest('/ghost-guard/setup', happyFields), env);
  assert.match(await rerun.text(), /Turnstile signup protection is active/);
  assert.equal(state.routePosts, 1);
  assert.equal(state.widgetPosts, 1);
  const gate = await worker.fetch(new Request('https://example.com/ghost-guard/setup'), env);
  const gateHtml = await gate.text();
  assert.doesNotMatch(gateHtml, /data-sitekey|Route reachable/);
  const status = await worker.fetch(formRequest('/ghost-guard/setup', {intent:'view'}), env);
  assert.match(await status.text(), /Install the Ghost snippet/);
});

function activationFields(store) {
  return { intent: 'activate', snippet_installed: 'on', config_revision: store.data.get('config').revision };
}

test('stale activation forms cannot enable a replacement widget', async (t) => {
  const state = world();
  install(t, state);
  const store = memoryStore(), env = baseEnv(store);
  const first = await worker.fetch(formRequest('/ghost-guard/setup', happyFields), env);
  const oldForm = activationFields(store);
  assert.match(await first.text(), new RegExp(`name="config_revision" value="${oldForm.config_revision}"`));
  state.widgets[0].sitekey = 'NEW-SITEKEY';
  await worker.fetch(formRequest('/ghost-guard/setup', happyFields), env);
  const stale = await worker.fetch(formRequest('/ghost-guard/setup', oldForm), env);
  assert.equal(stale.status, 409);
  assert.match(await stale.text(), /Setup changed in another tab/);
  assert.equal(store.data.get('config').turnstileEnabled, false);
  assert.equal(store.data.get('config').turnstileSitekey, 'NEW-SITEKEY');
  const results = await Promise.all(Array.from({ length: 2 }, () => worker.fetch(formRequest('/ghost-guard/setup', activationFields(store)), env)));
  assert.deepEqual(results.map(res => res.status).sort(), [200, 409]);
  assert.equal(store.data.get('config').turnstileEnabled, true);
});

test('an overlapping preparation cannot overwrite a successful activation', async (t) => {
  const state = world();
  install(t, state);
  const store = memoryStore(), env = baseEnv(store);
  await worker.fetch(formRequest('/ghost-guard/setup', happyFields), env);
  const originalFetch = globalThis.fetch;
  let release, reached;
  const hold = new Promise(resolve => { release = resolve; });
  const paused = new Promise(resolve => { reached = resolve; });
  t.after(() => release());
  t.mock.method(globalThis, 'fetch', async (input, init) => {
    if (new URL(input).pathname === '/ghost-guard/turnstile.js') { reached(); await hold; }
    return originalFetch(input, init);
  });
  const pending = worker.fetch(formRequest('/ghost-guard/setup', happyFields), env);
  await paused;
  assert.equal((await worker.fetch(formRequest('/ghost-guard/setup', activationFields(store)), env)).status, 200);
  const activeRevision = store.data.get('config').revision;
  release();
  assert.match(await (await pending).text(), /Setup changed in another tab/);
  assert.equal(store.data.get('config').revision, activeRevision);
  assert.equal(store.data.get('config').turnstileEnabled, true);
});

test('setup refuses overlapping Cloudflare exclusions even when the hostname route already exists', async (t) => {
  for (const pattern of ['example.com/blog/Members*', 'https://example.com/blog//Members/API/Send-Magic-Link/', 'example.com/ghost-guard/turnstile.js', '*example.com/blog/Members*']) {
    const state = world();
    state.routes.push({ id: 'bypass', pattern, script: null });
    state.routes.push({ id: 'main', pattern: 'example.com/*', script: 'ghost-guard' });
    install(t, state);
    const store = memoryStore();
    const response = await worker.fetch(formRequest('/ghost-guard/setup', happyFields), baseEnv(store));
    assert.match(await response.text(), /conflicting Cloudflare routes can bypass protection/);
    assert.equal(store.data.has('config'), false);
    assert.equal(state.widgetPosts, 0);
    assert.equal(state.routePosts, 0);
  }
});

test('route conflicts cover root installs and schemes but allow unrelated apps and wider host routes', () => {
  const route = (pattern, script = null) => ({ pattern, script });
  const blocked = [route('example.com/Members*'), route('http://example.com/*', 'another-worker'), route('example.com/MEMBERS/API/SEND-MAGIC-LINK')];
  assert.deepEqual(conflictingRoutes(blocked, 'example.com', '', 'ghost-guard'), blocked);
  const allowed = [route('*.example.com/Members*'), route('other.example.com/Members*'), route('*example.com/*', 'another-worker'), route('example.com/assets/*'), route('example.com/blog/Members*', 'ghost-guard')];
  assert.deepEqual(conflictingRoutes(allowed, 'example.com', '/blog', 'ghost-guard'), []);
  assert.equal(conflictingRoutes([route('*.example.com/blog/Members*')], 'www.example.com', '/blog', 'ghost-guard').length, 1);
});

test('setup password attempts share an IPv6 /64 quota', async () => {
  const store = memoryStore(), env = baseEnv(store);
  for (let i = 1; i <= SETUP_FAILURE_LIMIT; i++) {
    assert.equal((await worker.fetch(formRequest('/ghost-guard/setup', { intent: 'view' }, { token: 'wrong', ip: `2001:db8:1234:5678::${i}` }), env)).status, 401);
  }
  assert.equal((await worker.fetch(formRequest('/ghost-guard/setup', { intent: 'view' }, { ip: '2001:db8:1234:5678::99' }), env)).status, 429);
  assert.equal((await worker.fetch(formRequest('/ghost-guard/setup', { intent: 'view' }, { ip: '2001:db8:1234:5679::1' }), env)).status, 200);
  assert.equal([...store.data.keys()].filter(key => key.startsWith('fail:')).length, 1);
});

test('setup alarms sweep expired login records in batches without deleting config or live limits', async () => {
  const store = memoryStore(), env = baseEnv(store);
  await worker.fetch(formRequest('/ghost-guard/setup', { intent: 'view' }, { token: 'wrong' }), env);
  assert.ok(store.storage.alarm > Date.now());
  const deadline = Date.now() + 30_000;
  store.data.clear();
  store.data.set('config', { revision: 'keep' });
  store.data.set('setupToken', 'keep');
  for (let i = 0; i < 300; i++) store.data.set(`fail:${String(i).padStart(4, '0')}`, { count: 1, expires: Date.now() - 1 });
  store.data.set('fail:live', { count: 8, expires: deadline });
  await store.fire();
  assert.deepEqual([...store.data.keys()].sort(), ['config', 'fail:live', 'setupToken']);
  assert.equal(store.storage.alarm, deadline);
  store.data.get('fail:live').expires = Date.now() - 1;
  await store.fire();
  assert.equal(store.data.has('fail:live'), false);
  assert.equal(store.storage.alarm, null);
});

test('signup-only setup leaves a manual labeller alone; a rerun keeps the labeller; turning it off clears it', async (t) => {
  const state = world();
  install(t, state);
  const store = memoryStore();
  const env = baseEnv(store);
  const manual = {CLEANUP_ENABLED:'true',ADMIN_API_KEY:ADMIN_KEY};
  const {webhook, webhook_secret, admin_api_key, ...fields} = happyFields;
  await worker.fetch(formRequest('/ghost-guard/setup', fields), env);
  assert.equal(mergeConfig(manual, store.data.get('config')).CLEANUP_ENABLED, 'true');
  assert.equal(mergeConfig(manual, store.data.get('config')).ADMIN_API_KEY, ADMIN_KEY);

  await worker.fetch(formRequest('/ghost-guard/setup', happyFields), env);
  const rerun = await worker.fetch(formRequest('/ghost-guard/setup', fields), env);
  assert.match(await rerun.text(), /Cloudflare ready/);
  assert.equal(store.data.get('config').cleanupEnabled, 'true');
  assert.equal(store.data.get('config').adminApiKey, ADMIN_KEY);
  assert.equal(store.data.get('config').webhookSecret, happyFields.webhook_secret);

  const response = await worker.fetch(formRequest('/ghost-guard/setup', {...fields, webhook:'off'}), env);
  assert.match(await response.text(), /Cloudflare ready/);
  const saved = store.data.get('config');
  assert.equal(saved.cleanupEnabled, 'false');
  assert.equal(saved.adminApiKey, '');
  assert.equal(saved.webhookSecret, '');
  const effective = mergeConfig(manual, saved);
  assert.equal(effective.CLEANUP_ENABLED, 'false');
  assert.equal(effective.ADMIN_API_KEY, '');
});

test('a failed widget step keeps the previous working configuration and can be retried', async (t) => {
  const state = world();
  state.failWidgets = true;
  install(t, state);
  const store = memoryStore();
  const previous = {turnstileSecret:'previous-secret',turnstileEnabled:true,cleanupEnabled:'true',adminApiUrl:'https://old.example'};
  store.data.set('config', previous);
  const failed = await worker.fetch(formRequest('/ghost-guard/setup', happyFields), baseEnv(store));
  const html = await failed.text();
  assert.match(html, /Setup did not finish/);
  assert.match(html, /Turnstile permission was denied/);
  assert.match(html, /Zone Zone Read/);
  assertNoSecrets(html);
  assert.deepEqual(store.data.get('config'), previous);
  state.failWidgets = false;
  const success = await worker.fetch(formRequest('/ghost-guard/setup', happyFields), baseEnv(store));
  assert.match(await success.text(), /Cloudflare ready/);
  assert.equal(state.routePosts, 1);
});

test('setup reports unreachable routes and failed sign-in checks without claiming success for them', async (t) => {
  const state = world();
  state.scriptStatus = 404;
  state.scriptBody = 'Not found';
  state.signinStatus = 503;
  install(t, state);
  const store = memoryStore();
  await worker.fetch(formRequest('/ghost-guard/setup', happyFields), baseEnv(store));
  const checks = store.data.get('config').checklist;
  assert.equal(checks.find(check => check.title === 'Route reachable').ok, false);
  const signin = checks.find(check => check.title === 'Sign-in passthrough');
  assert.equal(signin.ok, false);
  assert.match(signin.detail, /HTTP 503/);
});

function signup(emailType = 'signup') {
  return new Request('https://example.com/members/api/send-magic-link/', {
    method:'POST',headers:{'content-type':'application/json','CF-Connecting-IP':'192.0.2.10'},
    body:JSON.stringify({email:'reader@work.example',emailType}),
  });
}

test('stored config outages reject signup and webhook traffic; ordinary same-zone traffic and assets keep working', async (t) => {
  let reads = 0;
  const env = {
    SETUP_STORE:{idFromName(n){return n;},get(){return {fetch(){reads++;throw Error('unavailable');}};}},
    LOCAL_RATE_LIMITER:new MemoryRateLimiter(),
    ASSETS:{fetch(){return new Response('script');}},
  };
  const forwarded = [];
  t.mock.method(globalThis,'fetch',async request=>{forwarded.push(request.url);return new Response('origin',{status:201});});
  assert.equal((await worker.fetch(signup(),env)).status,503);
  assert.equal((await worker.fetch(new Request('https://example.com/signup-shield/webhooks/member-added',{method:'POST',body:'{}'}),env)).status,503);
  assert.equal(forwarded.length,0);
  const before = reads;
  for (const path of ['/', '/post/', '/image.png', '/members/?token=x&action=signup']) {
    assert.ok((await worker.fetch(new Request(`https://example.com${path}`),env)).ok);
  }
  assert.equal((await worker.fetch(new Request('https://example.com/ghost-guard/turnstile.js'),env)).status,200);
  assert.equal((await worker.fetch(signup('signin'),env)).status,201);
  assert.equal(reads,before);
});

test('a setup store outage with GHOST_ORIGIN keeps pages up and still rejects signups', async (t) => {
  const env = {
    GHOST_ORIGIN:'https://origin.example',
    SETUP_STORE:{idFromName(n){return n;},get(){return {fetch(){throw Error('unavailable');}};}},
    LOCAL_RATE_LIMITER:new MemoryRateLimiter(),
  };
  const hosts = [];
  t.mock.method(globalThis,'fetch',async request=>{hosts.push(new URL(request.url).hostname);return new Response('origin');});
  assert.ok((await worker.fetch(new Request('https://example.com/post/'),env)).ok);
  assert.deepEqual(hosts,['origin.example']);
  assert.equal((await worker.fetch(signup(),env)).status,503);
});

test('a rerun from the public hostname reuses the saved script name and checks through the guard', async (t) => {
  const state = world();
  install(t, state);
  const store = memoryStore(), env = baseEnv(store);
  const first = formRequest('/ghost-guard/setup', happyFields);
  await worker.fetch(new Request(first.url.replace('ghost-guard.tester', 'my-guard.tester'), first), env);
  assert.equal(store.data.get('config').scriptName, 'my-guard');
  const rerun = formRequest('/ghost-guard/setup', happyFields);
  state.calls.length = 0;
  const html = await (await worker.fetch(new Request(rerun.url.replace('ghost-guard.tester.workers.dev', 'example.com'), rerun), env)).text();
  assert.match(html, /Cloudflare ready/);
  assert.equal(state.routePosts, 1);
  const checks = store.data.get('config').checklist;
  assert.ok(checks.every(check => check.ok), JSON.stringify(checks));
  // The confirmation page came from the guard itself, and sign-in went to Ghost's origin.
  assert.equal(state.calls.some(call => call.url.hostname === 'example.com' && call.url.pathname === '/blog/members/'), false);
  assert.ok(state.calls.some(call => call.url.hostname === 'origin.example' && call.url.pathname.endsWith('/send-magic-link/')));
});

test('first setup on a custom hostname adopts the Worker its route runs, or stops if unknown', async (t) => {
  const state = world();
  state.routes.push({ id: 'route-1', pattern: 'example.com/*', script: 'my-guard' });
  install(t, state);
  const store = memoryStore(), env = baseEnv(store);
  const onHost = (fields) => { const r = formRequest('/ghost-guard/setup', fields); return new Request(r.url.replace('ghost-guard.tester.workers.dev', 'example.com'), r); };
  assert.match(await (await worker.fetch(onHost(happyFields), env)).text(), /Cloudflare ready/);
  assert.equal(store.data.get('config').scriptName, 'my-guard');
  const other = memoryStore();
  const elsewhere = formRequest('/ghost-guard/setup', happyFields);
  const html = await (await worker.fetch(new Request(elsewhere.url.replace('ghost-guard.tester.workers.dev', 'setup.other.example'), elsewhere), baseEnv(other))).text();
  assert.match(html, /Worker name is unknown/);
  assert.equal(state.routePosts, 0);
});

test('a rerun on the public hostname trusts the route over a stale saved Worker name', async (t) => {
  const state = world();
  state.routes.push({ id: 'route-1', pattern: 'example.com/*', script: 'my-guard' });
  install(t, state);
  const store = memoryStore(), env = baseEnv(store);
  store.data.set('config', { scriptName: 'ghost-guard' });
  const r = formRequest('/ghost-guard/setup', happyFields);
  assert.match(await (await worker.fetch(new Request(r.url.replace('ghost-guard.tester.workers.dev', 'example.com'), r), env)).text(), /Cloudflare ready/);
  assert.equal(store.data.get('config').scriptName, 'my-guard');
});

test('same-host checks use the subfolder entered in this run, not the saved one', async (t) => {
  const state = world();
  install(t, state);
  const store = memoryStore(), env = baseEnv(store);
  store.data.set('config', { ghostBasePath: '/old', scriptName: 'ghost-guard' });
  const r = formRequest('/ghost-guard/setup', happyFields);
  await worker.fetch(new Request(r.url.replace('ghost-guard.tester.workers.dev', 'example.com'), r), env);
  const signin = store.data.get('config').checklist.find(check => check.title === 'Sign-in passthrough');
  assert.equal(signin.ok, true, signin.detail);
  const signins = state.calls.filter(call => call.url.pathname === '/blog/members/api/send-magic-link/');
  assert.deepEqual(signins.map(call => call.url.hostname), ['origin.example']);
});

test('Ghost rejecting a sign-in for an unknown member still passes the sign-in check', async (t) => {
  const state = world();
  state.signinStatus = 400;
  state.signinBody = { errors: [{ message: 'No member exists with this e-mail address.' }] };
  install(t, state);
  const store = memoryStore();
  await worker.fetch(formRequest('/ghost-guard/setup', happyFields), baseEnv(store));
  assert.equal(store.data.get('config').checklist.find(check => check.title === 'Sign-in passthrough').ok, true);
});

test('a rotated widget secret survives a failed save and is reused without rotating again', async (t) => {
  const state = world();
  state.widgets.push({ sitekey: SITEKEY, name: 'ghost-guard-example.com', domains: ['example.com'] });
  install(t, state);
  const store = memoryStore(), env = baseEnv(store);
  const originalFetch = globalThis.fetch;
  const race = t.mock.method(globalThis, 'fetch', async (input, init) => {
    // Another tab saves while this run is checking the route.
    if (String(input).endsWith('/ghost-guard/turnstile.js')) store.data.set('config', { revision: 'other-tab' });
    return originalFetch(input, init);
  });
  const failed = await worker.fetch(formRequest('/ghost-guard/setup', happyFields), env);
  assert.match(await failed.text(), /Setup changed in another tab/);
  assert.equal(state.rotations, 1);
  assert.equal(store.data.get('widgetSecret').secret, TURNSTILE_SECRET);
  race.mock.restore();
  delete state.widgets[0].secret;
  store.data.delete('config');
  assert.match(await (await worker.fetch(formRequest('/ghost-guard/setup', happyFields), env)).text(), /Cloudflare ready/);
  assert.equal(state.rotations, 1);
  assert.equal(store.data.get('config').turnstileSecret, TURNSTILE_SECRET);
});

test('stored settings own setup-managed fields and preserve manual deployments without config', async (t) => {
  const manual = {TURNSTILE_SECRET:'manual',CLEANUP_ENABLED:'true'};
  assert.equal(mergeConfig(manual,null),manual);
  const effective = mergeConfig({TURNSTILE_SECRET:'stale',GHOST_BASE_PATH:'/old',ADMIN_API_URL:'https://old.example',CLEANUP_ENABLED:'false'}, {
    turnstileSecret:'stored',ghostBasePath:'/blog',cleanupEnabled:'true',adminApiUrl:'https://example.com/blog',adminApiKey:ADMIN_KEY,webhookSecret:'stored-hook',
  });
  assert.equal(effective.TURNSTILE_SECRET,'stored');
  assert.equal(effective.GHOST_BASE_PATH,'/blog');
  assert.equal(effective.ADMIN_API_URL,'https://example.com/blog');
  assert.equal(effective.CLEANUP_ENABLED,'true');
  // A prepared, unactivated widget leaves a manual secret in force.
  assert.equal(mergeConfig(manual,{turnstileSecret:'prepared',turnstileEnabled:false}).TURNSTILE_SECRET,'manual');
  const store = memoryStore();
  store.data.set('config',{ghostBasePath:'/blog'});
  const hosts = [];
  t.mock.method(globalThis,'fetch',async request=>{hosts.push(new URL(request.url).hostname);return new Response('ok');});
  const env = baseEnv(store,{GHOST_BASE_PATH:'/old'});
  await worker.fetch(new Request('https://example.com/about/'),env);
  await worker.fetch(new Request('https://example.com/blog/post/'),env);
  assert.deepEqual(hosts,['example.com','origin.example']);
});

test('manual snippet contains only the public key and rejects unsafe keys', () => {
  assert.equal(codeInjectionSnippet(SITEKEY), `${GUARD_START}\n<script src="/ghost-guard/turnstile.js" data-sitekey="${SITEKEY}"></script>\n${GUARD_END}`);
  assert.throws(()=>codeInjectionSnippet('"><script>bad</script>'));
});

test('bad setup inputs and activation before preparation call no external APIs', async (t) => {
  const state = world();
  install(t,state);
  const env = baseEnv(memoryStore());
  for (const fields of [
    {...happyFields,ghost_base_path:'/blog/..'},
    {...happyFields,admin_api_key:'invalid'},
    {...happyFields,webhook_secret:'short'},
    {intent:'activate',snippet_installed:'on'},
  ]) {
    assert.equal((await worker.fetch(formRequest('/ghost-guard/setup',fields),env)).status,400);
  }
  assert.equal(state.calls.length,0);
});

test('webhook secrets respect Ghost’s 191-character boundary', async (t) => {
  const state = world();
  install(t, state);
  const store = memoryStore(), env = baseEnv(store);
  const form = await worker.fetch(new Request('https://example.com/ghost-guard/setup'), env);
  assert.match(await form.text(), /name="webhook_secret"[^>]*maxlength="191"/);
  const rejected = await worker.fetch(formRequest('/ghost-guard/setup', { ...happyFields, webhook_secret: 'x'.repeat(192) }), env);
  assert.equal(rejected.status, 400);
  assert.equal(state.calls.length, 0);
  const allowed = await worker.fetch(formRequest('/ghost-guard/setup', { ...happyFields, webhook_secret: 'x'.repeat(191) }), env);
  assert.match(await allowed.text(), /Cloudflare ready/);
  assert.equal(store.data.get('config').webhookSecret.length, 191);
});

test('guided Turnstile uses the saved public hostname while manual installations keep their override', async (t) => {
  const store = memoryStore();
  store.data.set('config', { hostname: 'example.com', turnstileSecret: 'saved-secret', turnstileEnabled: true });
  const env = baseEnv(store, { TURNSTILE_HOSTNAME: 'old.example' });
  let forwarded = 0;
  let verifiedHostname = 'example.com';
  t.mock.method(globalThis, 'fetch', async (input, init) => {
    if (String(input) === 'https://challenges.cloudflare.com/turnstile/v0/siteverify') {
      assert.equal(new URLSearchParams(init.body).get('secret'), 'saved-secret');
      return Response.json({ success: true, hostname: verifiedHostname, action: 'ghost_signup' });
    }
    forwarded++;
    return new Response('origin', { status: 201 });
  });
  const request = () => new Request(signup(), { headers: { 'content-type': 'application/json', 'cf-turnstile-response': 'valid' } });
  assert.equal((await worker.fetch(request(), env)).status, 201);
  verifiedHostname = 'old.example';
  assert.equal((await worker.fetch(request(), env)).status, 400);
  assert.equal(forwarded, 1);
  assert.equal(mergeConfig({ TURNSTILE_HOSTNAME: 'manual.example' }, null).TURNSTILE_HOSTNAME, 'manual.example');
});

test('setup bounds actual body bytes with missing or misleading Content-Length', async () => {
  for (const length of [undefined, '1']) {
    const store = memoryStore();
    const headers = { 'content-type': 'application/x-www-form-urlencoded', ...(length ? { 'content-length': length } : {}) };
    const response = await worker.fetch(new Request('https://example.com/ghost-guard/setup', { method: 'POST', headers, body: 'padding=' + 'x'.repeat(64 * 1024) }), baseEnv(store));
    assert.equal(response.status, 400);
    assert.match(await response.text(), /setup form is too large/);
    assert.equal(store.data.size, 0);
  }
  const store = memoryStore();
  const atLimit = await worker.fetch(new Request('https://example.com/ghost-guard/setup', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'padding=' + 'x'.repeat(64 * 1024 - 8),
  }), baseEnv(store));
  assert.equal(atLimit.status, 401);
  const multipart = '--boundary\r\nContent-Disposition: form-data; name="padding"\r\n\r\n' + 'x'.repeat(64 * 1024) + '\r\n--boundary--\r\n';
  const oversizedMultipart = await worker.fetch(new Request('https://example.com/ghost-guard/setup', {
    method: 'POST', body: multipart, headers: { 'content-type': 'multipart/form-data; boundary=boundary' },
  }), baseEnv(store));
  assert.equal(oversizedMultipart.status, 400);
});

test('setup cancels a chunked body as soon as it exceeds the limit', async () => {
  let pulls = 0, cancelled = false;
  const stream = new ReadableStream({
    pull(controller) {
      pulls++;
      if (pulls > 100) controller.close();
      else controller.enqueue(new Uint8Array(4096).fill(120));
    },
    cancel() { cancelled = true; },
  });
  const response = await worker.fetch(new Request('https://example.com/ghost-guard/setup', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: stream, duplex: 'half',
  }), baseEnv(memoryStore()));
  assert.equal(response.status, 400);
  assert.equal(cancelled, true);
  assert.ok(pulls < 100);
});

test('a failed widget-secret read stops setup instead of rotating a secret it could not keep', async (t) => {
  const state = world();
  // The listed widget has no secret, so setup would otherwise fall back to rotation.
  state.widgets.push({ sitekey: SITEKEY, name: 'ghost-guard-example.com', domains: ['example.com'] });
  install(t, state);
  const store = memoryStore();
  const inner = store.SETUP_STORE.get();
  const SETUP_STORE = {
    idFromName(name) { return name; },
    get() {
      return {
        // storeFetch passes a Request; read its URL without consuming the body.
        fetch: (request) => request.method === 'GET' && new URL(request.url).pathname === '/widget-secret'
          ? new Response('unavailable', { status: 500 })
          : inner.fetch(request),
      };
    },
  };
  const res = await worker.fetch(formRequest('/ghost-guard/setup', happyFields), baseEnv(store, { SETUP_STORE }));
  assert.match(await res.text(), /setup storage is unavailable/);
  assert.equal(state.rotations || 0, 0);
  assert.equal(store.data.has('config'), false);
});

test('activation is refused when the last run could not confirm the Turnstile widget', async (t) => {
  const state = world();
  install(t, state);
  const store = memoryStore(), env = baseEnv(store);
  await worker.fetch(formRequest('/ghost-guard/setup', happyFields), env);
  const config = store.data.get('config');
  config.checklist = config.checklist.map((item) => item.title === 'Turnstile widget' ? { ...item, ok: false } : item);
  const refused = await worker.fetch(formRequest('/ghost-guard/setup', activationFields(store)), env);
  assert.equal(refused.status, 400);
  assert.match(await refused.text(), /could not confirm the Turnstile widget/);
  assert.equal(store.data.get('config').turnstileEnabled, false);
});

test('signups reuse this isolate’s copy of stored settings until setup saves', async (t) => {
  const state = world();
  install(t, state);
  const store = memoryStore();
  const inner = store.SETUP_STORE.get();
  let reads = 0;
  const SETUP_STORE = {
    idFromName(name) { return name; },
    get() {
      return {
        fetch: (request) => {
          if (request.method === 'GET' && new URL(request.url).pathname === '/config') reads++;
          return inner.fetch(request);
        },
      };
    },
  };
  const env = baseEnv(store, { SETUP_STORE });
  await worker.fetch(formRequest('/ghost-guard/setup', happyFields), env);
  t.mock.method(globalThis, 'fetch', async (input) => String(input?.url || input).includes('siteverify')
    ? Response.json({ success: false })
    : new Response('origin'));
  for (let i = 0; i < 3; i++) await worker.fetch(new Request('https://example.com/blog/post/'), env);
  const afterPages = reads;
  for (let i = 0; i < 3; i++) await worker.fetch(new Request('https://example.com/blog/post/'), env);
  assert.equal(reads, afterPages);
  // Activation in this isolate takes effect on the next signup, not after the cache expires.
  await worker.fetch(formRequest('/ghost-guard/setup', activationFields(store)), env);
  assert.equal((await worker.fetch(signup(), env)).status, 400);
});
