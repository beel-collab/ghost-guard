import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';
import { MemoryRateLimiter } from '../src/rate-limit.js';
import {
  SetupStore, SETUP_FAILURE_LIMIT, codeInjectionSnippet, mergeConfig, GUARD_START, GUARD_END,
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
    routePosts: 0,
    widgetPosts: 0,
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
    if (url.hostname === 'example.com' && url.pathname === '/blog/members/api/send-magic-link/' && method === 'POST') {
      assert.equal(headers.get('authorization'), null);
      const payload = JSON.parse(bodyText);
      assert.equal(payload.emailType, 'signin');
      assert.equal(payload.email, 'ghost-guard-setup-check@example.invalid');
      return json({ success: true }, state.signinStatus);
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
  assert.equal(store.data.get('config').webhookSecret, happyFields.webhook_secret);
  assert.equal(state.calls.some(call => call.url.pathname.includes('/ghost/api/admin/')), false);
  assert.equal(state.calls.some(call => call.url.pathname.endsWith('/secrets')), false);
  assert.equal(JSON.stringify([...store.data.values()]).includes(CF_TOKEN), false);

  const missingCheckbox = await worker.fetch(formRequest('/ghost-guard/setup', {intent:'activate'}), env);
  assert.equal(missingCheckbox.status, 400);
  const unauthorized = await worker.fetch(formRequest('/ghost-guard/setup', {intent:'activate',snippet_installed:'on'}, {token:'wrong'}), env);
  assert.equal(unauthorized.status, 401);
  assert.equal(store.data.get('config').turnstileEnabled, false);
  const activated = await worker.fetch(formRequest('/ghost-guard/setup', {intent:'activate',snippet_installed:'on'}), env);
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

test('signup-only setup needs no Ghost credentials; disabling the labeller clears its stored credentials', async (t) => {
  const state = world();
  install(t, state);
  const store = memoryStore();
  const env = baseEnv(store);
  await worker.fetch(formRequest('/ghost-guard/setup', happyFields), env);
  const {webhook, webhook_secret, admin_api_key, ...fields} = happyFields;
  const response = await worker.fetch(formRequest('/ghost-guard/setup', fields), env);
  assert.match(await response.text(), /Cloudflare ready/);
  const saved = store.data.get('config');
  assert.equal(saved.cleanupEnabled, 'false');
  assert.equal(saved.adminApiKey, '');
  assert.equal(saved.webhookSecret, '');
  const effective = mergeConfig({CLEANUP_ENABLED:'true',ADMIN_API_KEY:ADMIN_KEY}, saved);
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
  assert.equal(mergeConfig(manual,{turnstileSecret:'prepared',turnstileEnabled:false}).TURNSTILE_SECRET,'');
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
