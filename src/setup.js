/**
 * Guided setup for a self-hosted Ghost site on Cloudflare.
 *
 * Runtime config is stored in the SetupStore Durable Object. Environment
 * variables win when they are non-empty (CLEANUP_ENABLED only when it is the
 * string "true", because wrangler.toml ships it as "false"). The Cloudflare
 * API token is used for the setup request and is not stored. The Ghost Admin
 * API key is stored only when the webhook labeller is enabled.
 *
 * Worker secret PUTs are also attempted for TURNSTILE_SECRET, WEBHOOK_SECRET
 * and ADMIN_API_KEY. ADMIN_API_URL, CLEANUP_ENABLED and GHOST_BASE_PATH are
 * plain vars in wrangler.toml, so a secret binding of the same name conflicts,
 * and a settings update would replace every binding. Those three live in the
 * Durable Object only. A failed secret PUT does not undo the Durable Object
 * write: the Worker reads that copy on the next request, including the request
 * that just created the Turnstile widget, before the secret deployment rolls.
 */

import { ADMIN_KEY_PATTERN, adminApiHeaders } from './webhook.js';

export const GUARD_START = '<!-- ghost-guard:start -->';
export const GUARD_END = '<!-- ghost-guard:end -->';
export const SETUP_FAILURE_LIMIT = 8;
export const SETUP_FAILURE_WINDOW_MS = 15 * 60 * 1000;

const WIDGET_MODE = 'managed';

export function pageHeaders() {
  return {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store, no-cache, must-revalidate',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    'x-frame-options': 'DENY',
  };
}

function nonempty(value) {
  return typeof value === 'string' && value.length > 0;
}

// Env wins when it actually carries a value. Empty ADMIN_API_URL and the
// default CLEANUP_ENABLED=false are the wrangler.toml defaults, not a choice
// the operator made, so a completed setup may fill them.
export function mergeConfig(env, stored) {
  if (!stored || typeof stored !== 'object') return env;
  const next = { ...env };
  const fill = (envKey, storedKey) => {
    if (!nonempty(env[envKey]) && nonempty(stored[storedKey])) next[envKey] = stored[storedKey];
  };
  fill('TURNSTILE_SECRET', 'turnstileSecret');
  fill('WEBHOOK_SECRET', 'webhookSecret');
  fill('ADMIN_API_KEY', 'adminApiKey');
  fill('ADMIN_API_URL', 'adminApiUrl');
  fill('GHOST_BASE_PATH', 'ghostBasePath');
  if (env.CLEANUP_ENABLED !== 'true' && stored.cleanupEnabled === 'true') next.CLEANUP_ENABLED = 'true';
  return next;
}

let warnedSetupStore = false;

export async function withStoredConfig(env) {
  if (!env?.SETUP_STORE) return env;
  try {
    const stored = await readConfig(env);
    return mergeConfig(env, stored);
  } catch {
    if (!warnedSetupStore) {
      warnedSetupStore = true;
      console.error('ghost-guard: setup config could not be read');
    }
    return env;
  }
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function scrub(value, secrets) {
  let text = String(value ?? '');
  for (const secret of secrets || []) {
    if (typeof secret === 'string' && secret.length >= 8) text = text.split(secret).join('[redacted]');
  }
  return text.slice(0, 500);
}

function httpError(message, status, extra) {
  const error = new Error(message);
  error.status = status;
  if (extra) Object.assign(error, extra);
  return error;
}

export function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function tokensMatch(provided, expected) {
  const left = String(provided ?? '');
  const right = String(expected ?? '');
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(left.slice(0, 4096))),
    crypto.subtle.digest('SHA-256', enc.encode(right.slice(0, 4096))),
  ]);
  const x = new Uint8Array(a);
  const y = new Uint8Array(b);
  let diff = left.length === right.length ? 0 : 1;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Replace the marked block. Content outside the markers is kept. A second
// marked block is removed so a re-run cannot stack snippets.
export function mergeCodeInjection(existing, sitekey) {
  if (!/^[A-Za-z0-9_-]+$/.test(sitekey)) throw new Error('Unexpected Turnstile site key.');
  const block = `${GUARD_START}\n<script src="/ghost-guard/turnstile.js" data-sitekey="${sitekey}"></script>\n${GUARD_END}`;
  const source = existing == null ? '' : String(existing);
  const pair = new RegExp(`${escapeRegex(GUARD_START)}[\\s\\S]*?${escapeRegex(GUARD_END)}`, 'g');
  if (pair.test(source)) {
    pair.lastIndex = 0;
    let replaced = false;
    return source.replace(pair, () => (replaced ? '' : ((replaced = true), block)));
  }
  const stripped = source.replaceAll(GUARD_START, '').replaceAll(GUARD_END, '').replace(/\s*$/, '');
  return stripped ? `${stripped}\n${block}\n` : `${block}\n`;
}

function sanitizeChecklist(list) {
  if (!Array.isArray(list)) return [];
  return list.slice(0, 12).map((item) => ({
    title: String(item?.title || '').slice(0, 80),
    ok: item?.ok === true,
    detail: String(item?.detail || '').slice(0, 500),
  }));
}

export function sanitizeConfig(input) {
  const source = input && typeof input === 'object' ? input : {};
  const webhookEnabled = source.webhookEnabled === true;
  return {
    complete: source.complete === true,
    hostname: String(source.hostname || '').slice(0, 253),
    siteUrl: String(source.siteUrl || '').slice(0, 500),
    ghostBasePath: String(source.ghostBasePath || '').slice(0, 200),
    turnstileSitekey: String(source.turnstileSitekey || '').slice(0, 64),
    turnstileSecret: String(source.turnstileSecret || '').slice(0, 256),
    webhookEnabled,
    webhookSecret: webhookEnabled ? String(source.webhookSecret || '').slice(0, 256) : '',
    adminApiUrl: webhookEnabled ? String(source.adminApiUrl || '').slice(0, 500) : '',
    adminApiKey: webhookEnabled ? String(source.adminApiKey || '').slice(0, 128) : '',
    cleanupEnabled: webhookEnabled ? 'true' : 'false',
    scriptName: String(source.scriptName || 'ghost-guard').slice(0, 64),
    checklist: sanitizeChecklist(source.checklist),
    updatedAt: Date.now(),
  };
}

// One object per deployment. Requests are serialized so token creation and
// the failure counter cannot race inside the object.
export class SetupStore {
  constructor(ctx) {
    this.storage = ctx.storage;
    this.tail = Promise.resolve();
  }

  fetch(request) {
    const run = this.tail.then(() => this.#handle(request));
    this.tail = run.then(() => undefined, () => undefined);
    return run;
  }

  async #handle(request) {
    const url = new URL(request.url);
    const { pathname } = url;
    if (request.method === 'POST' && pathname === '/token') {
      let token = await this.storage.get('setupToken');
      let created = false;
      if (typeof token !== 'string' || !token) {
        token = randomToken();
        await this.storage.put('setupToken', token);
        created = true;
      }
      return Response.json({ token, created });
    }
    if (request.method === 'POST' && pathname === '/gate') {
      const { ip, match } = await request.json();
      const key = `fail:${String(ip || '').slice(0, 128)}`;
      const now = Date.now();
      const row = await this.storage.get(key);
      const active = row && row.expires > now ? row : null;
      if (active && active.count >= SETUP_FAILURE_LIMIT) {
        return Response.json({
          ok: false,
          limited: true,
          retryAfter: Math.max(1, Math.ceil((active.expires - now) / 1000)),
        });
      }
      if (match === true) {
        if (active) await this.storage.delete(key);
        return Response.json({ ok: true, limited: false });
      }
      const count = (active?.count || 0) + 1;
      const expires = active?.expires || now + SETUP_FAILURE_WINDOW_MS;
      await this.storage.put(key, { count, expires });
      return Response.json({ ok: false, limited: false });
    }
    if (request.method === 'GET' && pathname === '/config') {
      const value = await this.storage.get('config');
      return Response.json({ value: value || null });
    }
    if (request.method === 'PUT' && pathname === '/config') {
      const body = await request.json();
      await this.storage.put('config', sanitizeConfig(body.value));
      return Response.json({ ok: true });
    }
    return new Response('Not Found', { status: 404 });
  }
}

function storeStub(env) {
  if (!env.SETUP_STORE) return null;
  return env.SETUP_STORE.get(env.SETUP_STORE.idFromName('setup'));
}

async function storeFetch(env, pathname, init) {
  const stub = storeStub(env);
  if (!stub) throw httpError('Fix: the SETUP_STORE binding is missing. Deploy the current wrangler.toml so the v3 migration runs.', 503);
  return stub.fetch(new Request(`https://setup-store${pathname}`, {
    method: init?.method || 'GET',
    headers: init?.body ? { 'content-type': 'application/json' } : undefined,
    body: init?.body,
  }));
}

async function readConfig(env) {
  const res = await storeFetch(env, '/config');
  if (!res.ok) throw new Error('setup store unavailable');
  const body = await res.json();
  return body?.value || null;
}

async function writeConfig(env, value) {
  const res = await storeFetch(env, '/config', { method: 'PUT', body: JSON.stringify({ value }) });
  if (!res.ok) throw httpError('Fix: setup storage could not be saved. Deploy the current wrangler.toml and run setup again.', 503);
}

async function expectedToken(env) {
  const configured = typeof env.SETUP_TOKEN === 'string' ? env.SETUP_TOKEN.trim() : '';
  if (configured) return { token: configured, source: 'env' };
  const res = await storeFetch(env, '/token', { method: 'POST' });
  if (!res.ok) throw httpError('Fix: the setup token could not be stored. Deploy the current wrangler.toml and try again.', 503);
  const body = await res.json();
  if (body.created) {
    console.log(`ghost-guard: SETUP_TOKEN is not set. A setup token was generated and stored. Token: ${body.token}. Enter it at /ghost-guard/setup. It is not shown on the setup page. To set your own, run: npx wrangler secret put SETUP_TOKEN`);
  }
  return { token: body.token, source: 'stored' };
}

async function authorize(request, env, provided, expected) {
  const match = await tokensMatch(String(provided || '').slice(0, 4096), expected);
  const ipHash = await digest(request.headers.get('CF-Connecting-IP') || 'unknown');
  const res = await storeFetch(env, '/gate', { method: 'POST', body: JSON.stringify({ ip: ipHash, match }) });
  if (!res.ok) throw httpError('Fix: setup storage is unavailable. Try again shortly.', 503);
  const gate = await res.json();
  if (gate.limited) throw httpError('Too many setup attempts from this address. Try again later.', 429, { retryAfter: gate.retryAfter });
  if (!gate.ok) throw httpError('That setup token is not valid.', 401);
}

async function digest(value) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function scriptNameFrom(request, env) {
  const configured = String(env.SCRIPT_NAME || '').trim();
  if (/^[a-z0-9][a-z0-9-]{0,62}$/i.test(configured)) return configured;
  const host = new URL(request.url).hostname.toLowerCase();
  const match = host.match(/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.workers\.dev$/);
  return match ? match[1] : 'ghost-guard';
}

function layout(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>${escapeHtml(title)}</title>
  <style>
    :root { color-scheme: light dark; }
    body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 0; min-height: 100vh; background: #f6f6f4; color: #15171a; }
    main { width: min(40rem, calc(100% - 2rem)); margin: 2rem auto; background: #fff; border-radius: 12px; padding: 2rem; box-shadow: 0 8px 30px rgba(0,0,0,.08); }
    h1 { font-size: 1.4rem; margin: 0 0 .75rem; }
    h2 { font-size: 1.05rem; margin: 1.5rem 0 .5rem; }
    p, li { line-height: 1.5; }
    label { display: block; font-weight: 600; margin: 1rem 0 .3rem; }
    input[type="text"], input[type="url"], input[type="password"] { width: 100%; box-sizing: border-box; font: inherit; padding: .6rem .7rem; border: 1px solid #c5c8cb; border-radius: 8px; background: #fff; color: inherit; }
    .hint, .check { font-weight: 400; }
    .hint { color: #52616a; font-size: .9rem; }
    button { appearance: none; border: 0; border-radius: 8px; background: #15171a; color: #fff; font: inherit; font-weight: 600; padding: .8rem 1.2rem; cursor: pointer; margin-top: 1.25rem; }
    .error { color: #a30; font-weight: 600; }
    .ok { color: #0a7a32; }
    .bad { color: #a30; }
    a { color: inherit; }
    @media (prefers-color-scheme: dark) {
      body { background: #111; color: #f4f4f2; }
      main { background: #1c1e21; box-shadow: none; }
      input { background: #111; border-color: #444; }
      button { background: #f4f4f2; color: #15171a; }
      .hint { color: #b7c0c6; }
    }
  </style>
</head>
<body>
  <main>
    ${body}
  </main>
</body>
</html>`;
}

function generatedNote(generated) {
  if (!generated) return '<p class="hint">Enter the SETUP_TOKEN for this Worker.</p>';
  return '<p class="hint">No SETUP_TOKEN is set. A token was written to this Worker\'s logs only. Run <code>npx wrangler tail</code> or open the dashboard logs, then enter it here. To choose your own: <code>npx wrangler secret put SETUP_TOKEN</code>.</p>';
}

function renderMessage(message) {
  return layout('Set up ghost-guard', `<h1>Set up ghost-guard</h1><p class="error" role="alert">${escapeHtml(message)}</p><p><a href="/ghost-guard/setup">Back to setup</a></p>`);
}

function renderGate({ generated }) {
  return layout('Set up ghost-guard', `<h1>ghost-guard setup</h1>
    <p>Setup is already complete. Enter the setup token to view status. Running setup again asks for the token on the form.</p>
    ${generatedNote(generated)}
    <form method="post" action="" autocomplete="off">
      <label for="setup_token">Setup token</label>
      <input id="setup_token" name="setup_token" type="password" required maxlength="256" autocomplete="current-password">
      <button type="submit" name="intent" value="view">View status</button>
    </form>
    <p><a href="?rerun=1">Run setup again</a></p>`);
}

function formFields(values = {}) {
  const check = values.webhook ? ' checked' : '';
  return `<form method="post" action="" autocomplete="off">
      <input type="hidden" name="intent" value="run">
      <label for="setup_token">Setup token</label>
      <input id="setup_token" name="setup_token" type="password" required maxlength="256" autocomplete="current-password">
      <label for="ghost_url">Ghost site URL</label>
      <input id="ghost_url" name="ghost_url" type="url" required maxlength="500" placeholder="https://yourdomain.com" value="${escapeHtml(values.ghost_url || '')}">
      <p class="hint">The public https URL. Include a subfolder if Ghost lives in one, for example https://yourdomain.com/blog.</p>
      <label for="admin_api_key">Ghost Admin API key</label>
      <input id="admin_api_key" name="admin_api_key" type="password" required maxlength="128" autocomplete="off" placeholder="id:secret">
      <p class="hint">From a custom integration: Ghost Admin, Settings, Advanced, Integrations. The id:secret key. It is not shown again. It is stored only if you enable the webhook labeller.</p>
      <label for="cf_api_token">Cloudflare API token</label>
      <input id="cf_api_token" name="cf_api_token" type="password" required maxlength="4096" autocomplete="off">
      <p class="hint">Used for this request and not stored. Permissions: Zone, Workers Routes, Edit; Account, Turnstile, Edit; Account, Workers Scripts, Edit. Include this zone in the token.</p>
      <label for="account_id">Cloudflare account ID <span class="hint">(optional)</span></label>
      <input id="account_id" name="account_id" type="text" maxlength="32" value="${escapeHtml(values.account_id || '')}">
      <p class="hint">Leave blank to use the account that owns the zone.</p>
      <label for="ghost_base_path">Ghost subfolder <span class="hint">(optional)</span></label>
      <input id="ghost_base_path" name="ghost_base_path" type="text" maxlength="200" placeholder="/blog" value="${escapeHtml(values.ghost_base_path || '')}">
      <p class="hint">Only if GHOST_ORIGIN is set and Ghost is not at the domain root. Leave blank to use the path from the site URL.</p>
      <label class="check"><input name="webhook" type="checkbox" value="on"${check}> Enable the webhook labeller</label>
      <p class="hint">Adds the label signup-shield-review to new free members from non-consumer domains. Does not delete members. Ghost will attach the member.added webhook to the custom integration that owns the Admin API key.</p>
      <button type="submit">Run setup</button>
    </form>`;
}

function renderForm({ generated, values }) {
  return layout('Set up ghost-guard', `<h1>Set up ghost-guard</h1>
    <p>One form attaches the Worker route, creates a Turnstile widget, and adds the site-header snippet. It is safe to submit again.</p>
    ${generatedNote(generated)}
    ${formFields(values)}`);
}

function renderItems(items) {
  return `<ul>${items.map((item) => `<li class="${item.ok ? 'ok' : 'bad'}"><strong>${item.ok ? 'OK' : 'Needs attention'}.</strong> ${escapeHtml(item.title)}. ${escapeHtml(item.detail)}</li>`).join('')}</ul>`;
}

function renderResult({ steps, checks, secrets, values, ok }) {
  const safeSteps = steps.map((step) => ({ ...step, detail: scrub(step.detail, secrets) }));
  const safeChecks = (checks || []).map((check) => ({ ...check, detail: scrub(check.detail, secrets) }));
  const summary = ok
    ? '<p>Setup finished. Environment variables still override this stored configuration when they are set.</p>'
    : '<p class="error">Setup stopped at the first failed step. Earlier steps were kept. Submit the form again; existing routes, widgets and webhooks are reused.</p>';
  const checksHtml = safeChecks.length ? `<h2>Checks</h2>${renderItems(safeChecks)}` : '';
  return layout(ok ? 'ghost-guard setup complete' : 'ghost-guard setup needs attention', `<h1>${ok ? 'Setup complete' : 'Setup did not finish'}</h1>
    ${summary}
    <h2>Steps</h2>
    ${renderItems(safeSteps)}
    ${checksHtml}
    <p><a href="/ghost-guard/setup">View status</a> or <a href="/ghost-guard/setup?rerun=1">run setup again</a>.</p>
    ${ok ? '' : formFields(values)}`);
}

function renderStatus(config) {
  const items = config?.checklist?.length ? config.checklist : [{ title: 'Saved checklist', ok: false, detail: 'Fix: run setup again to refresh the checklist.' }];
  const host = config?.hostname ? ` for ${escapeHtml(config.hostname)}` : '';
  return layout('ghost-guard status', `<h1>ghost-guard status${host}</h1>
    <p>This is the last setup run. Secrets are not shown. Run setup again to change it; the token is required on that form.</p>
    ${renderItems(items)}
    <p><a href="?rerun=1">Run setup again</a></p>`);
}

function manualPage() {
  const body = `<h1>Set up ghost-guard</h1>
    <p>This guided setup runs on the Cloudflare Worker. It creates the Worker route, the Turnstile widget and the Ghost code-injection snippet.</p>
    <p>The Node sidecar does not call the Cloudflare API. Configure the proxy, Turnstile and the snippet by hand.</p>
    <p><a href="https://github.com/beel-collab/ghost-guard#quick-start">Manual setup in the README</a></p>`;
  return new Response(layout('Set up ghost-guard', body), { status: 200, headers: pageHeaders() });
}

function htmlResponse(status, html, extra) {
  return new Response(html, { status, headers: { ...pageHeaders(), ...extra } });
}

async function readForm(request) {
  const length = Number(request.headers.get('content-length') || 0);
  if (Number.isFinite(length) && length > 64 * 1024) throw httpError('The setup form is too large.', 400);
  const type = request.headers.get('content-type') || '';
  if (!type.includes('application/x-www-form-urlencoded') && !type.includes('multipart/form-data')) {
    throw httpError('Submit the setup form from this page.', 400);
  }
  try {
    return await request.formData();
  } catch {
    throw httpError('The setup form could not be read. Submit it again.', 400);
  }
}

export async function handleSetup(request, env) {
  if (env.SIDECAR === true) {
    if (!['GET', 'HEAD', 'POST'].includes(request.method)) {
      return new Response('Method Not Allowed', { status: 405, headers: { ...pageHeaders(), 'content-type': 'text/plain; charset=utf-8', Allow: 'GET, HEAD, POST' } });
    }
    if (request.method === 'HEAD') return new Response(null, { status: 200, headers: pageHeaders() });
    return manualPage();
  }
  if (!['GET', 'HEAD', 'POST'].includes(request.method)) {
    return new Response('Method Not Allowed', { status: 405, headers: { ...pageHeaders(), 'content-type': 'text/plain; charset=utf-8', Allow: 'GET, HEAD, POST' } });
  }
  if (request.method === 'HEAD') return new Response(null, { status: 200, headers: pageHeaders() });
  const secrets = [];
  try {
    if (!env.SETUP_STORE) {
      return htmlResponse(503, renderMessage('Fix: the SETUP_STORE binding is missing. Deploy the current wrangler.toml so the v3 migration runs.'));
    }
    const url = new URL(request.url);
    const tokenInfo = await expectedToken(env);
    secrets.push(tokenInfo.token);
    if (request.method === 'GET') {
      const config = await readConfig(env);
      if (config?.complete && url.searchParams.get('rerun') !== '1') {
        return htmlResponse(200, renderGate({ generated: tokenInfo.source === 'stored' }));
      }
      return htmlResponse(200, renderForm({ generated: tokenInfo.source === 'stored' }));
    }
    const form = await readForm(request);
    const provided = String(form.get('setup_token') || '');
    secrets.push(provided);
    await authorize(request, env, provided, tokenInfo.token);
    const config = await readConfig(env);
    const intent = String(form.get('intent') || '');
    const ghostUrl = String(form.get('ghost_url') || '').trim();
    if (intent === 'view' || (!ghostUrl && config?.complete && intent !== 'run')) {
      return htmlResponse(200, renderStatus(config));
    }
    const values = {
      ghost_url: ghostUrl,
      account_id: String(form.get('account_id') || '').trim(),
      ghost_base_path: String(form.get('ghost_base_path') || '').trim(),
      webhook: form.get('webhook') != null,
    };
    const cfToken = String(form.get('cf_api_token') || '');
    const adminKey = String(form.get('admin_api_key') || '').trim();
    secrets.push(cfToken, adminKey, adminKey.split(':')[1]);
    const result = await runSetup({ request, env, values, cfToken, adminKey, secrets });
    return htmlResponse(200, renderResult(result));
  } catch (error) {
    const status = error.status || 500;
    const headers = {};
    if (error.retryAfter) headers['retry-after'] = String(error.retryAfter);
    const message = status === 500 ? 'Setup could not be completed. Try again.' : scrub(error.message, secrets);
    if (status === 500) console.error('ghost-guard: setup failed');
    return htmlResponse(status, renderMessage(message), headers);
  }
}

async function normalizeBasePath(value) {
  const { ghostBasePath } = await import('./worker.js');
  try {
    return ghostBasePath({ GHOST_BASE_PATH: value });
  } catch (error) {
    throw httpError(`Fix: ${error.message}`, 400);
  }
}

async function parseSite(values) {
  let url;
  try {
    url = new URL(values.ghost_url);
  } catch {
    throw httpError('Fix: enter the public Ghost site URL, including https://.', 400);
  }
  if (url.username || url.password) throw httpError('Fix: enter the Ghost site URL without a username or password.', 400);
  if (url.protocol !== 'https:') throw httpError('Fix: the Ghost site URL must start with https://.', 400);
  const hostname = url.hostname.toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(hostname) || hostname.endsWith('.workers.dev')) {
    throw httpError('Fix: use the public Ghost hostname that Cloudflare proxies, not a workers.dev hostname.', 400);
  }
  const rawBase = values.ghost_base_path || (url.pathname === '/' ? '' : url.pathname);
  const ghostBasePath = rawBase ? await normalizeBasePath(rawBase) : '';
  const siteUrl = `${url.origin}${ghostBasePath}`;
  return { hostname, ghostBasePath, siteUrl };
}

async function cfFetch(token, url, options = {}) {
  const res = await fetch(url, {
    method: options.method || 'GET',
    headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json' },
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    signal: AbortSignal.timeout(15_000),
  });
  const text = await res.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {};
  }
  if (!res.ok || data.success === false) {
    const message = data?.errors?.[0]?.message || `HTTP ${res.status}`;
    const error = httpError(`Fix: Cloudflare API ${message}. The token needs Zone Workers Routes Edit, Account Turnstile Edit, and Account Workers Scripts Edit.`, res.status);
    error.cfStatus = res.status;
    throw error;
  }
  return data;
}

function safeId(value) {
  const id = String(value || '');
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) throw httpError('Fix: Cloudflare returned an unexpected id. Run setup again.', 502);
  return id;
}

async function findZone(token, hostname, accountId) {
  const labels = hostname.split('.');
  for (let i = 0; i <= labels.length - 2; i++) {
    const name = labels.slice(i).join('.');
    const url = new URL('https://api.cloudflare.com/client/v4/zones');
    url.searchParams.set('name', name);
    if (accountId) url.searchParams.set('account.id', accountId);
    const data = await cfFetch(token, url);
    const zone = (data.result || []).find((item) => item.name === name);
    if (zone) return zone;
  }
  throw httpError(`Fix: no Cloudflare zone for ${hostname} was visible to this token. Include that zone in the token and proxy the hostname, then run setup again.`, 400);
}

async function ghostFetch(adminKey, siteUrl, path, options = {}) {
  const url = `${siteUrl.replace(/\/+$/, '')}/ghost/api/admin/${path}`;
  const send = async (version) => {
    const headers = await adminApiHeaders(adminKey, version);
    return fetch(url, {
      method: options.method || 'GET',
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      redirect: 'manual',
      signal: AbortSignal.timeout(15_000),
    });
  };
  let res = await send('v6.0');
  if (res.status === 406) {
    await res.body?.cancel?.();
    res = await send('v5.0');
  }
  if (res.status >= 300 && res.status < 400) {
    throw httpError('Fix: the Ghost Admin API redirected. Use the public site URL, including the subfolder.', 502);
  }
  const text = await res.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {};
  }
  if (!res.ok) {
    const message = data?.errors?.[0]?.message || `HTTP ${res.status}`;
    throw httpError(`Fix: Ghost Admin API ${message}.`, res.status);
  }
  return data;
}

function widgetName(hostname) {
  return `ghost-guard-${hostname}`.slice(0, 254);
}

function domainsInclude(widget, hostname) {
  return (widget.domains || []).map((domain) => String(domain).toLowerCase()).includes(hostname);
}

async function listWidgets(token, accountId) {
  const widgets = [];
  for (let page = 1; page <= 20; page++) {
    const url = new URL(`https://api.cloudflare.com/client/v4/accounts/${accountId}/challenges/widgets`);
    url.searchParams.set('page', String(page));
    url.searchParams.set('per_page', '50');
    const data = await cfFetch(token, url);
    const batch = data.result || [];
    widgets.push(...batch);
    const pages = data.result_info?.total_pages;
    if (!pages || page >= pages || batch.length === 0) break;
  }
  return widgets;
}

async function putWorkerSecrets(token, accountId, scriptName, entries) {
  const failures = [];
  for (const [name, text] of Object.entries(entries)) {
    if (!text) continue;
    try {
      await cfFetch(token, `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${encodeURIComponent(scriptName)}/secrets`, {
        method: 'PUT',
        body: { name, text, type: 'secret_text' },
      });
    } catch (error) {
      failures.push(`${name}: ${error.message}`);
    }
  }
  return failures;
}

async function listWebhooks(adminKey, siteUrl) {
  const hooks = [];
  for (let page = 1; page <= 10; page++) {
    const data = await ghostFetch(adminKey, siteUrl, `webhooks/?limit=100&page=${page}`);
    const batch = data.webhooks || [];
    hooks.push(...batch);
    const pages = data.meta?.pagination?.pages;
    if (!pages || page >= pages || batch.length === 0) break;
  }
  return hooks;
}

function sameTarget(left, right) {
  try {
    return new URL(left).href === new URL(right).href;
  } catch {
    return false;
  }
}

async function runSetup({ request, env, values, cfToken, adminKey, secrets }) {
  if (!nonempty(cfToken) || cfToken.length > 4096) throw httpError('Fix: enter a Cloudflare API token.', 400);
  if (!ADMIN_KEY_PATTERN.test(adminKey)) {
    throw httpError('Fix: the Ghost Admin API key must be the id:secret value from a custom integration.', 400);
  }
  if (values.account_id && !/^[a-f0-9]{32}$/i.test(values.account_id)) {
    throw httpError('Fix: the account ID is the 32-character id from the Cloudflare dashboard, or leave it blank.', 400);
  }
  const site = await parseSite(values);
  const scriptName = scriptNameFrom(request, env);
  const integrationId = adminKey.split(':')[0].toLowerCase();
  const ctx = {
    ...site,
    scriptName,
    integrationId,
    cfToken,
    adminKey,
    accountId: values.account_id.toLowerCase(),
    webhookEnabled: values.webhook === true,
    webhookTarget: `https://${site.hostname}/signup-shield/webhooks/member-added`,
    requestHost: new URL(request.url).hostname.toLowerCase(),
    secrets,
  };
  const steps = [];
  const run = async (title, fn) => {
    try {
      const detail = await fn();
      steps.push({ title, ok: true, detail: scrub(detail, secrets) });
      return true;
    } catch (error) {
      steps.push({ title, ok: false, detail: scrub(error.message || 'This step failed.', secrets) });
      return false;
    }
  };

  const persisted = () => ({
    complete: false,
    hostname: ctx.hostname,
    siteUrl: ctx.siteUrl,
    ghostBasePath: ctx.ghostBasePath,
    turnstileSitekey: ctx.turnstileSitekey || '',
    turnstileSecret: ctx.turnstileSecret || '',
    webhookEnabled: false,
    scriptName,
    checklist: [],
  });

  if (!await run('Cloudflare zone', async () => {
    const zone = await findZone(cfToken, ctx.hostname, ctx.accountId);
    const accountId = zone.account?.id;
    if (ctx.accountId && accountId && accountId !== ctx.accountId) {
      throw httpError('Fix: that account ID does not own this hostname. Leave the field blank to use the zone account.', 400);
    }
    ctx.zoneId = safeId(zone.id);
    ctx.accountId = safeId(accountId);
    return `Zone ${zone.name} in account ${ctx.accountId}.`;
  })) return { steps, checks: [], secrets, values, ok: false };

  if (!await run('Worker route', async () => {
    const pattern = `${ctx.hostname}/*`;
    const data = await cfFetch(cfToken, `https://api.cloudflare.com/client/v4/zones/${ctx.zoneId}/workers/routes`);
    const existing = (data.result || []).find((route) => route.pattern === pattern);
    if (existing?.script === scriptName) return `Route ${pattern} is already attached to ${scriptName}.`;
    if (existing?.script) throw httpError(`Fix: ${pattern} already points at ${existing.script}. Point it at ${scriptName}, or remove it, then run setup again.`, 409);
    if (existing) {
      await cfFetch(cfToken, `https://api.cloudflare.com/client/v4/zones/${ctx.zoneId}/workers/routes/${safeId(existing.id)}`, {
        method: 'PUT',
        body: { pattern, script: scriptName },
      });
      return `Route ${pattern} now points at ${scriptName}.`;
    }
    await cfFetch(cfToken, `https://api.cloudflare.com/client/v4/zones/${ctx.zoneId}/workers/routes`, {
      method: 'POST',
      body: { pattern, script: scriptName },
    });
    return `Route ${pattern} now points at ${scriptName}.`;
  })) return { steps, checks: [], secrets, values, ok: false };

  if (!await run('Turnstile widget', async () => {
    const name = widgetName(ctx.hostname);
    const widgets = await listWidgets(cfToken, ctx.accountId);
    const named = widgets.filter((item) => item.name === name);
    let widget = named.find((item) => domainsInclude(item, ctx.hostname)) || named[0];
    if (widget) {
      if (!domainsInclude(widget, ctx.hostname)) {
        const domains = [...new Set([...(widget.domains || []).map((domain) => String(domain).toLowerCase()), ctx.hostname])];
        const updated = await cfFetch(cfToken, `https://api.cloudflare.com/client/v4/accounts/${ctx.accountId}/challenges/widgets/${encodeURIComponent(widget.sitekey)}`, {
          method: 'PUT',
          body: { name, domains, mode: WIDGET_MODE },
        });
        widget = { ...widget, ...updated.result };
      }
      if (!widget.secret) {
        const detail = await cfFetch(cfToken, `https://api.cloudflare.com/client/v4/accounts/${ctx.accountId}/challenges/widgets/${encodeURIComponent(widget.sitekey)}`);
        widget = { ...widget, ...detail.result };
      }
      const stored = await readConfig(env);
      if (!widget.secret && stored?.turnstileSitekey === widget.sitekey && stored.turnstileSecret) {
        widget = { ...widget, secret: stored.turnstileSecret };
      }
      if (!widget.secret) {
        const rotated = await cfFetch(cfToken, `https://api.cloudflare.com/client/v4/accounts/${ctx.accountId}/challenges/widgets/${encodeURIComponent(widget.sitekey)}/rotate_secret`, {
          method: 'POST',
          body: { invalidate_immediately: false },
        });
        widget = { ...widget, secret: rotated.result?.secret, sitekey: rotated.result?.sitekey || widget.sitekey };
      }
    } else {
      const created = await cfFetch(cfToken, `https://api.cloudflare.com/client/v4/accounts/${ctx.accountId}/challenges/widgets`, {
        method: 'POST',
        body: { name, domains: [ctx.hostname], mode: WIDGET_MODE },
      });
      widget = created.result;
    }
    if (!widget?.sitekey || !widget.secret) throw httpError('Fix: Turnstile did not return a site key and secret. Run setup again.', 502);
    if (!/^[A-Za-z0-9_-]+$/.test(widget.sitekey)) throw httpError('Fix: Turnstile returned an unexpected site key. Run setup again.', 502);
    ctx.turnstileSitekey = widget.sitekey;
    ctx.turnstileSecret = widget.secret;
    secrets.push(widget.secret);
    return `Turnstile widget ${name} is ready.`;
  })) return { steps, checks: [], secrets, values, ok: false };

  // Snippet before the secret is visible to request handling, so signups are
  // not rejected for a missing token in the gap.
  if (!await run('Ghost code injection', async () => {
    const data = await ghostFetch(adminKey, ctx.siteUrl, 'settings/');
    const current = (data.settings || []).find((item) => item.key === 'codeinjection_head')?.value || '';
    const merged = mergeCodeInjection(current, ctx.turnstileSitekey);
    await ghostFetch(adminKey, ctx.siteUrl, 'settings/', {
      method: 'PUT',
      body: { settings: [{ key: 'codeinjection_head', value: merged }] },
    });
    ctx.injection = merged;
    return 'The site header snippet is in place. Other header HTML was left as it was.';
  })) return { steps, checks: [], secrets, values, ok: false };

  if (!await run('Save configuration', async () => {
    await writeConfig(env, persisted());
    const failures = await putWorkerSecrets(cfToken, ctx.accountId, scriptName, { TURNSTILE_SECRET: ctx.turnstileSecret });
    if (failures.length) {
      return `The Turnstile secret is stored for this Worker. Updating the Worker secret did not apply (${failures.join(' ')}). The Worker reads the stored copy, and an environment variable still wins when it is set.`;
    }
    return 'The Turnstile secret is saved as a Worker secret and in this Worker\'s setup store.';
  })) return { steps, checks: [], secrets, values, ok: false };

  if (!await run('Webhook labeller', async () => {
    if (!ctx.webhookEnabled) return 'Webhook labeller is off.';
    const hooks = await listWebhooks(adminKey, ctx.siteUrl);
    const existing = hooks.find((hook) => hook.event === 'member.added' && sameTarget(hook.target_url, ctx.webhookTarget));
    let webhookSecret = typeof existing?.secret === 'string' && existing.secret.length >= 16 ? existing.secret : '';
    if (existing && !webhookSecret) {
      webhookSecret = randomToken();
      await ghostFetch(adminKey, ctx.siteUrl, `webhooks/${encodeURIComponent(existing.id)}/`, {
        method: 'PUT',
        body: { webhooks: [{ event: 'member.added', target_url: ctx.webhookTarget, name: 'ghost-guard', secret: webhookSecret, integration_id: integrationId }] },
      });
    }
    if (!existing) {
      webhookSecret = randomToken();
      const webhook = { event: 'member.added', target_url: ctx.webhookTarget, name: 'ghost-guard', secret: webhookSecret, integration_id: integrationId };
      try {
        await ghostFetch(adminKey, ctx.siteUrl, 'webhooks/', { method: 'POST', body: { webhooks: [webhook] } });
      } catch (error) {
        if (!/integration|validation/i.test(error.message)) throw error;
        try {
          const withoutIntegration = { ...webhook };
          delete withoutIntegration.integration_id;
          await ghostFetch(adminKey, ctx.siteUrl, 'webhooks/', { method: 'POST', body: { webhooks: [withoutIntegration] } });
        } catch {
          throw httpError('Fix: Ghost only creates webhooks for the custom integration this Admin API key belongs to. Use that integration\'s id:secret key and run setup again.', error.status || 422);
        }
      }
    }
    secrets.push(webhookSecret);
    ctx.webhookSecret = webhookSecret;
    await writeConfig(env, {
      ...persisted(),
      webhookEnabled: true,
      webhookSecret,
      adminApiUrl: ctx.siteUrl,
      adminApiKey: adminKey,
    });
    const failures = await putWorkerSecrets(cfToken, ctx.accountId, scriptName, {
      WEBHOOK_SECRET: webhookSecret,
      ADMIN_API_KEY: adminKey,
    });
    const reused = existing ? 'Reused the member.added webhook.' : 'Created the member.added webhook.';
    if (failures.length) return `${reused} Its secret is stored for this Worker. Updating Worker secrets did not apply (${failures.join(' ')}).`;
    return `${reused} It targets ${ctx.webhookTarget}.`;
  })) return { steps, checks: [], secrets, values, ok: false };

  const checks = await runChecks(ctx);
  await writeConfig(env, {
    ...persisted(),
    webhookEnabled: ctx.webhookEnabled,
    webhookSecret: ctx.webhookSecret || '',
    adminApiUrl: ctx.webhookEnabled ? ctx.siteUrl : '',
    adminApiKey: ctx.webhookEnabled ? adminKey : '',
    complete: true,
    checklist: checks.map((check) => ({ title: check.title, ok: check.ok, detail: scrub(check.detail, secrets) })),
  });
  return { steps, checks, secrets, values, ok: true };
}

async function readLimited(res) {
  const text = await res.text();
  return text.slice(0, 100_000);
}

async function runChecks(ctx) {
  const checks = [];
  checks.push(await checkRoute(ctx));
  checks.push(await checkTurnstile(ctx));
  checks.push(await checkSnippet(ctx));
  checks.push(await checkConfirm(ctx));
  checks.push(await checkSignin(ctx));
  checks.push(await checkWebhook(ctx));
  return checks;
}

async function checkRoute(ctx) {
  const title = 'Route reachable';
  const url = `https://${ctx.hostname}/ghost-guard/turnstile.js`;
  let failure = 'the script was not returned';
  try {
    const res = await fetch(url, { redirect: 'manual', cache: 'no-store', signal: AbortSignal.timeout(10_000) });
    const text = await readLimited(res);
    if (res.status === 200 && text.includes('__ghostGuardTurnstile')) {
      return { title, ok: true, detail: 'The public hostname served the Turnstile script.' };
    }
    failure = `the public URL returned HTTP ${res.status} without the ghost-guard script`;
  } catch (error) {
    failure = `the public URL could not be fetched (${error.message})`;
  }
  // A Worker fetch to its own zone skips the Worker and hits the origin.
  // Loading this page on that hostname is the proof the route is attached.
  if (ctx.requestHost === ctx.hostname) {
    return { title, ok: true, detail: 'This page is served by the Worker on that hostname. A fetch from the Worker to its own zone skips the Worker, so this check uses the route that was just confirmed.' };
  }
  return { title, ok: false, detail: `Fix: open ${url} in a browser and confirm it is the ghost-guard script. This run saw that ${failure}.` };
}

async function checkTurnstile(ctx) {
  const title = 'Turnstile widget';
  try {
    const body = new URLSearchParams();
    body.set('secret', ctx.turnstileSecret);
    body.set('response', 'ghost-guard-setup-check');
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body,
      signal: AbortSignal.timeout(10_000),
    });
    const data = await res.json();
    const codes = data['error-codes'] || [];
    if (codes.includes('invalid-input-secret') || codes.includes('missing-input-secret')) {
      return { title, ok: false, detail: 'Fix: Turnstile rejected the widget secret. Run setup again.' };
    }
    if (data.success === true || codes.includes('invalid-input-response')) {
      return { title, ok: true, detail: 'The Turnstile secret was accepted for this widget.' };
    }
    return { title, ok: false, detail: 'Fix: Turnstile did not accept the widget secret. Run setup again.' };
  } catch {
    return { title, ok: false, detail: 'Fix: the Turnstile siteverify call did not answer. Run setup again.' };
  }
}

async function checkSnippet(ctx) {
  const title = 'Code injection snippet';
  try {
    const data = await ghostFetch(ctx.adminKey, ctx.siteUrl, 'settings/');
    const head = (data.settings || []).find((item) => item.key === 'codeinjection_head')?.value || '';
    const ready = head.includes(GUARD_START) && head.includes(GUARD_END) && head.includes(ctx.turnstileSitekey) && head.includes('/ghost-guard/turnstile.js');
    if (!ready) return { title, ok: false, detail: 'Fix: in Ghost Admin, Code injection, Site header, keep the ghost-guard markers and run setup again.' };
    return { title, ok: true, detail: 'The site header contains the ghost-guard snippet.' };
  } catch (error) {
    return { title, ok: false, detail: scrub(error.message, ctx.secrets) };
  }
}

async function checkConfirm(ctx) {
  const title = 'Confirmation page';
  const url = `https://${ctx.hostname}${ctx.ghostBasePath}/members/?token=x&action=signup`;
  try {
    const res = await fetch(url, { redirect: 'manual', cache: 'no-store', signal: AbortSignal.timeout(10_000) });
    const text = await readLimited(res);
    if (res.status === 200 && text.includes('Confirm signup')) {
      return { title, ok: true, detail: 'A fake signup link showed the confirmation page. The token was not exchanged and no member was created.' };
    }
    return { title, ok: false, detail: 'Fix: open a signup link and confirm this Worker shows Confirm signup before Ghost creates a member.' };
  } catch {
    return { title, ok: false, detail: 'Fix: the confirmation page could not be fetched. Check the Worker route and run setup again.' };
  }
}

async function checkSignin(ctx) {
  const title = 'Sign-in passthrough';
  const url = `https://${ctx.hostname}${ctx.ghostBasePath}/members/api/send-magic-link/`;
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ email: 'ghost-guard-setup-check@example.invalid', emailType: 'signin' }),
      redirect: 'manual',
      cache: 'no-store',
      signal: AbortSignal.timeout(10_000),
    });
    const text = await readLimited(res);
    if (/Unable to verify your request|Too many sign-up attempts|Signup protection is temporarily unavailable/.test(text)) {
      return { title, ok: false, detail: 'Fix: sign-in requests should skip Turnstile and quotas. Deploy the current Worker and run setup again.' };
    }
    return { title, ok: true, detail: 'A sign-in for a reserved nonexistent address was not blocked. No member was created.' };
  } catch {
    return { title, ok: false, detail: 'Fix: the sign-in request could not be sent. Check that Ghost is reachable through the Worker route.' };
  }
}

async function checkWebhook(ctx) {
  const title = 'Webhook';
  if (!ctx.webhookEnabled) return { title, ok: true, detail: 'Webhook labeller is off.' };
  try {
    const hooks = await listWebhooks(ctx.adminKey, ctx.siteUrl);
    const found = hooks.some((hook) => hook.event === 'member.added' && sameTarget(hook.target_url, ctx.webhookTarget));
    if (!found) return { title, ok: false, detail: 'Fix: add a member.added webhook on the custom integration that owns the Admin API key, targeting the signup-shield URL, then run setup again.' };
    return { title, ok: true, detail: `member.added points at ${ctx.webhookTarget}.` };
  } catch (error) {
    return { title, ok: false, detail: scrub(error.message, ctx.secrets) };
  }
}
