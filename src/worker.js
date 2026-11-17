/**
 * ghost-guard
 *
 * Intercepts Ghost signup magic-link GETs (`/members/?token=&action=signup`)
 * and serves a confirmation page. The member is created only after a human
 * POSTs the form. Corporate email scanners that prefetch the link with a
 * GET therefore no longer confirm the signup.
 *
 * Optional second mode: POST /signup-shield/webhooks/member-added
 * labels new members for review via the Admin API (Ghost(Pro)-friendly).
 */

import { checkSignupIpRateLimit, checkSignupEmailRateLimit } from './rate-limit.js';
export { SignupRateLimiter } from './rate-limit.js';
import { handleMemberAddedWebhook } from './webhook.js';
export { MemberLabeller } from './webhook.js';
import { escapeHtml, handleSetup, pageHeaders } from './setup.js';
import { refreshStoredConfig, withStoredConfig } from './config.js';
export { SetupStore } from './setup.js';

const BYPASS_HEADER = 'X-Ghost-Signup-Shield';
const DEFAULT_ACTIONS = 'signup,subscribe,signup-paid';
const WEBHOOK_REFRESH_MS = 5_000;

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      if (error.code !== 'SETUP_CONFIG_UNAVAILABLE') throw error;
      return portalError('Signup protection is temporarily unavailable. Please try again later.', 503);
    }
  },
};

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = canonicalPath(url.pathname);
  if (path === '/ghost-guard/setup') return handleSetup(request, env);
  // Read once per protected request. Ordinary same-zone pages and assets
  // don't need setup settings. Direct-origin routing does need the base path.
  let configPromise;
  const config = () => configPromise ||= withStoredConfig(env);
  // Outside a subfolder install the path belongs to whatever else serves this
  // hostname, so it goes to the zone's normal origin, not to Ghost. The
  // sidecar has no zone origin; nginx only sends it Ghost's paths. Protected
  // requests use the same rule, so a lookalike path on a root app still
  // reaches that app after the checks.
  // If setup storage is down, plain forwarding falls back to the deployment's
  // own settings rather than taking every page and asset down with it.
  const forward = async (forwarded) => {
    const routingEnv = env.GHOST_ORIGIN && env.SETUP_STORE ? await config().catch(() => env) : env;
    return routingEnv.SIDECAR === true || insideGhost(path, routingEnv)
      ? forwardToOrigin(forwarded, routingEnv)
      : forwardToZone(forwarded);
  };

  if (path === '/ghost-guard/turnstile.js') {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'GET, HEAD' } });
    }
    const assetUrl = new URL(request.url);
    assetUrl.pathname = '/ghost-guard/turnstile.js';
    return env.ASSETS.fetch(new Request(assetUrl, { method: request.method, headers: request.headers }));
  }

  // Protection is decided by suffix, whatever GHOST_BASE_PATH says: Ghost only
  // serves these under <subfolder>/members, and covering a lookalike path
  // elsewhere is harmless. A wrong base path can then misroute, never unprotect.
  if (path.endsWith('/members/api/send-magic-link') && request.method === 'POST') {
    return handleSendMagicLink(request, config, forward);
  }

  if (url.pathname === '/signup-shield/webhooks/member-added') {
    // Ghost never retries a delivery. If the cached settings reject it (bad
    // secret, labeller off, missing credentials), setup may have just changed
    // them in another isolate: recheck once against the store (throttled).
    const retry = env.SETUP_STORE ? request.clone() : null;
    const response = await handleMemberAddedWebhook(request, await config());
    if (![401, 503].includes(response.status) || !retry) return response;
    const latest = await refreshStoredConfig(env, WEBHOOK_REFRESH_MS);
    return latest ? handleMemberAddedWebhook(retry, latest) : response;
  }

  if (path.endsWith('/members') && url.searchParams.has('token')) {
    return handleMagicLink(request, url, env, forward);
  }

  return forward(request);
}

async function handleSendMagicLink(request, config, forward) {
  let body;
  try {
    body = await request.clone().json();
  } catch {
    return portalError('Invalid signup request. Please try again.', 400);
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return portalError('Invalid signup request. Please try again.', 400);
  }

  // Only the explicit signin type is exempt. Missing/unknown types must not
  // become an alternative path to an unprotected signup.
  if (body.emailType === 'signin') return forward(request);
  if (typeof body.email !== 'string' || !body.email.trim()) {
    return portalError('Please enter an email address.', 400);
  }

  const env = await config();

  // Bound verification traffic even when every challenge is missing or invalid.
  const ipError = await rateLimitRejection(checkSignupIpRateLimit(request, env));
  if (ipError) return ipError;

  if (env.TURNSTILE_SECRET) {
    const token = request.headers.get('cf-turnstile-response') || body['cf-turnstile-response'];
    const valid = await verifyTurnstile(token, env, request);
    if (!valid) return portalError('Unable to verify your request, please try again', 400);
  }

  // Invalid challenges consume IP attempts but never a reader's email quota.
  const emailError = await rateLimitRejection(checkSignupEmailRateLimit(request, body.email, env));
  if (emailError) return emailError;

  // Strip our token before sending JSON to Ghost, retaining all Portal fields.
  const headers = new Headers(request.headers);
  headers.delete('cf-turnstile-response');
  headers.delete('content-length');
  delete body['cf-turnstile-response'];
  return forward(new Request(request, { headers, body: JSON.stringify(body) }));
}

async function rateLimitRejection(check) {
  try {
    const limit = await check;
    return limit.allowed ? null : portalError('Too many sign-up attempts, try again later', 429, { 'Retry-After': String(limit.retryAfter) });
  } catch {
    return portalError('Signup protection is temporarily unavailable. Please try again later.', 503);
  }
}

function portalError(message, status, headers = {}) {
  return new Response(JSON.stringify({ errors: [{ message, type: status === 429 ? 'TooManyRequestsError' : 'ValidationError' }] }), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
  });
}

// GHOST_BASE_PATH: the subfolder Ghost is installed under (e.g. "/blog" for
// example.com/blog), or empty for the domain root. Returned lowercased with a
// leading slash and no trailing one, since Ghost's routes ignore case.
// Only routing depends on this: protection is decided by path suffix. Values a
// request path could never match (dot or empty segments, query characters)
// are rejected rather than silently misrouting.
export function ghostBasePath(env) {
  const path = String(env.GHOST_BASE_PATH || '').trim().replace(/^\/+|\/+$/g, '');
  if (!path) return '';
  const valid = path.split('/').every((segment) => /^(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9A-Fa-f]{2})+$/.test(segment) && segment !== '.' && segment !== '..');
  if (!valid) throw new Error('GHOST_BASE_PATH must be a plain path such as /blog');
  return `/${path.toLowerCase()}`;
}

let warnedBasePath = false;

// With an invalid base path nothing is treated as Ghost's, so every page goes
// to the zone's normal origin: a separate root site keeps working, and
// signups stay protected because protection does not depend on the base.
function insideGhost(path, env) {
  let base;
  try {
    base = ghostBasePath(env);
  } catch (error) {
    if (!warnedBasePath) {
      warnedBasePath = true;
      console.error(`ghost-guard: ${error.message}; sending pages to the zone origin`);
    }
    return false;
  }
  return !base || path === base || path.startsWith(`${base}/`);
}

// The sidecar buffers and size-limits only the bodies ghost-guard reads.
export function readsRequestBody(pathname) {
  const path = canonicalPath(pathname);
  return path.endsWith('/members/api/send-magic-link') || path.endsWith('/members') || path.startsWith('/signup-shield/') || path === '/ghost-guard/setup';
}

// Lowercased, without trailing slashes, and with repeated slashes collapsed:
// Express routes "/members//api/…" and "/blog//members/…" to Ghost's handlers,
// so the guard must treat them as the paths Ghost will serve.
function canonicalPath(pathname) {
  return pathname.replace(/\/{2,}/g, '/').replace(/\/+$/, '').toLowerCase();
}


function interstitialActions(env) {
  const raw = env.INTERSTITIAL_ACTIONS || DEFAULT_ACTIONS;
  return new Set(
    raw
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  );
}

function shouldInterstitial(url, env) {
  const action = url.searchParams.get('action') || '';
  return interstitialActions(env).has(action);
}

async function handleMagicLink(request, url, env, forward) {
  const secret = env.CONFIRM_SECRET;
  if (secret && request.headers.get(BYPASS_HEADER) === secret) {
    return forward(request);
  }

  if (!shouldInterstitial(url, env)) {
    return forward(request);
  }

  if (request.method === 'GET' || request.method === 'HEAD') {
    if (request.method === 'HEAD') {
      return new Response(null, {
        status: 200,
        headers: htmlHeaders(),
      });
    }
    return new Response(renderInterstitial(url, env), {
      status: 200,
      headers: htmlHeaders(),
    });
  }

  if (request.method === 'POST') {
    return confirmAndForward(request, url, env, forward);
  }

  return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'GET, HEAD, POST' } });
}

async function confirmAndForward(request, url, env, forward) {
  const contentType = request.headers.get('content-type') || '';
  let token = url.searchParams.get('token');
  let action = url.searchParams.get('action');
  let referrer = url.searchParams.get('r');

  if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
    let form;
    try {
      form = await request.formData();
    } catch {
      return new Response(renderInterstitial(url, env, 'The confirmation form was invalid. Please try again.'), {
        status: 400,
        headers: htmlHeaders(),
      });
    }
    token = String(form.get('token') || token || '');
    action = String(form.get('action') || action || '');
    referrer = String(form.get('r') || referrer || '');
  }

  if (!token) {
    return new Response(renderInterstitial(url, env, 'Missing confirmation token.'), {
      status: 400,
      headers: htmlHeaders(),
    });
  }

  const confirmUrl = new URL(url.href);
  confirmUrl.searchParams.set('token', token);
  if (action) confirmUrl.searchParams.set('action', action);
  if (referrer) confirmUrl.searchParams.set('r', referrer);

  const originRequest = new Request(confirmUrl.toString(), {
    method: 'GET',
    redirect: 'manual',
    headers: originForwardHeaders(request, env),
  });

  return forward(originRequest);
}

function originForwardHeaders(request, env) {
  const headers = new Headers(request.headers);
  headers.delete('content-length');
  headers.delete('content-type');
  if (env.CONFIRM_SECRET) {
    headers.set(BYPASS_HEADER, env.CONFIRM_SECRET);
  }
  return headers;
}

// The hostname's normal Cloudflare origin, as if the Worker were not routed.
// Same-zone subrequests do not re-enter this Worker, so the bypass header is
// never needed here; dropping it keeps CONFIRM_SECRET away from other apps.
function forwardToZone(request) {
  const clientIp = request.headers.get('CF-Connecting-IP');
  const headers = new Headers(request.headers);
  headers.delete(BYPASS_HEADER);
  if (clientIp) headers.set('X-Forwarded-For', clientIp);
  return fetch(new Request(request, { headers }));
}

async function forwardToOrigin(request, env) {
  // Ghost trusts every proxy and takes the leftmost X-Forwarded-For entry as the
  // client, and Cloudflare only appends to what the client sent. Replace the
  // header with the address Cloudflare (or the sidecar) resolved, so clients
  // cannot dodge Ghost's per-IP throttling, which is all that limits sign-ins.
  const clientIp = request.headers.get('CF-Connecting-IP');
  const origin = (env.GHOST_ORIGIN || '').replace(/\/+$/, '');
  // Without GHOST_ORIGIN, Ghost is the zone origin; same-zone subrequests do
  // not re-enter this Worker.
  if (!origin) return forwardToZone(request);

  const url = new URL(request.url);
  // Assign URL components so a leading // in the path cannot change authority.
  const target = new URL(origin);
  target.pathname = url.pathname;
  target.search = url.search;
  target.hash = '';
  const headers = new Headers(request.headers);
  if (clientIp) headers.set('X-Forwarded-For', clientIp);
  headers.set('Host', new URL(origin).host);
  if (env.CONFIRM_SECRET) {
    headers.set(BYPASS_HEADER, env.CONFIRM_SECRET);
  }

  return fetch(
    new Request(target.toString(), {
      method: request.method,
      headers,
      body: request.method === 'GET' || request.method === 'HEAD' ? undefined : request.body,
      redirect: 'manual',
      duplex: 'half',
    }),
  );
}

async function verifyTurnstile(token, env, request) {
  if (typeof token !== 'string' || !token || token.length > 2048) return false;
  const body = new URLSearchParams();
  body.set('secret', env.TURNSTILE_SECRET);
  body.set('response', token);
  const ip = request.headers.get('CF-Connecting-IP');
  if (ip) body.set('remoteip', ip);
  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body,
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return false;
    const data = await res.json();
    const hostname = env.TURNSTILE_HOSTNAME || new URL(request.url).hostname;
    return data?.success === true && data.hostname === hostname && data.action === 'ghost_signup';
  } catch {
    return false;
  }
}

function htmlHeaders() {
  const headers = pageHeaders();
  // Ghost may redirect a successful confirmation to an external welcome page.
  // Chromium also checks form-action on that redirect after consuming the token.
  headers['content-security-policy'] = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'";
  return headers;
}

function renderInterstitial(url, env, error) {
  const title = escapeHtml(env.SITE_TITLE || 'this publication');
  const token = escapeHtml(url.searchParams.get('token') || '');
  const action = escapeHtml(url.searchParams.get('action') || '');
  const referrer = escapeHtml(url.searchParams.get('r') || '');
  const errorHtml = error
    ? `<p class="error" role="alert">${escapeHtml(error)}</p>`
    : '';
  // No auto-submit. Corporate scanners often run JavaScript; a click is the signal we want.
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>Confirm your subscription</title>
  <style>
    :root { color-scheme: light dark; }
    body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f6f6f4; color: #15171a; }
    main { width: min(28rem, calc(100% - 2rem)); background: #fff; border-radius: 12px; padding: 2rem; box-shadow: 0 8px 30px rgba(0,0,0,.08); }
    h1 { font-size: 1.35rem; margin: 0 0 .75rem; }
    p { line-height: 1.5; margin: 0 0 1rem; color: #394047; }
    .error { color: #a30; font-weight: 600; }
    button { appearance: none; border: 0; border-radius: 8px; background: #15171a; color: #fff; font: inherit; font-weight: 600; padding: .8rem 1.2rem; cursor: pointer; width: 100%; }
    button:hover { background: #2b2f33; }
    .hint { font-size: .85rem; color: #738a94; margin-top: 1.25rem; }
    @media (prefers-color-scheme: dark) {
      body { background: #111; color: #f4f4f2; }
      main { background: #1c1e21; box-shadow: none; }
      p { color: #c8cdd1; }
      button { background: #f4f4f2; color: #15171a; }
      .hint { color: #8b9aa3; }
    }
  </style>
</head>
<body>
  <main>
    <h1>Confirm your subscription</h1>
    <p>One last step to finish signing up for ${title}.</p>
    ${errorHtml}
    <form method="post" action="">
      <input type="hidden" name="token" value="${token}">
      <input type="hidden" name="action" value="${action}">
      <input type="hidden" name="r" value="${referrer}">
      <button type="submit">Confirm signup</button>
    </form>
    <p class="hint">If you did not try to sign up, close this page. No account will be created.</p>
  </main>
</body>
</html>`;
}
