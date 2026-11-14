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

import { checkSignupRateLimit } from './rate-limit.js';
export { SignupRateLimiter } from './rate-limit.js';

const BYPASS_HEADER = 'X-Ghost-Signup-Shield';
const DEFAULT_ACTIONS = 'signup,subscribe,signup-paid';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/ghost-guard/turnstile.js') {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'GET, HEAD' } });
      }
      return env.ASSETS.fetch(request);
    }

    if (url.pathname.replace(/\/+$/, '') === '/members/api/send-magic-link' && request.method === 'POST') {
      return handleSendMagicLink(request, env);
    }

    if (url.pathname === '/signup-shield/webhooks/member-added') {
      return handleMemberAddedWebhook(request, env);
    }

    if (isMembersMagicLink(url)) {
      return handleMagicLink(request, url, env);
    }

    return forwardToOrigin(request, env);
  },
};

async function handleSendMagicLink(request, env) {
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
  if (body.emailType === 'signin') return forwardToOrigin(request, env);
  if (typeof body.email !== 'string' || !body.email.trim()) {
    return portalError('Please enter an email address.', 400);
  }

  if (env.TURNSTILE_SECRET) {
    const token = request.headers.get('cf-turnstile-response') || body['cf-turnstile-response'];
    const valid = await verifyTurnstile(token, env, request);
    if (!valid) return portalError('Unable to verify your request, please try again', 400);
  }

  // Invalid challenges do not exhaust somebody else's daily email quota.
  let limit;
  try {
    limit = await checkSignupRateLimit(request, body.email, env);
  } catch {
    return portalError('Signup protection is temporarily unavailable. Please try again later.', 503);
  }
  if (!limit.allowed) {
    return portalError('Too many sign-up attempts, try again later', 429, { 'Retry-After': String(limit.retryAfter) });
  }

  // Strip our token before sending JSON to Ghost, retaining all Portal fields.
  const headers = new Headers(request.headers);
  headers.delete('cf-turnstile-response');
  headers.delete('content-length');
  delete body['cf-turnstile-response'];
  return forwardToOrigin(new Request(request, { headers, body: JSON.stringify(body) }), env);
}

function portalError(message, status, headers = {}) {
  return new Response(JSON.stringify({ errors: [{ message, type: status === 429 ? 'TooManyRequestsError' : 'ValidationError' }] }), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
  });
}

function isMembersMagicLink(url) {
  const path = url.pathname.replace(/\/+$/, '') || '/';
  return (path === '/members' || path === '/members/') && url.searchParams.has('token');
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

async function handleMagicLink(request, url, env) {
  const secret = env.CONFIRM_SECRET;
  if (secret && request.headers.get(BYPASS_HEADER) === secret) {
    return forwardToOrigin(request, env);
  }

  if (!shouldInterstitial(url, env)) {
    return forwardToOrigin(request, env);
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
    return confirmAndForward(request, url, env);
  }

  return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'GET, HEAD, POST' } });
}

async function confirmAndForward(request, url, env) {
  const contentType = request.headers.get('content-type') || '';
  let token = url.searchParams.get('token');
  let action = url.searchParams.get('action');
  let referrer = url.searchParams.get('r');

  if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
    const form = await request.formData();
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

  return forwardToOrigin(originRequest, env);
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

async function forwardToOrigin(request, env) {
  const origin = (env.GHOST_ORIGIN || '').replace(/\/+$/, '');
  if (!origin) {
    // Same-zone routing: the bypass header (set by confirmAndForward) prevents a loop.
    return fetch(request);
  }

  const url = new URL(request.url);
  const target = new URL(url.pathname + url.search, origin);
  const headers = new Headers(request.headers);
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
  return {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store, no-cache, must-revalidate',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
  };
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
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
    <p>One last step to finish signing up for ${title}. This extra click keeps automated email scanners from creating an account in your name.</p>
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

async function handleMemberAddedWebhook(request, env) {
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }
  if (env.CLEANUP_ENABLED !== 'true') {
    return json({ ok: false, error: 'cleanup disabled' }, 503);
  }
  if (!env.ADMIN_API_URL || !env.ADMIN_API_KEY || !env.WEBHOOK_SECRET) {
    return json({ ok: false, error: 'admin api and webhook secret must be configured' }, 503);
  }

  const raw = await request.text();
  const valid = await verifyGhostWebhook(raw, request.headers.get('X-Ghost-Signature') || '', env.WEBHOOK_SECRET);
  if (!valid) {
    return json({ ok: false, error: 'invalid signature' }, 401);
  }

  let payload;
  try {
    payload = JSON.parse(raw);
  } catch {
    return json({ ok: false, error: 'invalid json' }, 400);
  }

  // Ghost webhook payload is { event, member: { current, previous } }
  // see ghost/core/server/services/webhooks/serialize.js
  const member =
    payload.member?.current ||
    payload.member ||
    (Array.isArray(payload.members) ? payload.members[0] : null);
  if (!member || !member.id || !member.email) {
    return json({ ok: false, error: 'no member in payload' }, 400);
  }

  if (member.status && member.status !== 'free') {
    return json({ ok: true, skipped: 'not-free' });
  }

  const domain = String(member.email).split('@')[1]?.toLowerCase() || '';
  const skip = new Set(
    (env.CLEANUP_SKIP_DOMAINS || '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
  if (skip.has(domain)) {
    return json({ ok: true, skipped: 'consumer-domain' });
  }

  await adminPatchMember(env, member, {
    labels: [...new Set([...existingLabelNames(member), 'signup-shield-review'])].map((name) => ({ name })),
  });
  return json({ ok: true, action: 'label', id: member.id });
}

function existingLabelNames(member) {
  if (!Array.isArray(member.labels)) return [];
  return member.labels.map((l) => l.name).filter(Boolean);
}

async function adminPatchMember(env, member, body) {
  const base = env.ADMIN_API_URL.replace(/\/+$/, '');
  const url = `${base}/ghost/api/admin/members/${member.id}/`;
  const headers = await adminApiHeaders(env.ADMIN_API_KEY);
  const res = await fetch(url, {
    method: 'PUT',
    headers,
    body: JSON.stringify({ members: [body] }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Admin API ${res.status}: ${text.slice(0, 300)}`);
  }
}

async function adminApiHeaders(adminApiKey) {
  const [id, secret] = String(adminApiKey).split(':');
  if (!id || !secret) {
    throw new Error('ADMIN_API_KEY must be in id:secret form');
  }
  const enc = new TextEncoder();
  const now = Math.floor(Date.now() / 1000);
  const header = btoa(JSON.stringify({ alg: 'HS256', kid: id, typ: 'JWT' }))
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  const payload = btoa(JSON.stringify({ iat: now, exp: now + 300, aud: '/admin/' }))
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  const data = `${header}.${payload}`;
  const key = await crypto.subtle.importKey(
    'raw',
    hexToBytes(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuf)))
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return {
    Authorization: `Ghost ${data}.${sig}`,
    'Content-Type': 'application/json',
    'Accept-Version': 'v6.0',
  };
}

function hexToBytes(hex) {
  const clean = hex.trim();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function verifyGhostWebhook(rawBody, signatureHeader, secret) {
  // Ghost signs with: sha256=hex, t=timestamp
  // https://docs.ghost.org/webhooks
  const parts = Object.fromEntries(
    String(signatureHeader)
      .split(',')
      .map((p) => p.trim().split('='))
      .filter((kv) => kv.length === 2),
  );
  const ts = parts.t;
  const hash = parts.sha256;
  if (!ts || !hash) return false;
  // Ghost uses Date.now() milliseconds and HMAC(payload + ts). See webhook-trigger.js.
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum) || Math.abs(Date.now() - tsNum) > 5 * 60 * 1000) return false;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(`${rawBody}${ts}`));
  const expected = [...new Uint8Array(sigBuf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  if (expected.length !== hash.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ hash.charCodeAt(i);
  }
  return diff === 0;
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}
