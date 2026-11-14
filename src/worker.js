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

    if (url.pathname.replace(/\/+$/, '').toLowerCase() === '/members/api/send-magic-link' && request.method === 'POST') {
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
  return forwardToOrigin(new Request(request, { headers, body: JSON.stringify(body) }), env);
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

function isMembersMagicLink(url) {
  const path = url.pathname.replace(/\/+$/, '').toLowerCase() || '/';
  return path === '/members' && url.searchParams.has('token');
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
  // Assign URL components so a leading // in the path cannot change authority.
  const target = new URL(origin);
  target.pathname = url.pathname;
  target.search = url.search;
  target.hash = '';
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
