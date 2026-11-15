/** Authenticated, additive member labelling shared by Worker and sidecar. */
import { withStoredConfig } from './setup.js';
const REVIEW_LABEL = 'signup-shield-review';

// Ghost sends each webhook once: a POST with a 2 s timeout that is not retried.
// Handlers therefore acknowledge immediately and label in the background,
// retrying on this schedule (just under 3 hours in total).
export const RETRY_DELAYS_MS = [30e3, 60e3, 120e3, 300e3, 900e3, 1800e3, 3600e3, 3600e3];

// Retrying cannot fix bad credentials, missing permissions or a malformed
// setting. Timeouts, network errors, 408, 429 and 5xx are worth retrying.
function isTerminal(error) {
  const status = error?.status;
  return error?.terminal === true || (status >= 400 && status < 500 && ![408, 429].includes(status));
}

// Logs the reason (an Admin API status or our own message), never member data.
function logFailure(error, outcome) {
  const log = outcome === 'retrying' ? console.warn : console.error;
  log(`ghost-guard: member labelling failed (${error?.message || 'unknown error'}); ${outcome}`);
}

function terminalError(message) {
  const error = new Error(message);
  error.terminal = true;
  return error;
}

// Serializes the entire read/check/write operation. Different members can run
// concurrently, and failed operations release the queue for a fresh retry.
export class MemberQueue {
  constructor() {
    this.pending = new Map();
  }

  async run(key, operation) {
    const previous = this.pending.get(key) || Promise.resolve();
    const result = previous.then(operation);
    const done = result.then(() => undefined, () => undefined);
    this.pending.set(key, done);
    try {
      return await result;
    } finally {
      if (this.pending.get(key) === done) this.pending.delete(key);
    }
  }
}

// Sidecar: per-member serialization plus in-process retries. Pending retries
// are lost if the process restarts.
export class LocalLabelQueue {
  constructor(delays = RETRY_DELAYS_MS) {
    this.queue = new MemberQueue();
    this.delays = delays;
    this.inflight = new Set();
  }

  enqueue(key, operation) {
    this.#attempt(key, operation, 0);
  }

  // Resolves once every queued label and scheduled retry has finished.
  // Retry timers are unref'd, so hold the process open while someone waits.
  async idle() {
    const keepAlive = setInterval(() => {}, 60_000);
    try {
      while (this.inflight.size) await Promise.all([...this.inflight]);
    } finally {
      clearInterval(keepAlive);
    }
  }

  #attempt(key, operation, attempt) {
    const run = this.queue.run(key, operation).catch((error) => {
      if (isTerminal(error)) return logFailure(error, 'not retrying');
      if (attempt >= this.delays.length) return logFailure(error, 'giving up after all retries');
      logFailure(error, 'retrying');
      return new Promise((resolve) => {
        // Unref so a pending retry cannot hold a sidecar process open after the
        // server stops.
        setTimeout(resolve, this.delays[attempt]).unref?.();
      }).then(() => this.#attempt(key, operation, attempt + 1));
    });
    const tracked = run.finally(() => this.inflight.delete(tracked));
    this.inflight.add(tracked);
    return tracked;
  }
}

// Worker: one object per Ghost site and member. The fetch handler records the
// member and schedules an alarm; the runtime runs at most one alarm per object
// at a time, which serializes the read/check/write across deliveries.
export class MemberLabeller {
  constructor(ctx, env) {
    this.storage = ctx.storage;
    this.env = env;
  }

  async fetch(request) {
    if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
    const { id } = await request.json();
    if (typeof id !== 'string' || !/^[a-f\d]{24}$/.test(id)) return new Response('Invalid member ID', { status: 400 });
    // A new delivery gets a fresh retry budget and runs now.
    await this.storage.put('id', id);
    await this.storage.put('attempt', 0);
    await this.storage.setAlarm(Date.now());
    return json({ ok: true, queued: true }, 202);
  }

  async alarm() {
    const id = await this.storage.get('id');
    if (!id) return;
    try {
      // Durable Objects receive deployment env, independently of Worker.fetch.
      // Reload setup settings on each attempt so retries see corrected config.
      const env = await withStoredConfig(this.env);
      if (env.CLEANUP_ENABLED === 'true') await labelCurrentMember(env, id);
      // A delivery that arrived mid-run has scheduled another pass; keep its state.
      if ((await this.storage.getAlarm()) === null) await this.storage.deleteAll();
    } catch (error) {
      // A delivery that arrived mid-run has already scheduled a fresh pass.
      if ((await this.storage.getAlarm()) !== null) return logFailure(error, 'a newer delivery will retry');
      const attempt = (await this.storage.get('attempt')) || 0;
      if (isTerminal(error) || attempt >= RETRY_DELAYS_MS.length) {
        logFailure(error, isTerminal(error) ? 'not retrying' : 'giving up after all retries');
        await this.storage.deleteAll();
        return;
      }
      logFailure(error, 'retrying');
      await this.storage.put('attempt', attempt + 1);
      await this.storage.setAlarm(Date.now() + RETRY_DELAYS_MS[attempt]);
    }
  }
}

let warnedWebhookSecret = false;

export async function handleMemberAddedWebhook(request, env) {
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }
  // Signature first. Missing-config details (URL shape, key form) are only
  // returned after a valid signature, so an unsigned caller cannot probe them.
  // A labeller that is switched off answers exactly like a bad signature.
  if (!env.WEBHOOK_SECRET && env.CLEANUP_ENABLED !== 'true') {
    return json({ ok: false, error: 'invalid signature' }, 401);
  }
  if (!env.WEBHOOK_SECRET) {
    if (!warnedWebhookSecret) {
      warnedWebhookSecret = true;
      console.warn('ghost-guard: webhook rejected because WEBHOOK_SECRET is not set');
    }
    return json({ ok: false, error: 'unauthorized' }, 503);
  }
  const raw = await request.text();
  const valid = await verifyGhostWebhook(raw, request.headers.get('X-Ghost-Signature') || '', env.WEBHOOK_SECRET);
  if (!valid) {
    return json({ ok: false, error: 'invalid signature' }, 401);
  }
  // Only signed requests learn whether the labeller is switched on.
  if (env.CLEANUP_ENABLED !== 'true') {
    return json({ ok: false, error: 'cleanup disabled' }, 503);
  }
  // Labelling runs after the 202, so report settings that can never work now,
  // where Ghost Admin's webhook status shows them. Only signed requests see this.
  const configError = adminConfigError(env);
  if (configError) return json({ ok: false, error: configError }, 503);

  let payload;
  try {
    payload = JSON.parse(raw);
  } catch {
    return json({ ok: false, error: 'invalid json' }, 400);
  }

  // Ghost webhook payload is { event, member: { current, previous } }
  // see ghost/core/server/services/webhooks/serialize.js
  const member =
    payload?.member?.current ||
    payload?.member ||
    (Array.isArray(payload?.members) ? payload.members[0] : null);
  if (typeof member?.id !== 'string' || !/^[a-f\d]{24}$/i.test(member.id)) {
    return json({ ok: false, error: 'no member in payload' }, 400);
  }

  try {
    const id = member.id.toLowerCase();
    const key = `${new URL(env.ADMIN_API_URL).href.replace(/\/+$/, '')}:${id}`;
    if (env.LOCAL_MEMBER_LABELLER) {
      env.LOCAL_MEMBER_LABELLER.enqueue(key, () => labelCurrentMember(env, id));
      return json({ ok: true, queued: true }, 202);
    }
    if (!env.MEMBER_LABELLER) throw new Error('MEMBER_LABELLER binding is required');
    const objectId = env.MEMBER_LABELLER.idFromName(key);
    return await env.MEMBER_LABELLER.get(objectId).fetch('https://member-labeller/label', {
      method: 'POST', body: JSON.stringify({ id }),
    });
  } catch {
    return json({ ok: false, error: 'member labelling could not be queued' }, 503);
  }
}

function adminConfigError(env) {
  let url;
  try {
    url = new URL(env.ADMIN_API_URL);
  } catch {
    url = null;
  }
  if (!url || !['http:', 'https:'].includes(url.protocol)) return 'ADMIN_API_URL must be an http(s) URL';
  if (!ADMIN_KEY_PATTERN.test(String(env.ADMIN_API_KEY).trim())) {
    return "ADMIN_API_KEY must be the integration's id:secret Admin API key";
  }
  return null;
}

async function readCurrentMember(env, id) {
  try {
    const data = await adminApiRequest(env, `members/${id}/`);
    const member = data.members?.[0];
    if (member?.id !== id || typeof member.email !== 'string') throw new Error('Invalid member response');
    return member;
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

// Returns the outcome; throws when the label may not have been applied.
export async function labelCurrentMember(env, id) {
  // The event is a creation-time snapshot. Eligibility and replay detection
  // must use current state, and label writes must be additive.
  const member = await readCurrentMember(env, id);
  if (!member) return { ok: true, skipped: 'member-missing' };
  if (member.status !== 'free') {
    return { ok: true, skipped: 'not-free' };
  }

  const domain = String(member.email).split('@')[1]?.toLowerCase() || '';
  const skip = new Set(
    (env.CLEANUP_SKIP_DOMAINS || '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );
  if (skip.has(domain)) {
    return { ok: true, skipped: 'consumer-domain' };
  }

  if (hasReviewLabel(member)) return { ok: true, skipped: 'already-labelled', id };
  const label = await getReviewLabel(env);
  const query = new URLSearchParams({ filter: `id:'${id}'+status:free` });
  const result = await adminApiRequest(env, `members/bulk/?${query}`, {
    method: 'PUT', body: { bulk: { action: 'addLabel', meta: { label: { id: label.id } } } },
  });
  const stats = result.bulk?.meta?.stats;
  if (stats?.successful === 1 && stats.unsuccessful === 0) return { ok: true, action: 'label', id };

  // Ghost reports bulk failures inside HTTP 200, for example when another
  // writer added the same label first. Accept only if the label is now present.
  const current = await readCurrentMember(env, id);
  if (!current) return { ok: true, skipped: 'member-missing' };
  if (current.status !== 'free') return { ok: true, skipped: 'not-free' };
  if (hasReviewLabel(current)) return { ok: true, skipped: 'already-labelled', id };
  throw new Error('Ghost did not apply the review label');
}

function hasReviewLabel(member) {
  return Array.isArray(member.labels) && member.labels.some((label) => label.name === REVIEW_LABEL);
}

async function getReviewLabel(env) {
  const query = new URLSearchParams({ filter: `name:'${REVIEW_LABEL}'`, limit: '1' });
  const find = async () => (await adminApiRequest(env, `labels/?${query}`)).labels?.[0];
  let label = await find();
  if (!label) {
    try {
      label = (await adminApiRequest(env, 'labels/', { method: 'POST', body: { labels: [{ name: REVIEW_LABEL }] } })).labels?.[0];
    } catch (error) {
      // Another delivery may have created the named label between GET and POST.
      if (![409, 422].includes(error.status)) throw error;
      label = await find();
    }
  }
  if (typeof label?.id !== 'string' || !/^[a-f\d]{24}$/i.test(label.id) || label.name !== REVIEW_LABEL) {
    throw new Error('Invalid review label response');
  }
  return label;
}

async function adminApiRequest(env, path, { method = 'GET', body } = {}) {
  const base = env.ADMIN_API_URL.replace(/\/+$/, '');
  const url = `${base}/ghost/api/admin/${path}`;
  const headers = await adminApiHeaders(env.ADMIN_API_KEY);
  const res = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) {
    const error = new Error(`Admin API ${res.status}`);
    error.status = res.status;
    throw error;
  }
  return res.json();
}

// Ghost Admin API keys: a 24-hex-digit key ID and a 64-hex-digit secret.
export const ADMIN_KEY_PATTERN = /^[a-f\d]{24}:[a-f\d]{64}$/i;

async function adminApiHeaders(adminApiKey) {
  const apiKey = String(adminApiKey).trim();
  if (!ADMIN_KEY_PATTERN.test(apiKey)) throw terminalError('ADMIN_API_KEY must be in id:secret form');
  const [id, secret] = apiKey.split(':');
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
