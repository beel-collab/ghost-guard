const HOUR = 60 * 60 * 1000;

function positiveInteger(value, fallback) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1) return fallback;
  return number;
}

export function rateLimitConfig(env) {
  return {
    ipLimit: positiveInteger(env.SIGNUP_IP_LIMIT, 5),
    ipWindowMs: positiveInteger(env.SIGNUP_IP_WINDOW_SECONDS, 3600) * 1000,
    emailLimit: positiveInteger(env.SIGNUP_EMAIL_LIMIT, 3),
    emailWindowMs: positiveInteger(env.SIGNUP_EMAIL_WINDOW_SECONDS, 86400) * 1000,
  };
}

// Both counters are checked before either is incremented. Windows start with the
// first allowed attempt; rejected requests never extend the window.
function consume(store, buckets, now) {
  const counters = buckets.map(({ key, limit, windowMs }) => {
    const previous = store.get(key);
    return {
      key,
      limit,
      count: previous && previous.expires > now ? previous.count : 0,
      expires: previous && previous.expires > now ? previous.expires : now + windowMs,
    };
  });
  const blocked = counters.filter((counter) => counter.count >= counter.limit);
  if (blocked.length) {
    return { allowed: false, retryAfter: Math.max(1, ...blocked.map((c) => Math.ceil((c.expires - now) / 1000))) };
  }
  for (const counter of counters) {
    store.put(counter.key, { count: counter.count + 1, expires: counter.expires });
  }
  return { allowed: true };
}

// Local adapter only: each sidecar process owns its own counters.
export class MemoryRateLimiter {
  constructor() {
    this.counters = new Map();
    this.nextSweep = 0;
  }

  async consume(buckets, now = Date.now()) {
    if (now >= this.nextSweep) {
      for (const [key, value] of this.counters) {
        if (value.expires <= now) this.counters.delete(key);
      }
      this.nextSweep = now + 60_000;
    }
    return consume({ get: (key) => this.counters.get(key), put: (key, value) => this.counters.set(key, value) }, buckets, now);
  }
}

// One SQLite-backed Durable Object per publication. A synchronous transaction
// checks and reserves both quotas atomically across concurrent Worker instances.
export class SignupRateLimiter {
  constructor(ctx) {
    this.storage = ctx.storage;
    this.sql = ctx.storage.sql;
    this.sql.exec('CREATE TABLE IF NOT EXISTS counters (key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL)');
  }

  async fetch(request) {
    const { buckets } = await request.json();
    const now = Date.now();
    const result = this.storage.transactionSync(() => consume({
      get: (key) => this.sql.exec('SELECT count, expires FROM counters WHERE key = ?', key).toArray()[0],
      put: (key, value) => this.sql.exec(
        'INSERT INTO counters (key, count, expires) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET count = excluded.count, expires = excluded.expires',
        key, value.count, value.expires,
      ),
    }, buckets, now));
    if (await this.storage.getAlarm() === null) await this.storage.setAlarm(now + HOUR);
    return Response.json(result);
  }

  async alarm() {
    this.sql.exec('DELETE FROM counters WHERE expires <= ?', Date.now());
    if (this.sql.exec('SELECT key FROM counters LIMIT 1').toArray().length) {
      await this.storage.setAlarm(Date.now() + HOUR);
    }
  }
}

async function digest(value) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function checkSignupRateLimit(request, email, env) {
  const config = rateLimitConfig(env);
  // The sidecar overwrites this header using the socket (or an explicitly
  // trusted upstream); Workers receive it from Cloudflare, never X-Forwarded-For.
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const buckets = [
    { key: `ip:${await digest(ip)}`, limit: config.ipLimit, windowMs: config.ipWindowMs },
    { key: `email:${await digest(email.trim().toLowerCase())}`, limit: config.emailLimit, windowMs: config.emailWindowMs },
  ];
  if (env.LOCAL_RATE_LIMITER) return env.LOCAL_RATE_LIMITER.consume(buckets);
  if (!env.SIGNUP_RATE_LIMITER) throw new Error('SIGNUP_RATE_LIMITER binding is required');
  const id = env.SIGNUP_RATE_LIMITER.idFromName(new URL(request.url).origin);
  const response = await env.SIGNUP_RATE_LIMITER.get(id).fetch('https://rate-limiter/consume', {
    method: 'POST',
    body: JSON.stringify({ buckets }),
  });
  if (!response.ok) throw new Error('Signup rate limiter unavailable');
  return response.json();
}
