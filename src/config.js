/** Settings saved by guided setup, layered over the deployment's env vars.
 * Leaf module: Worker, webhook and setup all read config through here.
 */

// Plain page and signup traffic reads settings from this isolate's copy for
// up to this long, so one global SetupStore is not on every request's path.
// Setup invalidates the copy in its own isolate when it saves.
export const CONFIG_CACHE_MS = 30_000;
const cache = new WeakMap();

export function mergeConfig(env, stored) {
  if (!stored || typeof stored !== 'object') return env;
  const next = { ...env };
  // A prepared widget takes over only once activated. Until then a manually
  // configured TURNSTILE_SECRET (if any) keeps protecting signups.
  if (Object.hasOwn(stored, 'turnstileSecret') && stored.turnstileEnabled !== false) {
    next.TURNSTILE_SECRET = stored.turnstileSecret;
    next.TURNSTILE_HOSTNAME = stored.hostname || '';
  }
  if (Object.hasOwn(stored, 'ghostBasePath')) next.GHOST_BASE_PATH = stored.ghostBasePath;
  // Setup owns the labeller only once it enabled or explicitly turned it off.
  // A run that left it alone keeps a manually configured labeller working.
  if (stored.cleanupEnabled === 'true' || stored.labellerDisabled === true) {
    next.CLEANUP_ENABLED = stored.cleanupEnabled;
    next.WEBHOOK_SECRET = stored.webhookSecret || '';
    next.ADMIN_API_KEY = stored.adminApiKey || '';
    next.ADMIN_API_URL = stored.adminApiUrl || '';
  }
  return next;
}

export function storeStub(env) {
  if (!env.SETUP_STORE) return null;
  return env.SETUP_STORE.get(env.SETUP_STORE.idFromName('setup'));
}

export async function readStoredConfig(env) {
  const res = await storeStub(env).fetch(new Request('https://setup-store/config'));
  if (!res.ok) throw new Error('setup store unavailable');
  return (await res.json())?.value || null;
}

export function forgetStoredConfig(env) {
  if (env?.SETUP_STORE) cache.delete(env.SETUP_STORE);
}

// Only settled values are cached. Sharing an in-flight read would tie other
// requests to the I/O of the request that started it, which may be cancelled.
// Failures are not cached: the next request retries the store.
async function cachedRead(env) {
  const key = env.SETUP_STORE;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CONFIG_CACHE_MS) return hit.value;
  const value = await readStoredConfig(env);
  cache.set(key, { at: Date.now(), value });
  return value;
}

/** `fresh: true` skips the isolate copy: webhooks (Ghost never retries one that
 * a stale secret rejected) and alarms must see the latest save. */
export async function withStoredConfig(env, { fresh = false } = {}) {
  if (!env?.SETUP_STORE) return env;
  try {
    return mergeConfig(env, await (fresh ? readStoredConfig(env) : cachedRead(env)));
  } catch (cause) {
    console.error(`ghost-guard: setup store read failed (${cause?.message || 'unknown error'})`);
    const error = new Error('Setup configuration is temporarily unavailable. Please try again later.');
    error.code = 'SETUP_CONFIG_UNAVAILABLE';
    throw error;
  }
}
