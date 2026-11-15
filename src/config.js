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

// Bumped on every forget, so a read that started before a save cannot put
// the pre-save value back into the cache when it finishes.
let generation = 0;

export function forgetStoredConfig(env) {
  generation++;
  if (env?.SETUP_STORE) cache.delete(env.SETUP_STORE);
}

// Only settled values are cached. Sharing an in-flight read would tie other
// requests to the I/O of the request that started it, which may be cancelled.
// Failures are not cached: the next request retries the store.
async function cachedRead(env, maxAge) {
  const key = env.SETUP_STORE;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < maxAge) return hit.value;
  const started = generation;
  const value = await readStoredConfig(env);
  if (generation === started) cache.set(key, { at: Date.now(), value });
  return value;
}

const refreshes = new WeakMap();

/** Reads the store now, at most once per isolate per `minInterval` (failed or
 * not). Returns null when throttled or unavailable. For callers that cannot
 * retry later, such as Ghost webhooks, so a flood cannot hammer the store. */
export async function refreshStoredConfig(env, minInterval) {
  if (!env?.SETUP_STORE) return null;
  if (Date.now() - (refreshes.get(env.SETUP_STORE) || 0) < minInterval) return null;
  refreshes.set(env.SETUP_STORE, Date.now());
  try {
    return await withStoredConfig(env, { maxAge: 0 });
  } catch {
    return null;
  }
}

/** `maxAge` bounds how old this isolate's copy may be; 0 always reads the store. */
export async function withStoredConfig(env, { maxAge = CONFIG_CACHE_MS } = {}) {
  if (!env?.SETUP_STORE) return env;
  try {
    return mergeConfig(env, await cachedRead(env, maxAge));
  } catch (cause) {
    console.error(`ghost-guard: setup store read failed (${cause?.message || 'unknown error'})`);
    const error = new Error('Setup configuration is temporarily unavailable. Please try again later.');
    error.code = 'SETUP_CONFIG_UNAVAILABLE';
    throw error;
  }
}
