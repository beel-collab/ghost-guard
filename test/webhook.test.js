import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import worker from '../src/worker.js';
import { MemberQueue, LocalLabelQueue, MemberLabeller, labelCurrentMember, RETRY_DELAYS_MS } from '../src/webhook.js';

const memberId = '111111111111111111111111';
const label = { id: '222222222222222222222222', name: 'signup-shield-review' };
const env = {
  CLEANUP_ENABLED: 'true', ADMIN_API_URL: 'https://admin.example',
  ADMIN_API_KEY: 'aaaaaaaaaaaaaaaaaaaaaaaa:' + '0123456789abcdef'.repeat(4), WEBHOOK_SECRET: 'webhook-secret',
};
function event(member = { id: memberId, email: 'reader@work.example', status: 'free', labels: [] }) {
  const body = JSON.stringify({ member: { current: member } });
  const timestamp = String(Date.now());
  const hash = createHmac('sha256', env.WEBHOOK_SECRET).update(body + timestamp).digest('hex');
  return new Request('https://blog.example/signup-shield/webhooks/member-added', {
    method: 'POST', body, headers: { 'X-Ghost-Signature': `sha256=${hash}, t=${timestamp}` },
  });
}
function ghost(t) {
  const state = {
    member: { id: memberId, email: 'reader@work.example', status: 'free', labels: [{ name: 'added-after-creation' }] },
    label: structuredClone(label), calls: [], beforeBulk: null, bulkResponse: null,
    createConflict: false, readStatus: 200, readFailures: 0,
  };
  t.mock.method(globalThis, 'fetch', async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method || 'GET';
    const body = init.body ? JSON.parse(init.body) : undefined;
    state.calls.push({ url, method, body });
    assert.equal(url.origin, 'https://admin.example');
    if (url.pathname === `/ghost/api/admin/members/${memberId}/` && method === 'GET') {
      if (state.readFailures > 0) { state.readFailures--; return Response.json({ errors: [] }, { status: 503 }); }
      if (state.readStatus !== 200) return Response.json({ errors: [] }, { status: state.readStatus });
      return state.member ? Response.json({ members: [structuredClone(state.member)] }) : new Response(null, { status: 404 });
    }
    if (url.pathname === '/ghost/api/admin/labels/' && method === 'GET') {
      assert.equal(url.searchParams.get('filter'), "name:'signup-shield-review'");
      return Response.json({ labels: state.label ? [state.label] : [] });
    }
    if (url.pathname === '/ghost/api/admin/labels/' && method === 'POST') {
      assert.deepEqual(body, { labels: [{ name: label.name }] });
      state.label = structuredClone(label);
      return state.createConflict ? Response.json({ errors: [{ message: 'Label already exists' }] }, { status: 422 }) : Response.json({ labels: [state.label] }, { status: 201 });
    }
    if (url.pathname === '/ghost/api/admin/members/bulk/' && method === 'PUT') {
      assert.equal(url.searchParams.get('filter'), `id:'${memberId}'+status:free`);
      assert.deepEqual(body, { bulk: { action: 'addLabel', meta: { label: { id: label.id } } } });
      await state.beforeBulk?.();
      if (state.bulkResponse) return Response.json(state.bulkResponse);
      const matches = state.member?.id === memberId && state.member.status === 'free';
      // Ghost bulkAdd inserts unconditionally; no member/label unique index.
      if (matches) state.member.labels.push(structuredClone(label));
      return Response.json({ bulk: { meta: { stats: { successful: matches ? 1 : 0, unsuccessful: 0 } } } });
    }
    throw new Error(`Unexpected Admin API call: ${method} ${url.pathname}`);
  });
  return state;
}

const label_ = (overrides = {}) => labelCurrentMember({ ...env, ...overrides }, memberId);

test('labelling only adds the review label and preserves current and concurrently added labels', async (t) => {
  const state = ghost(t);
  state.beforeBulk = () => state.member.labels.push({ name: 'added-during-delivery' });
  assert.equal((await label_({ CLEANUP_MODE: 'unsubscribe' })).action, 'label');
  assert.deepEqual(state.member.labels.map((item) => item.name), ['added-after-creation', 'added-during-delivery', 'signup-shield-review']);
  assert.ok(state.calls.filter((call) => call.method !== 'GET').every((call) => call.url.pathname.endsWith('/members/bulk/')));
});

test('repeated labelling is idempotent and does not restore labels removed since creation', async (t) => {
  const state = ghost(t);
  await label_();
  assert.equal((await label_()).skipped, 'already-labelled');
  assert.deepEqual(state.member.labels.map((item) => item.name), ['added-after-creation', label.name]);
  assert.equal(state.calls.filter((call) => call.method === 'PUT').length, 1);
});

test('labeller creates the fixed label when missing, including a concurrent creation conflict', async (t) => {
  const state = ghost(t);
  state.label = null;
  state.createConflict = true;
  await label_();
  assert.ok(state.member.labels.some((item) => item.name === label.name));
  assert.equal(state.calls.filter((call) => call.method === 'POST').length, 1);
});

for (const status of ['paid', 'comped', 'gift']) {
  test(`stale free-member events cannot label a currently ${status} member`, async (t) => {
    const state = ghost(t);
    state.member.status = status;
    assert.equal((await label_()).skipped, 'not-free');
    assert.equal(state.calls.length, 1);
  });
}

test('eligibility uses the current email domain', async (t) => {
  const state = ghost(t);
  state.member.email = 'reader@gmail.com';
  assert.equal((await label_({ CLEANUP_SKIP_DOMAINS: 'gmail.com' })).skipped, 'consumer-domain');
  assert.equal(state.calls.length, 1);
});

test('members deleted after the event are skipped', async (t) => {
  const state = ghost(t);
  state.member = null;
  assert.equal((await label_()).skipped, 'member-missing');
  assert.equal(state.calls.length, 1);
});

test('bulk filter rechecks free status at write time', async (t) => {
  const state = ghost(t);
  state.beforeBulk = () => { state.member.status = 'paid'; };
  assert.equal((await label_()).skipped, 'not-free');
  assert.deepEqual(state.member.labels.map((item) => item.name), ['added-after-creation']);
});

test('an HTTP 200 bulk failure is accepted only after observing the applied label', async (t) => {
  const state = ghost(t);
  state.beforeBulk = () => state.member.labels.push(structuredClone(label));
  state.bulkResponse = { bulk: { meta: { stats: { successful: 0, unsuccessful: 1 } } } };
  assert.equal((await label_()).skipped, 'already-labelled');
});

test('HTTP 200 bulk failures throw when the label was not applied', async (t) => {
  const state = ghost(t);
  state.bulkResponse = { bulk: { meta: { stats: { successful: 0, unsuccessful: 1 } } } };
  await assert.rejects(label_());
  assert.deepEqual(state.member.labels.map((item) => item.name), ['added-after-creation']);
});

test('Admin API outages throw without writing labels', async (t) => {
  const state = ghost(t);
  state.readStatus = 503;
  await assert.rejects(label_());
  assert.equal(state.calls.length, 1);
});

test('invalid event IDs cannot broaden the additive member filter', async (t) => {
  const state = ghost(t);
  const queue = new LocalLabelQueue([]);
  assert.equal((await worker.fetch(event({ id: "x'+status:free" }), { ...env, LOCAL_MEMBER_LABELLER: queue })).status, 400);
  await queue.idle();
  assert.equal(state.calls.length, 0);
});

test('missing Worker labeller binding fails closed', async (t) => {
  const state = ghost(t);
  assert.equal((await worker.fetch(event(), env)).status, 503);
  assert.equal(state.calls.length, 0);
});

function deferred() {
  let resolve;
  const promise = new Promise((complete) => { resolve = complete; });
  return { promise, resolve };
}

// Sidecar delivery: acknowledged at once, labelled in the background.

test('sidecar acknowledges within Ghost\'s timeout and labels in the background', async (t) => {
  const state = ghost(t);
  const release = deferred();
  state.beforeBulk = () => release.promise;
  const queue = new LocalLabelQueue([]);
  const response = await worker.fetch(event(), { ...env, LOCAL_MEMBER_LABELLER: queue });
  assert.equal(response.status, 202);
  assert.deepEqual(await response.json(), { ok: true, queued: true });
  assert.equal(state.member.labels.some((item) => item.name === label.name), false);
  release.resolve();
  await queue.idle();
  assert.equal(state.member.labels.filter((item) => item.name === label.name).length, 1);
});

test('sidecar retries a failed labelling until it succeeds', async (t) => {
  const state = ghost(t);
  state.readFailures = 2;
  const warnings = t.mock.method(console, 'warn', () => {});
  const queue = new LocalLabelQueue([0, 0, 0]);
  assert.equal((await worker.fetch(event(), { ...env, LOCAL_MEMBER_LABELLER: queue })).status, 202);
  await queue.idle();
  assert.equal(state.member.labels.filter((item) => item.name === label.name).length, 1);
  assert.equal(queue.queue.pending.size, 0);
  assert.equal(warnings.mock.callCount(), 2);
  assert.match(String(warnings.mock.calls[0].arguments), /Admin API 503.*retrying/);
});

test('sidecar gives up after the retry schedule and logs without the member data', async (t) => {
  const state = ghost(t);
  state.readStatus = 503;
  const errors = t.mock.method(console, 'error', () => {});
  t.mock.method(console, 'warn', () => {});
  const queue = new LocalLabelQueue([0, 0]);
  assert.equal((await worker.fetch(event(), { ...env, LOCAL_MEMBER_LABELLER: queue })).status, 202);
  await queue.idle();
  assert.equal(state.calls.length, 3);
  assert.equal(errors.mock.callCount(), 1);
  assert.match(String(errors.mock.calls[0].arguments), /Admin API 503.*giving up/);
  assert.doesNotMatch(String(errors.mock.calls[0].arguments), /reader@|1111/);
});

for (const [name, config] of [
  ['a malformed Admin API key', { ADMIN_API_KEY: 'id:secret' }],
  ['a non-hex Admin API secret', { ADMIN_API_KEY: 'aaaaaaaaaaaaaaaaaaaaaaaa:' + 'z'.repeat(64) }],
  ['an invalid Admin API URL', { ADMIN_API_URL: 'admin.example' }],
]) {
  test(`webhook reports ${name} to Ghost instead of acknowledging`, async (t) => {
    const state = ghost(t);
    const queue = new LocalLabelQueue([]);
    const response = await worker.fetch(event(), { ...env, ...config, LOCAL_MEMBER_LABELLER: queue });
    assert.equal(response.status, 503);
    assert.match((await response.json()).error, /ADMIN_API_(KEY|URL)/);
    await queue.idle();
    assert.equal(state.calls.length, 0);
  });
}

test('unsigned requests learn nothing about the Admin API configuration', async (t) => {
  ghost(t);
  const unsigned = new Request('https://blog.example/signup-shield/webhooks/member-added', { method: 'POST', body: '{}' });
  const response = await worker.fetch(unsigned, { ...env, ADMIN_API_KEY: 'id:secret', LOCAL_MEMBER_LABELLER: new LocalLabelQueue([]) });
  assert.equal(response.status, 401);
  assert.doesNotMatch(await response.text(), /ADMIN_API/);
});

test('sidecar does not retry errors that retrying cannot fix', async (t) => {
  const state = ghost(t);
  state.readStatus = 401;
  const errors = t.mock.method(console, 'error', () => {});
  const queue = new LocalLabelQueue([0, 0, 0]);
  assert.equal((await worker.fetch(event(), { ...env, LOCAL_MEMBER_LABELLER: queue })).status, 202);
  await queue.idle();
  assert.equal(state.calls.length, 1);
  assert.match(String(errors.mock.calls[0].arguments), /Admin API 401.*not retrying/);
});

test('sidecar overlapping deliveries serialize the fresh read and unconditional insert', { timeout: 3000 }, async (t) => {
  const state = ghost(t);
  const enteredBulk = deferred();
  const releaseBulk = deferred();
  state.beforeBulk = async () => { enteredBulk.resolve(); await releaseBulk.promise; };
  t.after(() => releaseBulk.resolve());
  const queue = new LocalLabelQueue([]);
  const config = { ...env, LOCAL_MEMBER_LABELLER: queue };
  assert.equal((await worker.fetch(event(), config)).status, 202);
  await enteredBulk.promise;
  assert.equal((await worker.fetch(event(), config)).status, 202);
  assert.equal(state.calls.filter((call) => call.url.pathname.endsWith(`/members/${memberId}/`)).length, 1);
  releaseBulk.resolve();
  await queue.idle();
  assert.equal(state.calls.filter((call) => call.method === 'PUT').length, 1);
  assert.equal(state.member.labels.filter((item) => item.name === label.name).length, 1);
});

test('the queue allows different members to proceed independently', async () => {
  const queue = new MemberQueue();
  const release = deferred();
  const entered = deferred();
  const first = queue.run('member-one', async () => { entered.resolve(); await release.promise; });
  await entered.promise;
  try {
    assert.equal(await queue.run('member-two', async () => 'completed'), 'completed');
  } finally {
    release.resolve();
    await first;
  }
  assert.equal(queue.pending.size, 0);
});

// Worker delivery: the Durable Object stores the member and labels from its alarm.

function durable() {
  const data = new Map();
  const storage = {
    data, alarm: null,
    async get(key) { return data.get(key); },
    async put(key, value) { data.set(key, value); },
    async deleteAll() { data.clear(); },
    async getAlarm() { return storage.alarm; },
    async setAlarm(time) { storage.alarm = time; },
  };
  const object = new MemberLabeller({ storage }, env);
  // The runtime clears the alarm before invoking the handler.
  const fire = () => { storage.alarm = null; return object.alarm(); };
  const config = { ...env, MEMBER_LABELLER: {
    idFromName(key) { assert.equal(key, `https://admin.example:${memberId}`); return key; },
    get() { return { fetch: (input, init) => object.fetch(new Request(input, init)) }; },
  } };
  return { storage, fire, config };
}

test('Worker acknowledges at once and labels from the Durable Object alarm', async (t) => {
  const state = ghost(t);
  const { storage, fire, config } = durable();
  const responses = await Promise.all([worker.fetch(event(), config), worker.fetch(event(), config)]);
  assert.deepEqual(responses.map((response) => response.status), [202, 202]);
  assert.equal(state.calls.length, 0);
  assert.ok(storage.alarm <= Date.now());
  await fire();
  assert.equal(state.member.labels.filter((item) => item.name === label.name).length, 1);
  assert.equal(storage.data.size, 0);
  assert.equal(storage.alarm, null);
});

test('Worker retries failed labelling on the backoff schedule', async (t) => {
  const state = ghost(t);
  const { storage, fire, config } = durable();
  state.readStatus = 503;
  t.mock.method(console, 'warn', () => {});
  assert.equal((await worker.fetch(event(), config)).status, 202);
  const before = Date.now();
  await fire();
  assert.equal(storage.data.get('attempt'), 1);
  assert.ok(storage.alarm >= before + RETRY_DELAYS_MS[0]);
  state.readStatus = 200;
  await fire();
  assert.equal(state.member.labels.filter((item) => item.name === label.name).length, 1);
  assert.equal(storage.data.size, 0);
});

test('Worker keeps a delivery that arrives while a retry is pending or a run is in progress', async (t) => {
  const state = ghost(t);
  const { storage, fire, config } = durable();
  state.readStatus = 503;
  t.mock.method(console, 'warn', () => {});
  await worker.fetch(event(), config);
  await fire();
  await fire();
  assert.equal(storage.data.get('attempt'), 2);
  // A new delivery brings the pending retry forward with a fresh budget.
  await worker.fetch(event(), config);
  assert.ok(storage.alarm <= Date.now());
  assert.equal(storage.data.get('attempt'), 0);
  state.readStatus = 200;
  state.beforeBulk = () => worker.fetch(event(), config);
  await fire();
  // The mid-run delivery scheduled another pass, so state is kept for it.
  assert.notEqual(storage.alarm, null);
  await fire();
  assert.equal(state.calls.filter((call) => call.method === 'PUT').length, 1);
  assert.equal(storage.data.size, 0);
});

test('Worker gives up after the retry schedule', async (t) => {
  const state = ghost(t);
  const { storage, fire, config } = durable();
  state.readStatus = 503;
  const errors = t.mock.method(console, 'error', () => {});
  t.mock.method(console, 'warn', () => {});
  await worker.fetch(event(), config);
  for (let i = 0; i <= RETRY_DELAYS_MS.length; i++) await fire();
  assert.equal(state.calls.length, RETRY_DELAYS_MS.length + 1);
  assert.equal(errors.mock.callCount(), 1);
  assert.equal(storage.data.size, 0);
  assert.equal(storage.alarm, null);
});

test('Worker does not retry errors that retrying cannot fix', async (t) => {
  const state = ghost(t);
  const { storage, fire, config } = durable();
  state.readStatus = 403;
  const errors = t.mock.method(console, 'error', () => {});
  await worker.fetch(event(), config);
  await fire();
  assert.equal(state.calls.length, 1);
  assert.equal(storage.alarm, null);
  assert.equal(storage.data.size, 0);
  assert.match(String(errors.mock.calls[0].arguments), /Admin API 403.*not retrying/);
});

test('Worker keeps a delivery that arrives during the final attempt', async (t) => {
  const state = ghost(t);
  const { storage, fire, config } = durable();
  state.readStatus = 503;
  t.mock.method(console, 'warn', () => {});
  await worker.fetch(event(), config);
  for (let i = 0; i < RETRY_DELAYS_MS.length; i++) await fire();
  assert.equal(storage.data.get('attempt'), RETRY_DELAYS_MS.length);
  // The final attempt fails while a new delivery arrives.
  const originalGet = storage.get;
  storage.get = async (key) => {
    if (key === 'id') { storage.get = originalGet; await worker.fetch(event(), config); }
    return originalGet(key);
  };
  await fire();
  assert.notEqual(storage.alarm, null);
  assert.equal(storage.data.get('id'), memberId);
  assert.equal(storage.data.get('attempt'), 0);
  state.readStatus = 200;
  await fire();
  assert.equal(state.member.labels.filter((item) => item.name === label.name).length, 1);
  assert.equal(storage.data.size, 0);
});
