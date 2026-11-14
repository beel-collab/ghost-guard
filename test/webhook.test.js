import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import worker from '../src/worker.js';

const memberId = '111111111111111111111111';
const label = { id: '222222222222222222222222', name: 'signup-shield-review' };
const env = {
  CLEANUP_ENABLED: 'true', ADMIN_API_URL: 'https://admin.example',
  ADMIN_API_KEY: 'id:0123456789abcdef', WEBHOOK_SECRET: 'webhook-secret',
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
    createConflict: false, readStatus: 200,
  };
  t.mock.method(globalThis, 'fetch', async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method || 'GET';
    const body = init.body ? JSON.parse(init.body) : undefined;
    state.calls.push({ url, method, body });
    assert.equal(url.origin, 'https://admin.example');
    if (url.pathname === `/ghost/api/admin/members/${memberId}/` && method === 'GET') {
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
      state.beforeBulk?.();
      if (state.bulkResponse) return Response.json(state.bulkResponse);
      const matches = state.member?.id === memberId && state.member.status === 'free';
      if (matches && !state.member.labels.some((item) => item.name === label.name)) state.member.labels.push(structuredClone(label));
      return Response.json({ bulk: { meta: { stats: { successful: matches ? 1 : 0, unsuccessful: 0 } } } });
    }
    throw new Error(`Unexpected Admin API call: ${method} ${url.pathname}`);
  });
  return state;
}

test('delayed webhook only adds the review label and preserves current and concurrently added labels', async (t) => {
  const state = ghost(t);
  state.beforeBulk = () => state.member.labels.push({ name: 'added-during-delivery' });
  const response = await worker.fetch(event(), { ...env, CLEANUP_MODE: 'unsubscribe' });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).action, 'label');
  assert.deepEqual(state.member.labels.map((item) => item.name), ['added-after-creation', 'added-during-delivery', 'signup-shield-review']);
  assert.ok(state.calls.filter((call) => call.method !== 'GET').every((call) => call.url.pathname.endsWith('/members/bulk/')));
});

test('replayed events are idempotent and do not restore labels removed since creation', async (t) => {
  const state = ghost(t);
  const snapshot = { id: memberId, email: 'reader@work.example', status: 'free', labels: [{ name: 'removed-since-creation' }] };
  assert.equal((await worker.fetch(event(snapshot), env)).status, 200);
  const replay = await worker.fetch(event(snapshot), env);
  assert.equal(replay.status, 200);
  assert.equal((await replay.json()).skipped, 'already-labelled');
  assert.deepEqual(state.member.labels.map((item) => item.name), ['added-after-creation', label.name]);
  assert.equal(state.calls.filter((call) => call.method === 'PUT').length, 1);
});

test('labeller creates the fixed label when missing, including a concurrent creation conflict', async (t) => {
  const state = ghost(t);
  state.label = null;
  state.createConflict = true;
  assert.equal((await worker.fetch(event(), env)).status, 200);
  assert.ok(state.member.labels.some((item) => item.name === label.name));
  assert.equal(state.calls.filter((call) => call.method === 'POST').length, 1);
});

for (const status of ['paid', 'comped', 'gift']) {
  test(`stale free-member events cannot label a currently ${status} member`, async (t) => {
    const state = ghost(t);
    state.member.status = status;
    const response = await worker.fetch(event(), env);
    assert.equal((await response.json()).skipped, 'not-free');
    assert.equal(state.calls.length, 1);
  });
}

test('eligibility uses the current email domain', async (t) => {
  const state = ghost(t);
  state.member.email = 'reader@gmail.com';
  const response = await worker.fetch(event(), { ...env, CLEANUP_SKIP_DOMAINS: 'gmail.com' });
  assert.equal((await response.json()).skipped, 'consumer-domain');
  assert.equal(state.calls.length, 1);
});

test('members deleted after the event are skipped', async (t) => {
  const state = ghost(t);
  state.member = null;
  assert.equal((await (await worker.fetch(event(), env)).json()).skipped, 'member-missing');
  assert.equal(state.calls.length, 1);
});

test('bulk filter rechecks free status at write time', async (t) => {
  const state = ghost(t);
  state.beforeBulk = () => { state.member.status = 'paid'; };
  assert.equal((await (await worker.fetch(event(), env)).json()).skipped, 'not-free');
  assert.deepEqual(state.member.labels.map((item) => item.name), ['added-after-creation']);
});

test('concurrent duplicate delivery is accepted only after observing the applied label', async (t) => {
  const state = ghost(t);
  state.beforeBulk = () => state.member.labels.push(structuredClone(label));
  state.bulkResponse = { bulk: { meta: { stats: { successful: 0, unsuccessful: 1 } } } };
  const response = await worker.fetch(event(), env);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).skipped, 'already-labelled');
});

test('HTTP 200 bulk failures are retryable when the label was not applied', async (t) => {
  const state = ghost(t);
  state.bulkResponse = { bulk: { meta: { stats: { successful: 0, unsuccessful: 1 } } } };
  assert.equal((await worker.fetch(event(), env)).status, 503);
  assert.deepEqual(state.member.labels.map((item) => item.name), ['added-after-creation']);
});

test('Admin API outages are retryable without writing labels', async (t) => {
  const state = ghost(t);
  state.readStatus = 503;
  assert.equal((await worker.fetch(event(), env)).status, 503);
  assert.equal(state.calls.length, 1);
});

test('invalid event IDs cannot broaden the additive member filter', async (t) => {
  const state = ghost(t);
  assert.equal((await worker.fetch(event({ id: "x'+status:free" }), env)).status, 400);
  assert.equal(state.calls.length, 0);
});
