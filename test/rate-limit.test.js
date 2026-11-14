import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { MemoryRateLimiter, SignupRateLimiter, checkSignupIpRateLimit, checkSignupEmailRateLimit, rateLimitConfig, ipBucket } from '../src/rate-limit.js';

// Run the DO's real SQL against SQLite; the Worker integration smoke test uses
// Wrangler's actual Durable Object runtime as well.
function sqliteStorage() {
  const db = new DatabaseSync(':memory:');
  let alarm = null;
  return {
    db,
    sql: { exec(query, ...args) {
      const statement = db.prepare(query);
      if (statement.columns().length) return { toArray: () => statement.all(...args) };
      statement.run(...args);
      return { toArray: () => [] };
    } },
    transactionSync(callback) {
      db.exec('BEGIN');
      try { const result = callback(); db.exec('COMMIT'); return result; }
      catch (error) { db.exec('ROLLBACK'); throw error; }
    },
    async getAlarm() { return alarm; },
    async setAlarm(value) { alarm = value; },
  };
}
function durableAdapter(storage) {
  const object = new SignupRateLimiter({ storage });
  return { object, consume: async (buckets) => (await object.fetch(new Request('https://limits/consume', { method: 'POST', body: JSON.stringify({ buckets }) }))).json() };
}
const buckets = (ip = 'ip:one', email = 'email:one') => [
  { key: ip, limit: 5, windowMs: 3600000 },
  { key: email, limit: 3, windowMs: 86400000 },
];

for (const adapter of ['memory', 'durable']) {
  test(`${adapter}: concurrent requests cannot exceed either quota`, async (t) => {
    const storage = adapter === 'durable' ? sqliteStorage() : null;
    if (storage) t.after(() => storage.db.close());
    const limiter = storage ? durableAdapter(storage) : new MemoryRateLimiter();
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => limiter.consume(buckets('ip:one', `email:${i}`))));
    assert.equal(results.filter((r) => r.allowed).length, 5);
    assert.equal(results.filter((r) => !r.allowed).length, 15);
    assert.ok(results.find((r) => !r.allowed).retryAfter > 3590);
  });

  test(`${adapter}: a rejected bucket batch is not partially reserved; windows expire independently`, async (t) => {
    let now = 1_000_000;
    t.mock.method(Date, 'now', () => now);
    const storage = adapter === 'durable' ? sqliteStorage() : null;
    if (storage) t.after(() => storage.db.close());
    const limiter = storage ? durableAdapter(storage) : new MemoryRateLimiter();
    for (let i = 0; i < 3; i++) assert.equal((await limiter.consume(buckets(`ip:${i}`, 'email:full'))).allowed, true);
    for (let i = 0; i < 8; i++) assert.equal((await limiter.consume(buckets('ip:fresh', 'email:full'))).allowed, false);
    for (let i = 0; i < 5; i++) assert.equal((await limiter.consume(buckets('ip:fresh', `email:new${i}`))).allowed, true);
    assert.equal((await limiter.consume(buckets('ip:fresh', 'email:another'))).allowed, false);
    now += 3600000;
    assert.equal((await limiter.consume(buckets('ip:fresh', 'email:another'))).allowed, true);
    assert.equal((await limiter.consume(buckets('ip:fresh', 'email:full'))).allowed, false);
    now += 86400000;
    assert.equal((await limiter.consume(buckets('ip:fresh', 'email:full'))).allowed, true);
  });
}

test('Durable Object counters survive object reconstruction and expired rows are removed by alarms', async (t) => {
  const storage = sqliteStorage();
  t.after(() => storage.db.close());
  let now = 1_000_000;
  t.mock.method(Date, 'now', () => now);
  const limiter = durableAdapter(storage);
  for (let i = 0; i < 3; i++) await limiter.consume(buckets());
  const recreated = durableAdapter(storage);
  assert.equal((await recreated.consume(buckets())).allowed, false);
  assert.ok(await storage.getAlarm());
  now += 86400000;
  await recreated.object.alarm();
  assert.equal(storage.sql.exec('SELECT key FROM counters').toArray().length, 0);
});

test('Worker uses the durable namespace and stores digests instead of email/IP', async () => {
  const seen = { bodies: [] };
  const env = { SIGNUP_RATE_LIMITER: {
    idFromName: (name) => { seen.name = name; return 'object-id'; },
    get: (id) => ({ async fetch(url, init) { seen.id = id; seen.bodies.push(init.body); return Response.json({ allowed: true }); } }),
  } };
  const request = new Request('https://blog.example/members/api/send-magic-link/', { headers: { 'CF-Connecting-IP': '192.0.2.1' } });
  assert.equal((await checkSignupIpRateLimit(request, env)).allowed, true);
  assert.equal((await checkSignupEmailRateLimit(request, 'Reader@Work.Example', env)).allowed, true);
  assert.equal(seen.name, 'https://blog.example');
  assert.equal(seen.id, 'object-id');
  for (const body of seen.bodies) assert.doesNotMatch(body, /192\.0\.2\.1|reader|work\.example/i);
  assert.match(JSON.parse(seen.bodies[0]).buckets[0].key, /^ip:[a-f0-9]{64}$/);
  assert.match(JSON.parse(seen.bodies[1]).buckets[0].key, /^email:[a-f0-9]{64}$/);
});

test('invalid configuration falls back to safe defaults', () => {
  assert.deepEqual(rateLimitConfig({ SIGNUP_IP_LIMIT: '0', SIGNUP_EMAIL_LIMIT: '-1', SIGNUP_IP_WINDOW_SECONDS: 'oops' }), {
    ipLimit: 5, emailLimit: 3, ipWindowMs: 3600000, emailWindowMs: 86400000,
  });
});

test('IPv6 addresses share one quota per /64; IPv4 and IPv4-mapped addresses stay exact', async () => {
  assert.equal(ipBucket('2001:db8:1:2::1'), '2001:db8:1:2::/64');
  assert.equal(ipBucket('2001:0DB8:0001:0002:ffff:1:2:3'), '2001:db8:1:2::/64');
  assert.equal(ipBucket('2001:db8::1'), '2001:db8:0:0::/64');
  assert.equal(ipBucket('fe80::1%eth0'), 'fe80:0:0:0::/64');
  assert.equal(ipBucket('64:ff9b:1:2::192.0.2.1'), '64:ff9b:1:2::/64');
  assert.equal(ipBucket('::1'), '0:0:0:0::/64');
  assert.equal(ipBucket('::ffff:192.0.2.1'), '192.0.2.1');
  assert.equal(ipBucket('192.0.2.1'), '192.0.2.1');
  assert.notEqual(ipBucket('2001:db8:1:2::1'), ipBucket('2001:db8:1:3::1'));

  const env = { LOCAL_RATE_LIMITER: new MemoryRateLimiter(), SIGNUP_IP_LIMIT: '2' };
  const from = (ip) => new Request('https://blog.example/', { headers: { 'CF-Connecting-IP': ip } });
  assert.equal((await checkSignupIpRateLimit(from('2001:db8:1:2::a'), env)).allowed, true);
  assert.equal((await checkSignupIpRateLimit(from('2001:db8:1:2:dead:beef:0:1'), env)).allowed, true);
  assert.equal((await checkSignupIpRateLimit(from('2001:db8:1:2::ffff'), env)).allowed, false);
  assert.equal((await checkSignupIpRateLimit(from('2001:db8:1:3::a'), env)).allowed, true);
});
