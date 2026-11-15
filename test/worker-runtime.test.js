import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHmac } from 'node:crypto';

test('Wrangler runtime serves assets and atomically enforces Durable Object quotas', { timeout: 60000 }, async (t) => {
  const temp = await mkdtemp(join(tmpdir(), 'ghost-guard-runtime-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  process.env.XDG_CONFIG_HOME = temp;
  process.env.WRANGLER_LOG_PATH = join(temp, 'wrangler.log');
  process.env.WRANGLER_SEND_METRICS = 'false';
  const { unstable_dev } = await import('wrangler');
  let forwarded = 0;
  const memberId = '111111111111111111111111';
  const reviewLabel = { id: '222222222222222222222222', name: 'signup-shield-review' };
  const labels = [];
  let labelWrites = 0;
  const origin = http.createServer(async (req, res) => {
    for await (const chunk of req) { void chunk; }
    if (req.url.startsWith('/ghost/api/admin/')) {
      res.setHeader('content-type', 'application/json');
      if (req.url.startsWith(`/ghost/api/admin/members/${memberId}/`)) {
        const snapshot = { id: memberId, email: 'reader@work.example', status: 'free', labels: structuredClone(labels) };
        await new Promise((resolve) => setTimeout(resolve, 15));
        res.end(JSON.stringify({ members: [snapshot] }));
      } else if (req.url.startsWith('/ghost/api/admin/labels/')) {
        res.end(JSON.stringify({ labels: [reviewLabel] }));
      } else if (req.url.startsWith('/ghost/api/admin/members/bulk/')) {
        await new Promise((resolve) => setTimeout(resolve, 15));
        // Match Ghost: every addLabel inserts a new physical relation.
        labels.push(reviewLabel);
        labelWrites++;
        res.end(JSON.stringify({ bulk: { meta: { stats: { successful: 1, unsuccessful: 0 } } } }));
      } else {
        res.writeHead(404);
        res.end('{}');
      }
      return;
    }
    forwarded++;
    res.writeHead(201, { 'content-type': 'application/json' });
    res.end('{}');
  });
  origin.listen(0, '127.0.0.1');
  await once(origin, 'listening');
  t.after(() => new Promise((resolve) => { origin.close(resolve); origin.closeAllConnections(); }));
  const dev = await unstable_dev('src/worker.js', {
    config: 'wrangler.toml', ip: '127.0.0.1', port: 0, inspectorPort: 0,
    local: true, persist: false, logLevel: 'error',
    vars: {
      GHOST_ORIGIN: `http://127.0.0.1:${origin.address().port}`,
      CLEANUP_ENABLED: 'true', ADMIN_API_URL: `http://127.0.0.1:${origin.address().port}`,
      ADMIN_API_KEY: 'aaaaaaaaaaaaaaaaaaaaaaaa:' + '0123456789abcdef'.repeat(4), WEBHOOK_SECRET: 'webhook-secret',
    },
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true, watch: false },
  });
  t.after(() => dev.stop());
  const script = await dev.fetch('/ghost-guard/turnstile.js');
  assert.equal(script.status, 200);
  assert.match(await script.text(), /window.fetch =/);
  const paths = ['/members/api/send-magic-link/', '/members/api/Send-Magic-Link/', '/MEMBERS/API/SEND-MAGIC-LINK'];
  const responses = await Promise.all(Array.from({ length: 20 }, (_, i) => dev.fetch(paths[i % paths.length], {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: `reader${i}@work.example`, emailType: 'signup' }),
  })));
  assert.equal(responses.filter((r) => r.status === 201).length, 5);
  assert.equal(responses.filter((r) => r.status === 429).length, 15);
  assert.ok(Number(responses.find((r) => r.status === 429).headers.get('retry-after')) > 3590);
  assert.equal(forwarded, 5);
  const signin = await dev.fetch('/members/api/send-magic-link/', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'existing@work.example', emailType: 'signin' }),
  });
  assert.equal(signin.status, 201);
  const page = await dev.fetch('/members/?token=abc&action=signup');
  assert.equal(page.status, 200);
  assert.doesNotMatch(await page.text(), /<script|turnstile|\.submit\(/i);
  assert.equal(forwarded, 6);

  const body = JSON.stringify({ member: { current: { id: memberId, email: 'reader@work.example' } } });
  const timestamp = String(Date.now());
  const hash = createHmac('sha256', 'webhook-secret').update(body + timestamp).digest('hex');
  const deliveries = await Promise.all(Array.from({ length: 10 }, () => dev.fetch('/signup-shield/webhooks/member-added', {
    method: 'POST', body, headers: { 'X-Ghost-Signature': `sha256=${hash}, t=${timestamp}` },
  })));
  // Ghost's 2 s webhook timeout: deliveries are acknowledged before labelling.
  assert.ok(deliveries.every((response) => response.status === 202));
  const deadline = Date.now() + 10000;
  while (labelWrites === 0 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 50));
  // Allow any extra alarm pass triggered by overlapping deliveries to finish.
  await new Promise((resolve) => setTimeout(resolve, 500));
  assert.equal(labelWrites, 1);
  assert.equal(labels.length, 1);
});

// The alarm logic assumes getAlarm() is null inside the running alarm unless a
// newer delivery set one. Exercise a real failure and retry in workerd.
test('Wrangler runtime protects setup revisions, expires login records, and retries webhook labelling', { timeout: 60000 }, async (t) => {
  const temp = await mkdtemp(join(tmpdir(), 'ghost-guard-retry-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  process.env.XDG_CONFIG_HOME = temp;
  process.env.WRANGLER_LOG_PATH = join(temp, 'wrangler.log');
  process.env.WRANGLER_SEND_METRICS = 'false';
  const { unstable_dev } = await import('wrangler');
  const memberId = '333333333333333333333333';
  const reviewLabel = { id: '222222222222222222222222', name: 'signup-shield-review' };
  const labels = [];
  let bulkAttempts = 0;
  const origin = http.createServer(async (req, res) => {
    for await (const chunk of req) { void chunk; }
    res.setHeader('content-type', 'application/json');
    if (req.url.startsWith(`/ghost/api/admin/members/${memberId}/`)) {
      res.end(JSON.stringify({ members: [{ id: memberId, email: 'reader@work.example', status: 'free', labels: structuredClone(labels) }] }));
    } else if (req.url.startsWith('/ghost/api/admin/labels/')) {
      res.end(JSON.stringify({ labels: [reviewLabel] }));
    } else if (req.url.startsWith('/ghost/api/admin/members/bulk/')) {
      // Fail the first write so the alarm has to schedule a retry.
      if (++bulkAttempts === 1) {
        res.writeHead(503);
        res.end('{}');
        return;
      }
      labels.push(reviewLabel);
      res.end(JSON.stringify({ bulk: { meta: { stats: { successful: 1, unsuccessful: 0 } } } }));
    } else {
      res.writeHead(404);
      res.end('{}');
    }
  });
  origin.listen(0, '127.0.0.1');
  await once(origin, 'listening');
  t.after(() => new Promise((resolve) => { origin.close(resolve); origin.closeAllConnections(); }));

  // Same Worker and Durable Objects, with the retry schedule shortened.
  const src = new URL('../src/', import.meta.url);
  const entry = join(temp, 'fast-retry-worker.js');
  await writeFile(entry, `
    import worker, { SignupRateLimiter, MemberLabeller, SetupStore as BaseSetupStore } from ${JSON.stringify(fileURLToPath(new URL('worker.js', src)))};
    import { RETRY_DELAYS_MS } from ${JSON.stringify(fileURLToPath(new URL('webhook.js', src)))};
    RETRY_DELAYS_MS.splice(0, RETRY_DELAYS_MS.length, 200, 200);
    export { SignupRateLimiter, MemberLabeller };
    export class SetupStore extends BaseSetupStore {
      async fetch(request) {
        const path = new URL(request.url).pathname;
        if (path === '/__test/expire-login') {
          await this.storage.put('setupToken', 'keep-token');
          await this.storage.put('fail:expired', {count:1,expires:Date.now()-1});
          await this.storage.put('fail:live', {count:8,expires:Date.now()+60000});
          await this.storage.setAlarm(Date.now());
          return Response.json({ok:true});
        }
        if (path === '/__test/storage') {
          return Response.json({
            failures:[...(await this.storage.list({prefix:'fail:'})).keys()],
            revision:(await this.storage.get('config')).revision,
            token:await this.storage.get('setupToken'),
          });
        }
        return super.fetch(request);
      }
    }
    export default {
      fetch(request, env) {
        const path = new URL(request.url).pathname;
        if (path.startsWith('/__test/')) {
          const store = env.SETUP_STORE.get(env.SETUP_STORE.idFromName('setup'));
          return store.fetch('https://setup-store' + (path === '/__test/config' ? '/config' : path), {
            method:path === '/__test/config' ? 'PUT' : request.method, body:request.body,
          });
        }
        return worker.fetch(request, env);
      },
    };
  `);
  const adminUrl = `http://127.0.0.1:${origin.address().port}`;
  const dev = await unstable_dev(entry, {
    config: 'wrangler.toml', ip: '127.0.0.1', port: 0, inspectorPort: 0,
    local: true, persist: false, logLevel: 'error',
    vars: {
      GHOST_ORIGIN: adminUrl, CLEANUP_ENABLED: 'false', ADMIN_API_URL: '',
      SETUP_TOKEN: 'runtime-setup-token',
    },
    experimental: { disableExperimentalWarning: true, disableDevRegistry: true, watch: false },
  });
  t.after(() => dev.stop());

  // SetupStore is the only source of labeller credentials, including in the
  // separately constructed Durable Object that performs background retries.
  const seeded = await dev.fetch('/__test/config', {
    method:'PUT', headers:{'content-type':'application/json'},
    body:JSON.stringify({value:{
      complete:true, hostname:'example.com',
      turnstileSecret:'runtime-turnstile-secret', turnstileSitekey:'runtime-public-key', turnstileEnabled:false,
      webhookEnabled:true, adminApiUrl:adminUrl,
      adminApiKey:'aaaaaaaaaaaaaaaaaaaaaaaa:' + '0123456789abcdef'.repeat(4),
      webhookSecret:'webhook-secret',
    }}),
  });
  assert.equal(seeded.status,200);
  const prepared = (await seeded.json()).value;
  const activation = {
    intent:'activate', snippet_installed:'on',
    setup_token:'runtime-setup-token', config_revision:prepared.revision,
  };
  const activated = await Promise.all(Array.from({length:2}, () => dev.fetch('/ghost-guard/setup', {
    method:'POST', headers:{'content-type':'application/x-www-form-urlencoded'},
    body:new URLSearchParams(activation),
  })));
  assert.deepEqual(activated.map(response => response.status).sort(), [200,409]);
  const staleSave = await dev.fetch('/__test/config', {
    method:'PUT', headers:{'content-type':'application/json'},
    body:JSON.stringify({value:prepared,expectedRevision:prepared.revision}),
  });
  assert.equal(staleSave.status,409);
  assert.equal((await dev.fetch('/__test/expire-login', {method:'POST'})).status,200);
  let saved;
  const sweepDeadline = Date.now() + 5000;
  do {
    saved = await (await dev.fetch('/__test/storage')).json();
    if (!saved.failures.includes('fail:expired')) break;
    await new Promise(resolve => setTimeout(resolve,50));
  } while (Date.now() < sweepDeadline);
  assert.deepEqual(saved.failures,['fail:live']);
  assert.notEqual(saved.revision,prepared.revision);
  assert.equal(saved.token,'keep-token');

  const body = JSON.stringify({ member: { current: { id: memberId, email: 'reader@work.example' } } });
  const timestamp = String(Date.now());
  const hash = createHmac('sha256', 'webhook-secret').update(body + timestamp).digest('hex');
  const delivery = await dev.fetch('/signup-shield/webhooks/member-added', {
    method: 'POST', body, headers: { 'X-Ghost-Signature': `sha256=${hash}, t=${timestamp}` },
  });
  assert.equal(delivery.status, 202);
  const deadline = Date.now() + 15000;
  while (labels.length === 0 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 50));
  // Leave time for any (wrong) extra pass before checking the totals.
  await new Promise((resolve) => setTimeout(resolve, 600));
  assert.equal(bulkAttempts, 2);
  assert.equal(labels.length, 1);
});
