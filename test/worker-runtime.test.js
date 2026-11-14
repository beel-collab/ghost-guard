import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
      ADMIN_API_KEY: 'id:0123456789abcdef', WEBHOOK_SECRET: 'webhook-secret',
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
