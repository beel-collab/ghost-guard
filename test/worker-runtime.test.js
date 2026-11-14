import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('Wrangler runtime serves assets and atomically enforces Durable Object quotas', { timeout: 60000 }, async (t) => {
  const temp = await mkdtemp(join(tmpdir(), 'ghost-guard-runtime-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  process.env.XDG_CONFIG_HOME = temp;
  process.env.WRANGLER_LOG_PATH = join(temp, 'wrangler.log');
  process.env.WRANGLER_SEND_METRICS = 'false';
  const { unstable_dev } = await import('wrangler');
  let forwarded = 0;
  const origin = http.createServer(async (req, res) => {
    for await (const chunk of req) { void chunk; }
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
    vars: { GHOST_ORIGIN: `http://127.0.0.1:${origin.address().port}` },
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
});
