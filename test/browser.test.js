import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const script = await readFile(new URL('../public/ghost-guard/turnstile.js', import.meta.url), 'utf8');
function browser({ failure = false, unavailable = false } = {}) {
  const calls = [];
  const widgets = new Map();
  let sequence = 0;
  const elements = [];
  const window = {
    location: { href: 'https://blog.example/article/', origin: 'https://blog.example' },
    fetch: async (...args) => { calls.push(args); return new Response('{}', { status: 201 }); },
    turnstile: unavailable ? undefined : {
      render: (container, options) => { const id = ++sequence; widgets.set(id, options); return id; },
      execute: (id) => queueMicrotask(() => failure ? widgets.get(id)['error-callback']() : widgets.get(id).callback(`token-${id}`)),
      remove: (id) => widgets.delete(id),
    },
  };
  const document = {
    currentScript: { dataset: { sitekey: 'public-key' } },
    createElement: () => ({ style: {}, setAttribute() {}, remove() { this.removed = true; } }),
    body: { appendChild(element) { elements.push(element); } },
    head: { appendChild(element) { queueMicrotask(() => element.onerror()); } },
  };
  const context = vm.createContext({ window, document, URL, Request, Response, Headers, Promise, setTimeout, clearTimeout, queueMicrotask });
  vm.runInContext(script, context);
  return { window, document, context, calls, widgets, elements };
}
const options = (emailType = 'signup') => ({ method: 'POST', headers: { 'content-type': 'application/json', 'x-original': 'kept' }, body: JSON.stringify({ email: 'reader@work.example', emailType }), credentials: 'include' });

test('Portal URL gets a fresh, single-use token per request; preserves the original body/options', async () => {
  const b = browser();
  const init = options();
  await b.window.fetch('/members/api/send-magic-link/', init);
  await b.window.fetch(new Request('https://blog.example/members/api/send-magic-link', options()));
  const [first] = b.calls[0];
  const [second] = b.calls[1];
  assert.equal(first.headers.get('cf-turnstile-response'), 'token-1');
  assert.equal(second.headers.get('cf-turnstile-response'), 'token-2');
  assert.equal(first.headers.get('x-original'), 'kept');
  assert.equal(first.credentials, 'include');
  assert.equal(await first.text(), init.body);
  assert.equal(init.headers['cf-turnstile-response'], undefined);
  assert.equal(b.widgets.size, 0);
  assert.ok(b.elements.every((element) => element.removed));
});

test('signin and unrelated fetches pass through with the exact original arguments', async () => {
  const b = browser();
  for (const [url, init] of [
    ['/members/api/send-magic-link/', options('signin')],
    ['/members/api/site/', options()],
    ['https://other.example/members/api/send-magic-link/', options()],
    ['/members/api/send-magic-link/', { method: 'GET' }],
  ]) {
    await b.window.fetch(url, init);
    assert.equal(b.calls.at(-1)[0], url);
    assert.equal(b.calls.at(-1)[1], init);
  }
  assert.equal(b.elements.length, 0);
});

test('omitted emailType is treated as signup, just like Ghost default subscribe', async () => {
  const b = browser();
  const init = options();
  init.body = JSON.stringify({ email: 'reader@work.example' });
  await b.window.fetch('/members/api/send-magic-link/', init);
  assert.ok(b.calls[0][0].headers.get('cf-turnstile-response'));
});

for (const configuration of [{ failure: true }, { unavailable: true }]) {
  test(`challenge failure produces a Portal-readable error without sending signup: ${JSON.stringify(configuration)}`, async () => {
    const b = browser(configuration);
    const response = await b.window.fetch('/members/api/send-magic-link/', options());
    assert.equal(response.status, 400);
    assert.match((await response.json()).errors[0].message, /verify/);
    assert.equal(b.calls.length, 0);
  });
}

test('aborted signup is not sent and duplicate injection does not wrap fetch twice', async () => {
  const b = browser();
  const installed = b.window.fetch;
  vm.runInContext(script, b.context);
  assert.equal(b.window.fetch, installed);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(b.window.fetch('/members/api/send-magic-link/', { ...options(), signal: controller.signal }), { name: 'AbortError' });
  assert.equal(b.calls.length, 0);
});
