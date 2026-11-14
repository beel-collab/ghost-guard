#!/usr/bin/env node
/**
 * Same confirmation interstitial, as a reverse proxy in front of self-hosted Ghost.
 * Use this when you are not putting the site on Cloudflare.
 *
 *   GHOST_ORIGIN=http://127.0.0.1:2368 PORT=8787 node sidecar/server.mjs
 */
import http from 'node:http';
import { Buffer } from 'node:buffer';

const ORIGIN = (process.env.GHOST_ORIGIN || 'http://127.0.0.1:2368').replace(/\/+$/, '');
const PORT = Number(process.env.PORT || 8787);
const SITE_TITLE = process.env.SITE_TITLE || 'this publication';
const ACTIONS = new Set(
  (process.env.INTERSTITIAL_ACTIONS || 'signup,subscribe,signup-paid')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
);

const workerEnv = {
  SITE_TITLE,
  INTERSTITIAL_ACTIONS: [...ACTIONS].join(','),
  TURNSTILE_SITE_KEY: process.env.TURNSTILE_SITE_KEY || '',
  TURNSTILE_SECRET: process.env.TURNSTILE_SECRET || '',
  CONFIRM_SECRET: process.env.CONFIRM_SECRET || 'sidecar-local',
  GHOST_ORIGIN: ORIGIN,
};

// Reuse the Worker module in Node 22+ by polyfilling the CF fetch handler via a tiny adapter.
const { default: worker } = await import('../src/worker.js');

function incomingToRequest(req, body) {
  const host = req.headers.host || `127.0.0.1:${PORT}`;
  const url = `http://${host}${req.url}`;
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (v) headers.set(k, Array.isArray(v) ? v.join(', ') : v);
  }
  const method = req.method || 'GET';
  const init = { method, headers };
  if (method !== 'GET' && method !== 'HEAD') {
    init.body = body;
  }
  return new Request(url, init);
}

async function writeResponse(res, response) {
  const headers = {};
  response.headers.forEach((value, key) => {
    // Node treats set-cookie specially; collect later if multiple.
    if (key.toLowerCase() === 'set-cookie') {
      const prev = headers['set-cookie'];
      headers['set-cookie'] = prev ? [].concat(prev, value) : value;
    } else {
      headers[key] = value;
    }
  });
  res.writeHead(response.status, headers);
  if (reqMethodIsHead(response) || response.status === 204) {
    res.end();
    return;
  }
  const buf = Buffer.from(await response.arrayBuffer());
  res.end(buf);
}

function reqMethodIsHead(response) {
  return response.status === 200 && response.headers.get('content-length') === '0' && !response.body;
}

const server = http.createServer(async (req, res) => {
  try {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    const request = incomingToRequest(req, body.length ? body : undefined);
    const response = await worker.fetch(request, workerEnv);
    await writeResponse(res, response);
  } catch (err) {
    console.error(err);
    res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('signup-shield proxy error');
  }
});

server.listen(PORT, () => {
  console.log(`ghost-guard sidecar listening on :${PORT} → ${ORIGIN}`);
});
