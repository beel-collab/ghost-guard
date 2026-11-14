/* Add this script in Ghost's Site Header Code Injection, with data-sitekey. */
(() => {
  'use strict';
  const sitekey = document.currentScript?.dataset.sitekey;
  if (!sitekey || window.__ghostGuardTurnstile) return;
  window.__ghostGuardTurnstile = true;

  const originalFetch = window.fetch.bind(window);
  let apiReady;

  function loadAPI() {
    if (window.turnstile) return Promise.resolve(window.turnstile);
    if (!apiReady) {
      apiReady = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        const timer = setTimeout(() => reject(new Error('Security check could not load.')), 15_000);
        script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
        script.async = true;
        script.onload = () => {
          clearTimeout(timer);
          if (window.turnstile) resolve(window.turnstile);
          else reject(new Error('Security check could not load.'));
        };
        script.onerror = () => {
          clearTimeout(timer);
          reject(new Error('Security check could not load.'));
        };
        document.head.appendChild(script);
      }).catch((error) => {
        apiReady = null;
        throw error;
      });
    }
    return apiReady;
  }

  async function getToken(signal) {
    const api = await loadAPI();
    if (signal.aborted) throw signal.reason;
    return new Promise((resolve, reject) => {
      const container = document.createElement('div');
      container.setAttribute('aria-label', 'Signup security check');
      Object.assign(container.style, { position: 'fixed', bottom: '16px', right: '16px', zIndex: '2147483647' });
      document.body.appendChild(container);
      let widget;
      let finished = false;
      const finish = (error, token) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        signal.removeEventListener('abort', abort);
        queueMicrotask(() => {
          if (widget !== undefined) api.remove(widget);
          container.remove();
        });
        if (error) reject(error);
        else resolve(token);
      };
      const abort = () => finish(signal.reason);
      const timer = setTimeout(() => finish(new Error('Security check timed out. Please try again.')), 120_000);
      signal.addEventListener('abort', abort, { once: true });
      try {
        widget = api.render(container, {
          sitekey,
          action: 'ghost_signup',
          execution: 'execute',
          appearance: 'interaction-only',
          callback: (token) => finish(null, token),
          'error-callback': () => finish(new Error('Security check failed. Please try again.')),
          'expired-callback': () => finish(new Error('Security check expired. Please try again.')),
          'timeout-callback': () => finish(new Error('Security check timed out. Please try again.')),
        });
        api.execute(widget);
      } catch (error) {
        finish(error);
      }
    });
  }

  window.fetch = async function (input, init) {
    // Never inspect or change requests to other endpoints or other sites.
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url, window.location.href);
    const method = (init?.method || input?.method || 'GET').toUpperCase();
    if (url.origin !== window.location.origin || url.pathname.replace(/\/+$/, '') !== '/members/api/send-magic-link' || method !== 'POST') {
      return originalFetch(input, init);
    }
    const request = new Request(typeof input === 'string' || input instanceof URL ? url.href : input, init);
    let body;
    try {
      body = await request.clone().json();
    } catch {
      return originalFetch(input, init);
    }
    if (!body || typeof body !== 'object' || Array.isArray(body) || body.emailType === 'signin') {
      return originalFetch(input, init);
    }
    try {
      const token = await getToken(request.signal);
      const headers = new Headers(request.headers);
      headers.set('cf-turnstile-response', token);
      return originalFetch(new Request(request, { headers }));
    } catch (error) {
      if (request.signal.aborted) throw error;
      return new Response(JSON.stringify({ errors: [{ message: 'Unable to verify your request, please try again', type: 'ValidationError' }] }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      });
    }
  };
})();
