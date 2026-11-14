# ghost-guard

Protect a self-hosted Ghost publication against two stages of signup abuse:

1. **Before an email is sent:** intercept signup requests to `/members/api/send-magic-link/`, verify an optional Turnstile challenge server-side, and enforce IP and email quotas.
2. **Before a member is created:** show a **Confirm signup** button when a signup magic link is opened. A scanner's GET/HEAD never reaches Ghost; only the form POST forwards the confirmation GET to Ghost.

The confirmation page has no JavaScript, auto-submit, or Turnstile widget. Explicit sign-in requests (`emailType: "signin"`) and sign-in magic links pass through unchanged. Both trailing-slash and case variants of the signup API are protected, matching Ghost's routing. Ghost defaults a missing `emailType` to `subscribe`, so omitted and unknown types receive signup protection too.

Ghost has no official plugin system. This is a proxy prototype, not an official Ghost plugin. It has automated tests but has not been deployed against a production Ghost site.

| Hosting | Deployment |
| --- | --- |
| Self-hosted with Cloudflare proxy | Cloudflare Worker with a SQLite-backed Durable Object |
| Self-hosted without Cloudflare proxy | Node 22.16+ sidecar, optionally Docker |
| Ghost(Pro) | Webhook labeller only; see the Ghost(Pro) note below |

## Self-hosted: Cloudflare Worker

Your Ghost hostname must already be proxied by Cloudflare. From this checkout:

```bash
npm ci
npx wrangler login
npx wrangler secret put CONFIRM_SECRET
npx wrangler secret put GHOST_ORIGIN
npx wrangler deploy
```

Use a long random `CONFIRM_SECRET`. Set `GHOST_ORIGIN` to a direct, DNS-only Ghost origin such as `https://origin.example.com`. The confirmation request includes the secret as `X-Ghost-Signup-Shield` to avoid intercepting its own follow-up request. A direct origin is recommended; without one the Worker uses same-zone forwarding. Restrict direct origin access to your proxy so attackers cannot bypass it.

`wrangler.toml` includes the static asset binding, the signup limiter and member labeller Durable Object bindings, and their `v1`/`v2` migrations. Deploy with this configuration when upgrading so the new labeller binding is present; a missing binding fails closed when the webhook is enabled. There is no KV namespace to create. Set `SITE_TITLE` and quotas in `[vars]` before deploying.

In Cloudflare **Workers & Pages → ghost-guard → Settings/Triggers → Routes**, attach:

```text
example.com/*
```

Route the **whole hostname** through the Worker. Ghost accepts case variants such as `/Members/API/Send-Magic-Link/`; a case-sensitive `/members*` Cloudflare route leaves those requests unprotected. The Worker protects the signup API and confirmation links, serves the Code Injection script and optional webhook, and forwards all other traffic to Ghost. Replace any older narrow routes for this Worker when updating an installation.

### Enable Turnstile on signup requests

1. Create a **Managed** Turnstile widget in Cloudflare, allowing your public Ghost hostname.
2. Set the widget's secret with `npx wrangler secret put TURNSTILE_SECRET`.
3. In **Ghost Admin → Settings → Advanced → Code injection → Site Header**, paste this, replacing the public sitekey:

```html
<script src="/ghost-guard/turnstile.js" data-sitekey="YOUR_PUBLIC_TURNSTILE_SITE_KEY"></script>
```

Save, then reload the public site before testing. Use Site Header, not an individual post's injection. Do not add `async` to this snippet. The Worker and sidecar both serve this URL. The public key is only in the snippet; `TURNSTILE_SITE_KEY` is no longer a server setting.

The script wraps `window.fetch` only for POSTs to this same site's `/members/api/send-magic-link/`, including case variants. Portal's API calls execute in the main page even though its UI uses frames. Explicit sign-in and unrelated requests keep their original arguments, including Request-object inputs. Every signup gets a fresh token from a managed widget; it stays unobtrusive unless Cloudflare requires interaction, and is removed after completion. Script/challenge failures return a Portal-readable JSON error without sending the signup request. Custom fetch-based forms on the same site work too; forms using XHR or normal HTML submission need their own token integration. Cross-origin Portal embeds are outside this snippet's scope.

For a custom client, send the token either as the `cf-turnstile-response` header or as a JSON field of that name. The server calls `https://challenges.cloudflare.com/turnstile/v0/siteverify` and checks success, hostname, and action `ghost_signup`. The expected hostname defaults to the incoming request hostname; use `TURNSTILE_HOSTNAME` if your public signup hostname differs. Tokens are removed before forwarding to Ghost. Missing, rejected, expired, reused, or unverifiable tokens yield HTTP 400:

```json
{"errors":[{"message":"Unable to verify your request, please try again","type":"ValidationError"}]}
```

**Turnstile is optional:** if `TURNSTILE_SECRET` is unset, token verification is skipped. Quotas and the click-to-confirm page remain active. To disable it cleanly, remove the Code Injection snippet as well. Configure the snippet and secret together. A widget alone is insufficient; see [Cloudflare's server validation requirements](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/).

### Rate limits and storage

Defaults are **5 signup requests per IP per hour** and **3 per email address per 24 hours**. These are independent windows anchored to the first allowed attempt. Email keys trim whitespace and ignore case; provider-specific aliases are not merged. Sign-in requests and confirmation clicks do not count.

The **IP quota runs before Turnstile**. Every well-formed signup attempt consumes it, including missing/invalid challenges and requests later rejected by the email quota. This bounds verification traffic from one IP. An attempt rejected by the IP quota makes no Siteverify call and does not extend that quota's window.

The **email quota runs after Turnstile**. Failed challenges never consume it, so they cannot exhaust another reader's daily allowance. With Turnstile disabled, every attempt allowed by the IP quota reaches the email check. An attempt forwarded to Ghost consumes both quotas even if Ghost subsequently fails.

Exceeding either quota returns HTTP **429** with Ghost-compatible `errors[].message` JSON and a **Retry-After** header in seconds for the quota that rejected the request.

The Worker uses **one SQLite-backed Durable Object per publication origin**, with each quota reservation in a synchronous transaction. IP and email checks run at their respective stages; concurrent requests cannot overrun either counter. KV's eventual consistency would allow quota overruns, which is why it is not used. Counter keys contain SHA-256 digests rather than plaintext IP/email values. An hourly alarm removes expired rows; expiry is also checked on each access. Missing/unavailable storage fails closed with 503. A single object is deliberately simple for publication signup traffic; very high traffic may need a different sharding design. Existing counter data and the `v1` migration remain compatible.

The sidecar uses the same quota algorithm with an **in-memory, per-process store**. Restarts reset quotas and multiple processes/replicas do not share them. Expired entries are swept during activity. Use one process or the Worker deployment if you need a shared durable limit.

## Self-hosted: Node / Docker sidecar

```bash
export GHOST_ORIGIN=http://127.0.0.1:2368
export SITE_TITLE="My Publication"
# Optional: export TURNSTILE_SECRET="your-widget-secret"
npm run sidecar
```

Or:

```bash
docker compose -f sidecar/docker-compose.yml up --build
```

Attach the container to Ghost's Docker network and adjust `GHOST_ORIGIN` in the compose file. The proxy listens on port 8787; Docker publishes it on loopback. It reuses the Worker's signup, confirmation, and webhook handlers. The Docker image includes the injection script. Incoming sidecar bodies are limited to 1 MiB.

Forward member paths **case-insensitively**, `/ghost-guard/`, and, if wanted, `/signup-shield/` to the sidecar. Keep other traffic going to Ghost. For example, in nginx:

```nginx
location ~* ^/members(?:/|$) {
    proxy_pass http://127.0.0.1:8787;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
}
location /ghost-guard/ {
    proxy_pass http://127.0.0.1:8787;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

The sidecar uses the TCP peer's IP and protocol by default and ignores client-supplied `CF-Connecting-IP`, `X-Forwarded-For`, and `X-Forwarded-Proto`. It rebuilds the upstream IP headers from the resolved client IP, preserving Ghost's own authentication throttling, and strips hop-by-hop headers in both directions. Chunked request bodies are buffered and reframed for the upstream connection. Behind nginx/Caddy, set **`TRUST_PROXY=true`** and ensure the immediate proxy **overwrites** `X-Forwarded-For` with the real client IP and `X-Forwarded-Proto` with the public request scheme, as above. The scheme must be preserved on signup and confirmation requests so Ghost does not redirect to an internal HTTPS address. Do not append untrusted incoming headers, and prevent direct public access to the sidecar. Ensure no other nginx location takes precedence and sends case variants directly to Ghost. Without a trusted proxy, leave this setting false. In Workers, Cloudflare supplies `CF-Connecting-IP`.

Use the same Code Injection snippet above for sidecar Turnstile. Its secret and quota variables are supplied through environment variables; `CONFIRM_SECRET` is unnecessary when the sidecar forwards directly to Ghost.

## Ghost(Pro) note

Ghost(Pro) does **not support another CDN/proxy in front of its service**; [Ghost's CDN policy](https://ghost.org/help/cdn-provider-support/) explains the restriction. Do not orange-cloud a Ghost(Pro) custom domain or deploy this request-intercepting setup there. Code Injection alone cannot enforce protection on Ghost's API or stop a confirmation that happens before theme HTML runs.

Use [Ghost's built-in signup spam protection](https://ghost.org/help/signup-spam-protection/) and contact Ghost support about recurring abuse. The only mode provided here for Ghost(Pro) is the **webhook labeller**, which runs after a member already exists. Do not add the Turnstile injection snippet for this mode.

### Optional webhook labeller

This handler only adds the fixed label **`signup-shield-review`**. It never deletes members or changes their newsletter subscriptions. Non-consumer email domains are a review heuristic, not proof of abuse; genuine work-address subscribers can be labelled too.

Deploy the Worker and use its default `workers.dev` URL (no proxy in front of your blog is needed). Configure:

```bash
npx wrangler secret put ADMIN_API_KEY
npx wrangler secret put WEBHOOK_SECRET
```

In `wrangler.toml` or the dashboard:

```toml
CLEANUP_ENABLED = "true"
ADMIN_API_URL = "https://your-site.ghost.io"
```

Create a **Custom Integration** in Ghost Admin with a **Member added** webhook targeting:

```text
https://YOUR-WORKER.workers.dev/signup-shield/webhooks/member-added
```

Use the same `WEBHOOK_SECRET` in Ghost. Its signature is required and checked with a five-minute timestamp tolerance. `ADMIN_API_KEY` is the integration's `id:secret` Admin API key. The labeller reads the current member before checking status, email domain, or an existing review label, rather than trusting the creation-time snapshot. It uses Ghost 6's Admin API label endpoints and the additive `members/bulk` `addLabel` operation, filtered to that member's ID and free status. Other labels are never replaced, including labels added concurrently. The review label is created when missing. Replayed events and concurrent duplicate deliveries are handled without adding a second review label; failed operations return 503 so delivery can be retried. The sidecar supports the same webhook settings if you need it for a self-hosted site.

The Worker routes each member's deliveries through the same **`MemberLabeller` Durable Object**. It serializes the entire current-member read and additive write, so overlapping deliveries cannot both observe an absent review label and insert it. Different members proceed independently. The sidecar uses the same queue logic **within one process**. Send webhooks to one sidecar process, or use the Worker labeller for multiple sidecar replicas; separate processes/deployments do not share these queues. This coordinates deliveries handled by this deployment, not other integrations independently editing the same label.

`CLEANUP_MODE` and `CLEANUP_LABEL` have been removed. Even a leftover `CLEANUP_MODE=unsubscribe` cannot enable automatic unsubscribing. Without `CLEANUP_SKIP_DOMAINS`, all new free members are eligible for review; the supplied Worker config includes common consumer domains. Webhook labelling does not prevent creation or establish that a signup is spam.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `GHOST_ORIGIN` | Worker: same-zone; sidecar: `http://127.0.0.1:2368` | Direct Ghost origin; Worker secret recommended |
| `CONFIRM_SECRET` | unset | Worker's secret bypass header for confirmation forwarding |
| `SITE_TITLE` | `this publication` | Name on the confirmation page |
| `INTERSTITIAL_ACTIONS` | `signup,subscribe,signup-paid` | Magic-link actions requiring a click |
| `TURNSTILE_SECRET` | unset | Enables server-side Turnstile on signup requests only |
| `TURNSTILE_HOSTNAME` | request hostname | Expected verified Turnstile hostname |
| `SIGNUP_IP_LIMIT` | `5` | Allowed signup attempts per IP/window |
| `SIGNUP_IP_WINDOW_SECONDS` | `3600` | IP window in seconds |
| `SIGNUP_EMAIL_LIMIT` | `3` | Allowed signup attempts per normalized email/window |
| `SIGNUP_EMAIL_WINDOW_SECONDS` | `86400` | Email window in seconds |
| `SIGNUP_RATE_LIMITER` | Wrangler binding | SQLite Durable Object namespace, Worker only |
| `MEMBER_LABELLER` | Wrangler binding | Shared per-member webhook serialization, Worker only |
| `ASSETS` | Wrangler binding | Serves the injection script, Worker only |
| `PORT` | `8787` | Sidecar listening port |
| `TRUST_PROXY` | `false` | Sidecar only: trust overwritten X-Forwarded-For and X-Forwarded-Proto from your proxy |
| `CLEANUP_ENABLED` | `false` | Enables label-only webhook when exactly `true` |
| `ADMIN_API_URL` | unset | Ghost Admin origin for the webhook |
| `ADMIN_API_KEY` | unset | Secret `id:secret` Custom Integration key |
| `WEBHOOK_SECRET` | unset | Required webhook signing secret when enabled |
| `CLEANUP_SKIP_DOMAINS` | See `wrangler.toml` | Comma-separated domains excluded from review |

Quota values must be positive integers; invalid/zero values fall back to the defaults. Windows are in seconds. There is no public signup-protection bypass flag. Keep Ghost's own invite-only or paid-only settings if open free signup is unnecessary.

## Verification and development

```bash
npm ci
npm test
npm run check
npx wrangler deploy --dry-run
npm run dev
# or: npm run sidecar
```

Tests use Node's built-in runner, mocked Siteverify responses, SQLite-backed counter tests, actual local HTTP sidecar requests, and Wrangler's local Worker runtime with real asset and Durable Object bindings. The browser script is exercised in a simulated DOM with a mocked Turnstile widget. `npm run check` includes `node --check` on both entry files, the limiter, and the public script. Local development/tests need Node 22.16+. No real Ghost or Cloudflare account is needed for the tests.

Before production, use a test Ghost publication and addresses you control:

1. With Turnstile enabled, sign up through Portal and verify that a token reaches the proxy. A direct signup API request without a token should return 400 and send no email. Confirm sign-in still works.
2. With small test quotas, exceed each limit independently and check 429 plus `Retry-After`. Restore the production values afterwards.
3. Open a fresh signup magic link in a private window (or use GET/HEAD from curl). It must return 200 HTML, without creating a member or consuming the token.
4. Click **Confirm signup**; check Ghost creates the member, redirects, and sets the session cookie. The confirmation page needs no JavaScript, even with signup Turnstile enabled.
5. Test your actual Portal/theme version, reverse proxy, trusted client IP, and Turnstile hostname. Custom clients must provide tokens when protection is enabled.

These layers reduce automated submissions and scanner confirmations; neither a button nor a challenge guarantees a human subscriber. The confirmation page alone does not stop emails being sent. This repository also contains an [upstream Ghost confirmation-page proposal](patch/confirmation-interstitial.md), not a ready-to-apply Ghost core patch.

To roll back, remove the proxy routes and the Code Injection snippet. On Cloudflare, remove the hostname-wide `example.com/*` route; Ghost then receives requests directly again. Remove any legacy narrow routes too.
