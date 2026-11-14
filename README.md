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

**Ghost in a subfolder.** If Ghost's `url` has a path, such as `https://example.com/blog`, set **`GHOST_BASE_PATH`** to it (`/blog`) in `wrangler.toml` `[vars]`; `wrangler deploy` replaces values set only in the dashboard. Signups then go to `/blog/members/api/send-magic-link/` and links to `/blog/members/?token=…`, and the Worker protects those paths instead of the root ones, ignoring case and repeated slashes like Ghost. Without this setting a subfolder install gets no protection. Requests outside the subfolder, including root `/members` paths, are not Ghost's: the Worker passes them to the hostname's normal Cloudflare origin rather than `GHOST_ORIGIN`, so a separate site at the root keeps working. A value a request path could never match, such as one containing `?`, `..` or `//`, makes member paths answer 500 (and logs why) rather than guess; the rest of the site keeps working. The script and webhook stay at the domain root (`/ghost-guard/…`, `/signup-shield/…`), so keep the route on the whole hostname.

### Enable Turnstile on signup requests

1. Create a **Managed** Turnstile widget in Cloudflare, allowing your public Ghost hostname.
2. Set the widget's secret with `npx wrangler secret put TURNSTILE_SECRET`.
3. In **Ghost Admin → Settings → Advanced → Code injection → Site Header**, paste this, replacing the public sitekey:

```html
<script src="/ghost-guard/turnstile.js" data-sitekey="YOUR_PUBLIC_TURNSTILE_SITE_KEY"></script>
```

The script covers any same-site path ending in `/members/api/send-magic-link`, so it needs no extra setting for Ghost in a subfolder; the server decides which paths it protects.

Save, then reload the public site before testing. Use Site Header, not an individual post's injection. Do not add `async` to this snippet. The Worker and sidecar both serve this URL. The public key is only in the snippet; `TURNSTILE_SITE_KEY` is no longer a server setting.

The script wraps `window.fetch` only for POSTs to this same site's `/members/api/send-magic-link/`, including case variants. Portal's API calls execute in the main page even though its UI uses frames. Explicit sign-in and unrelated requests keep their original arguments, including Request-object inputs. Every signup gets a fresh token from a managed widget; it stays unobtrusive unless Cloudflare requires interaction, and is removed after completion. Script/challenge failures return a Portal-readable JSON error without sending the signup request. Custom fetch-based forms on the same site work too; forms using XHR or normal HTML submission need their own token integration. Cross-origin Portal embeds are outside this snippet's scope.

For a custom client, send the token either as the `cf-turnstile-response` header or as a JSON field of that name. The server calls `https://challenges.cloudflare.com/turnstile/v0/siteverify` and checks success, hostname, and action `ghost_signup`. The expected hostname defaults to the incoming request hostname; use `TURNSTILE_HOSTNAME` if your public signup hostname differs. Tokens are removed before forwarding to Ghost. Missing, rejected, expired, reused, or unverifiable tokens yield HTTP 400:

```json
{"errors":[{"message":"Unable to verify your request, please try again","type":"ValidationError"}]}
```

**Turnstile is optional:** if `TURNSTILE_SECRET` is unset, token verification is skipped. Quotas and the click-to-confirm page remain active. To disable it cleanly, remove the Code Injection snippet as well. Configure the snippet and secret together. A widget alone is insufficient; see [Cloudflare's server validation requirements](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/).

### Rate limits and storage

Defaults are **5 signup requests per IP per hour** and **3 per email address per 24 hours**. These are independent windows anchored to the first allowed attempt. Email keys trim whitespace and ignore case; provider-specific aliases are not merged. Sign-in requests and confirmation clicks do not count. IPv6 clients are counted per **/64** network, the block one subscriber line usually receives, so rotating addresses within it does not reset the quota; IPv4 addresses are counted individually.

The **IP quota runs before Turnstile**. Every well-formed signup attempt consumes it, including missing/invalid challenges and requests later rejected by the email quota. This bounds verification traffic from one IP. An attempt rejected by the IP quota makes no Siteverify call and does not extend that quota's window.

The **email quota runs after Turnstile**. Failed challenges never consume it, so they cannot exhaust another reader's daily allowance. With Turnstile disabled, every attempt allowed by the IP quota reaches the email check. An attempt forwarded to Ghost consumes both quotas even if Ghost subsequently fails.

Exceeding either quota returns HTTP **429** with Ghost-compatible `errors[].message` JSON and a **Retry-After** header in seconds for the quota that rejected the request.

The Worker uses **one SQLite-backed Durable Object per Worker deployment**, shared by every hostname and scheme the Worker answers on (including `*.workers.dev`), with each quota reservation in a synchronous transaction. IP and email checks run at their respective stages; concurrent requests cannot overrun either counter. KV's eventual consistency would allow quota overruns, which is why it is not used. Counter keys contain SHA-256 digests rather than plaintext IP/email values. An hourly alarm removes expired rows; expiry is also checked on each access. Missing/unavailable storage fails closed with 503. A single object is deliberately simple for publication signup traffic; very high traffic may need a different sharding design. Existing counter data and the `v1` migration remain compatible.

The sidecar uses the same quota algorithm with an **in-memory, per-process store**. Restarts reset quotas and multiple processes/replicas do not share them. Expired entries are swept during activity. Use one process or the Worker deployment if you need a shared durable limit.

## Self-hosted: Node / Docker sidecar

```bash
export GHOST_ORIGIN=http://127.0.0.1:2368
export SITE_TITLE="My Publication"
# Behind a reverse proxy on this host (see below):
export TRUSTED_PROXIES=127.0.0.1,::1
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

For Ghost in a subfolder, set `GHOST_BASE_PATH` (for example `/blog`). Ghost-CLI's subfolder config serves Ghost from `location ^~ /blog`, and a `^~` prefix match stops nginx from checking regex locations, so a separate `/blog/members` regex location would never be used. Instead, point that existing `/blog` location's `proxy_pass` at the sidecar (`http://127.0.0.1:8787`), keeping its other directives: the sidecar protects the member paths and passes everything else under `/blog` to `GHOST_ORIGIN`. Keep `/ghost-guard/` (and `/signup-shield/` if used) at the root as above. The sidecar refuses to start with an invalid base path.

The sidecar uses the TCP peer's IP and protocol by default and ignores client-supplied `CF-Connecting-IP`, `X-Forwarded-For`, and `X-Forwarded-Proto`. It rebuilds the upstream IP headers from the resolved client IP, preserving Ghost's own authentication throttling, and strips hop-by-hop headers in both directions. Chunked request bodies are buffered and reframed for the upstream connection. Behind nginx/Caddy, set **`TRUSTED_PROXIES`** to the addresses your proxies connect from (comma-separated IPs or CIDR ranges). Without it, every reader shares the proxy's address, so the whole site gets one IP quota and Ghost's own throttling sees one client. The Docker Compose file defaults to loopback plus Docker's default bridge range (`127.0.0.1,::1,172.16.0.0/12`), where a host or container proxy connects from; narrow it to your proxy's address if untrusted containers share the network. Do not list ranges your readers connect from, such as a LAN: listed addresses are skipped as proxies, so a reader inside one could choose their IP. If your Docker networks use other ranges, add them. When an unlisted peer sends `X-Forwarded-For` or `X-Forwarded-Proto`, the sidecar logs one warning, the usual sign that this setting is missing or wrong. Entries with a port (`203.0.113.1:5555`) are accepted; an entry that is not an IP address falls back to the connecting peer. Only a listed peer may set `X-Forwarded-For` and `X-Forwarded-Proto`. The sidecar walks `X-Forwarded-For` from the right, skipping listed proxies, and uses the first other entry as the client, so it is correct whether the proxy overwrites the header (as above) or appends to it (`$proxy_add_x_forwarded_for`, Ghost-CLI's default), and with several proxy hops if each is listed. The proxy must set `X-Forwarded-For` itself: one that passes the client's header through unchanged lets clients choose their IP. It should also set `X-Forwarded-Proto` to the public request scheme. The older `TRUST_PROXY=true` still works but trusts every peer and uses the rightmost entry; it logs a warning at startup. The scheme must be preserved on signup and confirmation requests so Ghost does not redirect to an internal HTTPS address. Prevent direct access to the sidecar from anything but the proxy. Ensure no other nginx location takes precedence and sends case variants directly to Ghost. Leave `TRUSTED_PROXIES` unset only when clients connect to the sidecar directly. In Workers, Cloudflare supplies `CF-Connecting-IP`, and the Worker replaces any client-sent `X-Forwarded-For` with it before forwarding, because Ghost trusts the leftmost entry and Cloudflare only appends to what the client sent.

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
ADMIN_API_URL = "https://your-site.ghost.io"   # include the subfolder, e.g. https://example.com/blog
```

Create a **Custom Integration** in Ghost Admin with a **Member added** webhook targeting:

```text
https://YOUR-WORKER.workers.dev/signup-shield/webhooks/member-added
```

Use the same `WEBHOOK_SECRET` in Ghost. Its signature is required and checked with a five-minute timestamp tolerance. `ADMIN_API_KEY` is the integration's `id:secret` Admin API key. The labeller reads the current member before checking status, email domain, or an existing review label, rather than trusting the creation-time snapshot. It uses Ghost 6's Admin API label endpoints and the additive `members/bulk` `addLabel` operation, filtered to that member's ID and free status. Other labels are never replaced, including labels added concurrently. The review label is created when missing. Replayed events and concurrent duplicate deliveries are handled without adding a second review label. Ghost sends each webhook once, with a 2-second timeout and no retry, so the handler answers **202** as soon as the signature is verified and labels in the background. Before answering, it checks that `ADMIN_API_URL` is an http(s) URL and `ADMIN_API_KEY` has the `id:secret` form; if not, it returns 503 so the problem shows in Ghost Admin's webhook status. A failed attempt is retried after 30 s, 1, 2, 5, 15 and 30 minutes, then twice an hour later (just under 3 hours in total); after that the member stays unlabelled. Errors that a retry cannot fix, such as Admin API 401/403 or other 4xx responses except 408 and 429, stop immediately. Each failed attempt is logged with its reason (for example `Admin API 503`), never with member data, so check the Worker or sidecar logs if labels stop appearing. The sidecar supports the same webhook settings if you need it for a self-hosted site.

The Worker routes each member's deliveries through the same **`MemberLabeller` Durable Object**, which stores the member and labels from a Durable Object alarm. The runtime runs one alarm per object at a time, so overlapping deliveries cannot both observe an absent review label and insert it, and pending retries survive restarts. Different members proceed independently. The sidecar serializes and retries **within one process**, in memory: a restart drops pending retries. Send webhooks to one sidecar process, or use the Worker labeller for multiple sidecar replicas; separate processes/deployments do not share these queues. This coordinates deliveries handled by this deployment, not other integrations independently editing the same label.

`CLEANUP_MODE` and `CLEANUP_LABEL` have been removed. Even a leftover `CLEANUP_MODE=unsubscribe` cannot enable automatic unsubscribing. Without `CLEANUP_SKIP_DOMAINS`, all new free members are eligible for review; the supplied Worker config includes common consumer domains. Webhook labelling does not prevent creation or establish that a signup is spam.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `GHOST_ORIGIN` | Worker: same-zone; sidecar: `http://127.0.0.1:2368` | Direct Ghost origin; Worker secret recommended |
| `CONFIRM_SECRET` | unset | Worker's secret bypass header for confirmation forwarding |
| `SITE_TITLE` | `this publication` | Name on the confirmation page |
| `GHOST_BASE_PATH` | unset (domain root) | Subfolder Ghost is installed in, such as `/blog`; set it in `wrangler.toml` so deploys keep it |
| `INTERSTITIAL_ACTIONS` | `signup,subscribe,signup-paid` | Magic-link actions requiring a click |
| `TURNSTILE_SECRET` | unset | Enables server-side Turnstile on signup requests only |
| `TURNSTILE_HOSTNAME` | request hostname | Expected verified Turnstile hostname |
| `SIGNUP_IP_LIMIT` | `5` | Allowed signup attempts per IP/window |
| `SIGNUP_IP_WINDOW_SECONDS` | `3600` | IP window in seconds |
| `SIGNUP_EMAIL_LIMIT` | `3` | Allowed signup attempts per normalized email/window |
| `SIGNUP_EMAIL_WINDOW_SECONDS` | `86400` | Email window in seconds |
| `SIGNUP_RATE_LIMITER` | Wrangler binding | SQLite Durable Object namespace, Worker only |
| `MEMBER_LABELLER` | Wrangler binding | Per-member webhook serialization and retries, Worker only |
| `ASSETS` | Wrangler binding | Serves the injection script, Worker only |
| `PORT` | `8787` | Sidecar listening port |
| `TRUSTED_PROXIES` | unset (loopback and `172.16.0.0/12` in Docker Compose) | Sidecar only: addresses or CIDR ranges allowed to set X-Forwarded-For/-Proto |
| `TRUST_PROXY` | `false` | Sidecar only, legacy: `true` trusts forwarded headers from any peer; prefer `TRUSTED_PROXIES` |
| `CLEANUP_ENABLED` | `false` | Enables label-only webhook when exactly `true` |
| `ADMIN_API_URL` | unset | Ghost site URL for the webhook's Admin API calls, including any subfolder (`https://example.com/blog`) |
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
