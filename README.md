# ghost-guard

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/beel-collab/ghost-guard)

Protect a self-hosted Ghost publication against two stages of signup abuse:

1. **Before an email is sent:** intercept signup requests to `/members/api/send-magic-link/`, verify an optional Turnstile challenge server-side, and enforce IP and email quotas.
2. **Before a member is created:** show a **Confirm signup** button when a signup magic link is opened. A scanner's GET/HEAD never reaches Ghost; only the form POST forwards the confirmation GET to Ghost.

The confirmation page has no JavaScript, auto-submit, or Turnstile widget. Explicit sign-in requests (`emailType: "signin"`) and sign-in magic links pass through unchanged. Both trailing-slash and case variants of the signup API are protected, matching Ghost's routing. Ghost defaults a missing `emailType` to `subscribe`, so omitted and unknown types receive signup protection too.

Ghost has no official plugin system. This is a proxy prototype, not an official Ghost plugin. It has automated tests but has not been deployed against a production Ghost site.

## Quick start

Your Ghost hostname must already be proxied by Cloudflare (the orange cloud). Ghost(Pro) cannot sit behind this proxy; use the webhook-only note further down instead.

1. Click **Deploy to Cloudflare** above. When the deploy asks, set `SETUP_TOKEN` to a long random string. That value is the password for the setup page. Leave the Worker name as `ghost-guard`.
2. Open the setup page on the deploy result’s `*.workers.dev` URL, for example `https://ghost-guard.<account>.workers.dev/ghost-guard/setup`.
3. Submit the setup token, public Ghost URL (`https://yourdomain.com` or `https://yourdomain.com/blog`), and Cloudflare API token. The form attaches `yourdomain.com/*` and prepares a managed Turnstile widget. Ghost credentials are optional and needed only for the webhook labeller.
4. Copy the displayed snippet into **Ghost Admin → Settings → Advanced → Code injection → Site Header** and save. Keep other header HTML; replace an earlier ghost-guard block instead of adding a second one.
5. Return to setup, confirm the snippet is installed, and enter the setup token to **Activate signup protection**. Until activation, quotas and the confirmation page work, and Turnstile stays off. Reload your public site and test signup and sign-in.

From a checkout, set the token yourself and deploy:

```bash
npm ci
npx wrangler login
npx wrangler secret put SETUP_TOKEN
npx wrangler deploy
```

If `SETUP_TOKEN` is empty, the first visit generates one, and each page load until setup completes prints it **only** in the Worker logs (start `npx wrangler tail`, then reload the page), with the same `npx wrangler secret put SETUP_TOKEN` instruction. The page never shows the token. After eight wrong attempts from one IPv4 address or IPv6 /64, further attempts are refused for 15 minutes. An alarm removes expired login records. After setup finishes, opening the page shows status only; running it again asks for the token on the form.

The Deploy button reads `.dev.vars.example`, which lists `SETUP_TOKEN` so the dashboard can ask for it. `wrangler deploy` from a checkout does not prompt.

### Cloudflare API token

Create the token at <https://dash.cloudflare.com/profile/api-tokens> and include the Ghost zone:

| Scope | Permission |
| --- | --- |
| Zone | Zone: Read |
| Zone | Workers Routes: Edit |
| Account | Turnstile: Edit |
| Account | Workers Scripts: Edit |

The account ID is taken from the zone. Paste one into the form only if discovery fails. The token is used for that request and is not stored.

### What the form changes

- **Cloudflare:** route `<host>/*` on the Worker, reused when already attached, and a managed Turnstile widget named `ghost-guard-<host>` for that hostname. Setup stops if an overlapping route sends protected Ghost paths, the setup page, script or webhook to another Worker or bypasses Workers. Remove that route or assign it to this Worker before retrying. Unrelated paths and hostnames stay available to other apps. The form does not deploy Worker secrets.
- **Configuration:** `SetupStore` is the source of truth for settings saved through this form: Turnstile, the Ghost subfolder, and optional labeller credentials. Those saved fields override old environment values, including the Turnstile hostname and when the labeller is turned off. Manual installations with no saved setup configuration use environment variables. To change a guided installation, run the form again. Configuration read failures return 503 on signup and webhook requests; background labelling retries. With same-zone forwarding, ordinary pages, assets, sign-in and the confirmation interstitial do not read the setup store. A direct `GHOST_ORIGIN` reads it to select the Ghost subfolder before forwarding; if that read fails, forwarding uses the environment's `GHOST_BASE_PATH`, so also set it in `wrangler.toml` for a subfolder install.
- **Ghost snippet:** you paste the displayed public-key snippet into Site Header yourself. Integration API keys cannot edit Ghost settings. The widget secret stays in storage and is never included in HTML. Activation requires the setup token, confirmation that the snippet was saved, and a passing Turnstile check from the last run; a rerun where Turnstile rejects the secret returns an active widget to waiting (a siteverify outage keeps an active widget active). If the Worker also has its own `TURNSTILE_SECRET`, it applies whenever setup's widget is not active, and it rejects every signup once setup's snippet is in Site Header; delete it with `npx wrangler secret delete TURNSTILE_SECRET` after activating. Other Worker instances apply a save or activation to signups within 30 seconds; a webhook rejected by older settings is rechecked against the store, at most once per Worker instance every 5 seconds.
- **Optional webhook labeller:** choose **Enable** and supply a custom integration’s Admin API key (`id:secret`) plus a random webhook secret of 16–191 characters. After saving, open that integration in Ghost Admin and add a **Member added** webhook targeting `https://<host>/signup-shield/webhooks/member-added`, with the same secret. Update an existing matching webhook instead of creating another. No webhook-list API is called. Check a test delivery in Ghost Admin. Later runs keep the saved labeller unless you choose **Turn the labeller off**, which disables it and clears its stored credentials. A run that never enabled it leaves a manually configured labeller alone.

Repeat runs reuse the route and widget. An active widget remains active when its hostname and public key stay the same; a new widget waits for snippet installation and activation. Failed preparation leaves the previous stored configuration in place. Each save and activation checks a configuration revision inside the setup store. If another tab changes it, reload status before retrying; stale forms cannot activate a replacement widget or undo activation. The result includes a checklist; a red row gives a suggested fix. The confirmation check uses a fake token, and the sign-in check uses `ghost-guard-setup-check@example.invalid`; neither creates a member. A Worker fetch to its own zone skips the Worker, so open the public script and test confirmation and sign-in in a browser too.

The form does not set `GHOST_ORIGIN` or `CONFIRM_SECRET`. With no direct origin, the Worker forwards to the hostname's normal Cloudflare origin and does not need the bypass secret. Set those two by hand when Ghost is not that origin; the manual section below has the commands. Quotas and `SITE_TITLE` stay in `wrangler.toml`. The Node sidecar does not call the Cloudflare API; it shows a short page that links here.

| Hosting | Deployment |
| --- | --- |
| Self-hosted with Cloudflare proxy | Cloudflare Worker with a SQLite-backed Durable Object |
| Self-hosted without Cloudflare proxy | Node 22.16+ sidecar, optionally Docker |
| Ghost(Pro) | Webhook labeller only; see the Ghost(Pro) note below |

## Advanced: manual Cloudflare setup

Use this when you are not using `/ghost-guard/setup`. The [Quick start](#quick-start) flow guides the route, widget, snippet installation and activation.

Your Ghost hostname must already be proxied by Cloudflare.

**One-click:** the **Deploy to Cloudflare** button at the top copies this repository and deploys the Worker with its Durable Objects and assets from `wrangler.toml`. Set `SETUP_TOKEN` when the deploy asks, then use the setup page. To configure by hand instead, set `CONFIRM_SECRET`, `GHOST_ORIGIN`, and `TURNSTILE_SECRET` if used, in **Workers & Pages → ghost-guard → Settings → Variables and Secrets**, then attach the route described below.

**From a checkout:**

```bash
npm ci
npx wrangler login
npx wrangler secret put CONFIRM_SECRET
npx wrangler secret put GHOST_ORIGIN
npx wrangler deploy
```

Use a long random `CONFIRM_SECRET`. Set `GHOST_ORIGIN` to a direct, DNS-only Ghost origin such as `https://origin.example.com`. The confirmation request includes the secret as `X-Ghost-Signup-Shield` to avoid intercepting its own follow-up request. A direct origin is recommended; without one the Worker uses same-zone forwarding. Restrict direct origin access to your proxy so attackers cannot bypass it.

`wrangler.toml` includes the static asset binding, the signup limiter, member labeller, and setup-store Durable Object bindings, and their `v1`/`v2`/`v3` migrations. Deploy with this configuration when upgrading so the labeller and setup bindings are present; a missing labeller binding fails closed when the webhook is enabled, and a missing setup binding makes `/ghost-guard/setup` report that the migration has not run. There is no KV namespace to create. Set `SITE_TITLE` and quotas in `[vars]` before deploying.

In Cloudflare **Workers & Pages → ghost-guard → Settings/Triggers → Routes**, attach:

```text
example.com/*
```

Route the **whole hostname** through the Worker. Ghost accepts case variants such as `/Members/API/Send-Magic-Link/`; a case-sensitive `/members*` Cloudflare route leaves those requests unprotected. The Worker protects the signup API and confirmation links, serves the Code Injection script and optional webhook, and forwards all other traffic to Ghost. Replace any older narrow routes for this Worker when updating an installation.

**Ghost in a subfolder.** Protection needs no setting: the Worker protects any path ending in `/members/api/send-magic-link` and any `…/members?token=…` link, ignoring case and repeated slashes like Ghost, so `/blog/members/…` is covered automatically and a wrong setting can never turn protection off. What the setting changes is routing. With Ghost at `https://example.com/blog` and `GHOST_ORIGIN` set, set **`GHOST_BASE_PATH`** to `/blog` in `wrangler.toml` `[vars]` (`wrangler deploy` replaces values set only in the dashboard). Paths under `/blog` then go to `GHOST_ORIGIN`, and everything else goes to the hostname's normal Cloudflare origin, so a separate site at the root keeps working. Without `GHOST_ORIGIN`, every path already goes to that origin and the setting is not needed. A value no request path could match, such as one containing `?`, `..` or an interior `//`, is logged once and treated as matching nothing, so every page goes to the hostname's normal origin. The script and webhook stay at the domain root (`/ghost-guard/…`, `/signup-shield/…`), so keep the route on the whole hostname.

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

For a custom client, send the token either as the `cf-turnstile-response` header or as a JSON field of that name. The server calls `https://challenges.cloudflare.com/turnstile/v0/siteverify` and checks success, hostname, and action `ghost_signup`. Guided installations verify against the saved public Ghost hostname. In manual installations, the expected hostname defaults to the incoming request hostname; use `TURNSTILE_HOSTNAME` if your public signup hostname differs. For the sidecar, set it explicitly: there the request hostname comes from the client's `Host` header, so with a sitekey that covers several hostnames a token from one would be accepted for another. Tokens are removed before forwarding to Ghost. Missing, rejected, expired, reused, or unverifiable tokens yield HTTP 400:

```json
{"errors":[{"message":"Unable to verify your request, please try again","type":"ValidationError"}]}
```

**Turnstile is optional:** in manual installations, if `TURNSTILE_SECRET` is unset, token verification is skipped. Guided installations use the stored secret after activation. Quotas and the click-to-confirm page remain active. To disable it cleanly, remove the Code Injection snippet as well. Configure the snippet and secret together. A widget alone is insufficient; see [Cloudflare's server validation requirements](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/).

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

Attach the container to Ghost's Docker network and adjust `GHOST_ORIGIN` in the compose file. The proxy listens on port 8787; Docker publishes it on loopback. It reuses the Worker's signup, confirmation, and webhook handlers. The Docker image includes the injection script. Bodies ghost-guard reads itself (signup, confirmation and webhook requests) are limited to 1 MiB; everything else, such as Ghost Admin uploads, streams through in both directions, so your proxy's own limit applies.

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

For Ghost in a subfolder, Ghost-CLI's config serves Ghost from `location ^~ /blog`, and a `^~` prefix match stops nginx from checking regex locations, so a separate `/blog/members` regex location would never be used. Instead, point that existing `/blog` location's `proxy_pass` at the sidecar (`http://127.0.0.1:8787`), keeping its other directives such as `client_max_body_size`: the sidecar protects `/blog/members/…` and streams everything else under `/blog`, including Ghost Admin uploads, to `GHOST_ORIGIN`. The sidecar does not need `GHOST_BASE_PATH`, because nginx only sends it Ghost's paths. Keep `/ghost-guard/` (and `/signup-shield/` if used) at the root as above.

The sidecar uses the TCP peer's IP and protocol by default and ignores client-supplied `CF-Connecting-IP`, `X-Forwarded-For`, and `X-Forwarded-Proto`. It rebuilds the upstream IP headers from the resolved client IP, preserving Ghost's own authentication throttling, and strips hop-by-hop headers in both directions. Bodies ghost-guard reads are buffered and reframed for the upstream connection; all other bodies stream through. Behind nginx/Caddy, set **`TRUSTED_PROXIES`** to the addresses your proxies connect from (comma-separated IPs or CIDR ranges). Without it, every reader shares the proxy's address, so the whole site gets one IP quota and Ghost's own throttling sees one client. The Docker Compose file defaults to loopback plus Docker's default bridge range (`127.0.0.1,::1,172.16.0.0/12`), where a host or container proxy connects from; narrow it to your proxy's address if untrusted containers share the network. Do not list ranges your readers connect from, such as a LAN: listed addresses are skipped as proxies, so a reader inside one could choose their IP. If your Docker networks use other ranges, add them. When an unlisted peer sends `X-Forwarded-For` or `X-Forwarded-Proto`, the sidecar logs one warning, the usual sign that this setting is missing or wrong. Entries with a port (`203.0.113.1:5555`) are accepted; an entry that is not an IP address falls back to the connecting peer. Only a listed peer may set `X-Forwarded-For` and `X-Forwarded-Proto`. The sidecar walks `X-Forwarded-For` from the right, skipping listed proxies, and uses the first other entry as the client, so it is correct whether the proxy overwrites the header (as above) or appends to it (`$proxy_add_x_forwarded_for`, Ghost-CLI's default), and with several proxy hops if each is listed. The proxy must set `X-Forwarded-For` itself: one that passes the client's header through unchanged lets clients choose their IP. It should also set `X-Forwarded-Proto` to the public request scheme. The older `TRUST_PROXY=true` still works but trusts every peer and uses the rightmost entry; it logs a warning at startup. The scheme must be preserved on signup and confirmation requests so Ghost does not redirect to an internal HTTPS address. Prevent direct access to the sidecar from anything but the proxy. Ensure no other nginx location takes precedence and sends case variants directly to Ghost. Leave `TRUSTED_PROXIES` unset only when clients connect to the sidecar directly. In Workers, Cloudflare supplies `CF-Connecting-IP`, and the Worker replaces any client-sent `X-Forwarded-For` with it before forwarding, because Ghost trusts the leftmost entry and Cloudflare only appends to what the client sent.

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

In Ghost Admin, open the **Custom Integration** that owns the Admin API key and add a **Member added** webhook. For a guided installation, use the target shown by setup and the secret you entered there. For a manual webhook-only installation, target:

```text
https://YOUR-WORKER.workers.dev/signup-shield/webhooks/member-added
```

Use the same `WEBHOOK_SECRET` in Ghost. Its signature is required and checked with a five-minute timestamp tolerance. `ADMIN_API_KEY` is the integration's `id:secret` Admin API key. The labeller reads the current member before checking status, email domain, or an existing review label, rather than trusting the creation-time snapshot. It uses Ghost 6's Admin API label endpoints and the additive `members/bulk` `addLabel` operation, filtered to that member's ID and free status. Other labels are never replaced, including labels added concurrently. The review label is created when missing. Replayed events and concurrent duplicate deliveries are handled without adding a second review label. Ghost sends each webhook once, with a 2-second timeout and no retry, so the handler answers **202** as soon as the signature is verified and labels in the background. Before answering, it checks that `ADMIN_API_URL` is an http(s) URL and `ADMIN_API_KEY` has the `id:secret` form; if not, it returns 503 so the problem shows in Ghost Admin's webhook status. A failed attempt is retried after 30 s, 1, 2, 5, 15 and 30 minutes, then twice an hour later (just under 3 hours in total); after that the member stays unlabelled. Errors that a retry cannot fix, such as Admin API 401/403 or other 4xx responses except 408 and 429, stop immediately. Each failed attempt is logged with its reason (for example `Admin API 503`), never with member data, so check the Worker or sidecar logs if labels stop appearing. The sidecar supports the same webhook settings if you need it for a self-hosted site.

The Worker routes each member's deliveries through the same **`MemberLabeller` Durable Object**, which stores the member and labels from a Durable Object alarm. The runtime runs one alarm per object at a time, so overlapping deliveries cannot both observe an absent review label and insert it, and pending retries survive restarts. Different members proceed independently. The sidecar serializes and retries **within one process**, in memory: a restart drops pending retries. Send webhooks to one sidecar process, or use the Worker labeller for multiple sidecar replicas; separate processes/deployments do not share these queues. This coordinates deliveries handled by this deployment, not other integrations independently editing the same label.

`CLEANUP_MODE` and `CLEANUP_LABEL` have been removed. Even a leftover `CLEANUP_MODE=unsubscribe` cannot enable automatic unsubscribing. Without `CLEANUP_SKIP_DOMAINS`, all new free members are eligible for review; the supplied Worker config includes common consumer domains. Webhook labelling does not prevent creation or establish that a signup is spam.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `SETUP_TOKEN` | unset | Password for `/ghost-guard/setup`. `npx wrangler secret put SETUP_TOKEN`, or the value the Deploy button asks for. If it is empty, one is generated and printed only to the Worker logs on each setup page load until setup completes |
| `SETUP_STORE` | Wrangler binding | Durable Object holding guided setup settings; saved fields override environment values |
| `GHOST_ORIGIN` | Worker: same-zone; sidecar: `http://127.0.0.1:2368` | Direct Ghost origin; Worker secret recommended. Not set by the setup form |
| `CONFIRM_SECRET` | unset | Worker's secret bypass header for confirmation forwarding |
| `SITE_TITLE` | `this publication` | Name on the confirmation page |
| `GHOST_BASE_PATH` | unset (domain root) | Worker only: subfolder Ghost is installed in, such as `/blog`, so other paths go to the zone origin instead of `GHOST_ORIGIN`; set it in `wrangler.toml` so deploys keep it |
| `INTERSTITIAL_ACTIONS` | `signup,subscribe,signup-paid` | Magic-link actions requiring a click |
| `TURNSTILE_SECRET` | unset | Enables server-side Turnstile on signup requests only |
| `TURNSTILE_HOSTNAME` | request hostname | Expected verified Turnstile hostname; set it for the sidecar |
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
