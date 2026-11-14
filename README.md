# ghost-guard

Stop Ghost signup spam that shows up as **real members with corporate email addresses**.

Those accounts are created because Ghost confirms a signup on a **plain GET** of the magic link. Corporate mail scanners prefetch that link. This package puts a **click-to-confirm page** in front of that GET, so a scanner visit no longer creates the member.

Ghost has **no official plugin system**. The most plugin-like, easy install depends on how you host:

| Hosting | Easiest install | What it does |
| --- | --- | --- |
| Self-hosted, DNS already on Cloudflare | **Deploy the Worker**, add one route | Interstitial. This is the real fix. |
| Self-hosted, no Cloudflare | **Docker sidecar** in front of Ghost | Same interstitial, no CF account. |
| Ghost(Pro) | **Webhook cleanup** on the same Worker | Labels (or unsubscribes) new corporate-domain members. Does *not* stop creation. A confirmation interstitial is not officially possible on Ghost(Pro) — see below. |

This repository is a prototype. It has not been published or deployed.

## Why a click is required

Ghost’s signup email points at:

```
https://yourdomain.com/members/?token=…&action=signup
```

A GET of that URL creates the member, sets a session cookie, and redirects. There is no human step. Mail scanners do that GET automatically. Ghost already allows the token to be reused for 10 minutes after the first hit (up to 7 uses, 24-hour lifetime) so Outlook Safe Links do not break the real user’s click — but the first scanner GET has already created the member.

This tool serves an HTML form on that GET and only forwards the request to Ghost after the form is POSTed. There is **no auto-submit JavaScript**; many scanners run JS.

A CAPTCHA on the signup *form* is useful against bots that submit addresses, but it does not stop a scanner confirming an email that was already sent.

## Install: self-hosted on Cloudflare (recommended)

You need: a Cloudflare account (free plan is enough) and the Ghost hostname already proxied (orange cloud).

### 1. Deploy the Worker

When this repo is on GitHub, the one-click path is:

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/beel-collab/ghost-guard)

Until then, from a checkout:

```bash
npm install
npx wrangler login
npx wrangler secret put CONFIRM_SECRET   # any long random string
npx wrangler deploy
```

Optional:

```bash
npx wrangler secret put GHOST_ORIGIN     # https://origin.yourdomain.com (DNS-only / direct to Ghost)
npx wrangler secret put TURNSTILE_SECRET # only if you also set TURNSTILE_SITE_KEY
```

Set `SITE_TITLE` and, if you use Turnstile, `TURNSTILE_SITE_KEY` in `wrangler.toml` or the dashboard.

`CONFIRM_SECRET` is sent as the `X-Ghost-Signup-Shield` header when the Worker forwards a confirmed click to Ghost, so the Worker does not intercept its own follow-up request. Prefer also setting `GHOST_ORIGIN` to a DNS-only hostname that points at Ghost, to avoid any routing loop.

### 2. Attach one route

In Cloudflare: **Workers & Pages → ghost-guard → Triggers → Add route**

```
yourdomain.com/members*
```

Leave the rest of the site unrouted. The Worker only changes signup/subscribe/signup-paid magic links under `/members`. Sign-in links (`action=signin`) pass through unchanged.

### 3. Check it

1. Sign up with an address you control.
2. Open the confirmation link in a private window, or `curl -I 'https://yourdomain.com/members/?token=…&action=signup'`.
3. You should get an HTML page, **not** a 302, and **no new member** in Ghost Admin yet.
4. Click **Confirm signup**. You should be signed in and the member should appear.

If legitimate signups 404 or loop, the route or `GHOST_ORIGIN` is wrong. Remove the route to roll back instantly.

## Install: self-hosted without Cloudflare (Docker sidecar)

Point your TLS terminator or nginx at this proxy, or proxy only `/members` to it.

```bash
# from the repo root
export GHOST_ORIGIN=http://127.0.0.1:2368
export SITE_TITLE="My Publication"
node sidecar/server.mjs
```

Or:

```bash
docker compose -f sidecar/docker-compose.yml up --build
```

Edit `GHOST_ORIGIN` in the compose file so it can reach Ghost on the same Docker network. Then, in nginx / Caddy, send `/members` to `http://signup-shield:8787` and everything else to Ghost as today.

## Install: Ghost(Pro) (webhook cleanup)

**Do not orange-cloud a Ghost(Pro) custom domain.** Official docs require Cloudflare DNS records to be **DNS only**, and stacking another CDN in front of Ghost(Pro) is unsupported:

- https://ghost.org/help/cloudflare-domain-setup/
- https://ghost.org/help/cdn-provider-support/

A Worker therefore **cannot** intercept `/members/?token=` on Ghost(Pro). Site Header code injection also cannot: Ghost confirms the signup in middleware and 302s before any theme or injected HTML runs.

The easy Ghost(Pro) hook is a **Custom Integration webhook**. This is post-hoc: the member is already created. The default action only **labels** them for review. That is safer than auto-delete.

1. Deploy the same Worker (button or `wrangler deploy`).
2. Add a route for `yourworkersubdomain.workers.dev/signup-shield/*` (the default `*.workers.dev` URL is enough; you do not need to proxy the blog).
3. Set secrets and vars:

   ```bash
   npx wrangler secret put ADMIN_API_KEY    # Staff settings → Integrations → Custom → Admin API key (id:secret)
   npx wrangler secret put WEBHOOK_SECRET   # any random string, same value you paste into Ghost
   ```

   In `wrangler.toml` or the dashboard:

   ```
   CLEANUP_ENABLED = "true"
   ADMIN_API_URL = "https://your-site.ghost.io"
   CLEANUP_MODE = "label"
   CLEANUP_LABEL = "signup-shield-review"
   ```

   Use `https://your-site.ghost.io` or your custom Admin URL. Set `CLEANUP_MODE=unsubscribe` only if you accept the risk of unsubscribing a real reader who signed up from work.

4. In Ghost Admin: **Settings → Integrations → Add custom integration**. Add a webhook:

   - Event: **Member added**
   - Target URL: `https://<your-worker>.workers.dev/signup-shield/webhooks/member-added`
   - Secret: the same `WEBHOOK_SECRET`

5. Filter Members by the label and unsubscribe or delete in bulk after a quick review.

What this mode **cannot** do: Ghost does not store the time between “magic link sent” and “member created”, and it does not store the confirmation request’s user-agent. `created_at` is the confirmation time. Heuristics here are “free member with a non-consumer email domain”. That will also catch real people who subscribe from work, which is why the default is **label**, not delete.

## What this is not

- A replacement for Ghost’s own settings (invite-only / paid-only still wins if you do not need open free signup).
- An official Ghost plugin.
- A complete bot-proof system. A human or a solver can still click the button. Optional Turnstile on the confirm page raises that bar.
- A way to finish Cloudflare Turnstile in Ghost core. That is a separate, still-open spike: https://github.com/TryGhost/Ghost/pull/29136

The durable product fix is an upstream confirmation interstitial in Ghost itself, sketched in [`patch/confirmation-interstitial.md`](patch/confirmation-interstitial.md). Discuss that on the Ghost forum before opening a PR; Ghost does not merge substantial new features without prior discussion.

## Configuration reference

| Name | Where | Purpose |
| --- | --- | --- |
| `CONFIRM_SECRET` | secret | Bypass header for the Worker’s own confirm request |
| `GHOST_ORIGIN` | secret | Direct Ghost origin (recommended) |
| `SITE_TITLE` | var | Name shown on the confirm page |
| `INTERSTITIAL_ACTIONS` | var | Default `signup,subscribe,signup-paid` |
| `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET` | var / secret | Optional challenge on the confirm page |
| `CLEANUP_ENABLED` | var | `true` to enable the webhook |
| `ADMIN_API_URL` | var | Ghost Admin origin |
| `ADMIN_API_KEY` | secret | `id:secret` Custom Integration key |
| `WEBHOOK_SECRET` | secret | Must match the Ghost webhook secret |
| `CLEANUP_MODE` | var | `label` (default) or `unsubscribe` |
| `CLEANUP_LABEL` | var | Label applied in `label` mode |
| `CLEANUP_SKIP_DOMAINS` | var | Consumer domains that are never labelled |

## Development

```bash
npm install
npm run dev          # wrangler dev
npm run sidecar      # node sidecar/server.mjs
```

Point a test Ghost’s public URL at the dev Worker or sidecar and use a signup link from the confirmation email.
