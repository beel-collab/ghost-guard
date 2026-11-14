# Upstream sketch: signup confirmation interstitial

Do **not** open this as a PR without first discussing it on the Ghost forum.
Ghost’s contributing guide says new features and substantial product changes
must be discussed with the core team first:

- https://github.com/TryGhost/Ghost/blob/ab272fcb6056d23e32b307264eba35ffd27a921b/.github/CONTRIBUTING.md
- https://github.com/TryGhost/Ghost/blob/ab272fcb6056d23e32b307264eba35ffd27a921b/docs/contributing/workflow.md

This is a design-and-touch-list, not a ready-to-apply git patch.

## Why this change

Today, visiting the signup magic link with a GET creates the member.

`GET /members/?token=…&action=signup` hits global middleware that immediately
exchanges the token, creates the member, sets a session cookie, and 302s:

- `ghost/core/server/web/members/app.js` (`membersApp.use(middleware.createSessionFromMagicLink)`)
- `ghost/core/server/services/members/middleware.js` → `createSessionFromMagicLink`
- `ghost/core/server/services/members/members-ssr.js` → `exchangeTokenForSession`
- `ghost/core/server/services/members/members-api/members-api.js` → `getMemberDataFromMagicLinkToken` (creates the member on first successful signup token)

Corporate mail scanners prefetch that GET. Ghost already knows scanners hit
magic links: tokens are reusable up to 7 times for 10 minutes after first use,
for 24 hours from creation (`MAGIC_LINK_TOKEN_*` in
`ghost/core/server/services/members/api.js`). That grace period lets the real
person still sign *in* after a scanner visit. It does **not** prevent the
scanner’s GET from creating the member.

Turnstile on the signup *form* (PR #29136) does not fix this path. Once the
email is sent, a scanner still confirms it.

## Proposed behaviour

Behind a labs flag (then a Settings toggle once stable):

1. `GET /members/?token=&action=signup|subscribe|signup-paid` does **not**
   exchange the token. It returns a small HTML page: “Confirm your
   subscription” and a button. No auto-submit JavaScript (many scanners
   execute JS).
2. `POST /members/` with the same token (form body or hidden fields) runs the
   existing `exchangeTokenForSession` path and 302s as today.
3. `action=signin` and OTC (`otc_verification`) stay on the current GET
   exchange unless the team wants those too. Sign-in does not create members
   (`getMemberDataFromMagicLinkToken` refuses non-signup types).
4. The signup email can keep its current `<a href="${url}">` GET link
   (`ghost/core/server/services/members/emails/signup.js`). The GET now shows
   the interstitial, so email templates do not have to change.

## Labs flag

Follow `.agents/skills/add-private-feature-flag/SKILL.md`:

- Add `membersSignupConfirmationInterstitial` to `PRIVATE_FEATURES` in
  `ghost/core/shared/labs.js`
- Add the toggle in
  `apps/admin-x-settings/src/components/settings/advanced/labs/private-features.tsx`
- Update `ghost/core/test/unit/shared/labs.test.js` and the config API snapshot

No migration is required for a labs flag.

Ghost already uses labs for incomplete work (the unmerged Turnstile spike
proposes a `turnstile` flag). An interstitial has no third-party dependency,
which should be easier to accept than shipping Cloudflare Turnstile in core.

## Files to change

### 1. `ghost/core/server/services/members/middleware.js`

In `createSessionFromMagicLink` (starts ~line 467):

```js
const createSessionFromMagicLink = async function createSessionFromMagicLink(req, res, next) {
  if (!req.url.includes('token=')) {
    return next();
  }

  const action = req.query.action;
  const signupActions = new Set(['signup', 'subscribe', 'signup-paid']);
  const interstitialOn =
    labsService.isSet('membersSignupConfirmationInterstitial') &&
    signupActions.has(action);

  if (interstitialOn && req.method === 'GET') {
    res.set({ 'Cache-Control': 'no-store' });
    return res.type('html').send(renderSignupConfirmationPage({
      token: req.query.token,
      action,
      referrer: req.query.r,
      siteTitle: settingsCache.get('title'),
    }));
  }

  if (interstitialOn && req.method !== 'POST' && req.method !== 'GET') {
    res.set('Allow', 'GET, POST');
    return res.status(405).end();
  }

  // existing exchange + redirect, unchanged
};
```

Read the token for POST from `req.body.token` if present, falling back to
`req.query.token`. Mount `express.urlencoded()` for `/members` GET/POST
before this middleware, or parse the body only on POST here.

Do not call `exchangeTokenForSession` on the interstitial GET. That is the
whole fix.

### 2. New template

Add something like
`ghost/core/server/services/members/views/confirm-signup.html`
(or a JS template module next to `emails/signup.js`). Keep it small, no
external JS required, form `method="post"` to the same `/members/` URL,
hidden inputs for `token`, `action`, and `r`. Reuse site title / accent
colour from settings. Add i18n with `t()`.

### 3. Members app method / body parser

`ghost/core/server/web/members/app.js` currently registers
`createSessionFromMagicLink` with `membersApp.use(...)` on every method.
POST to `/members/` (no `/api`) already falls through this middleware, so
once the handler accepts POST, routing is enough. Add a urlencoded parser
scoped to this path if one is not already present.

### 4. Tests

- `ghost/test/e2e-frontend/members.test.js` and
  `ghost/test/e2e-api/members/signin.test.js`
- New cases, flag on:
  - GET signup token → 200 HTML, no member row, `used_count` unchanged
  - POST same token → 302, member created, session cookie set
  - GET with a scanner-like user-agent still does not create the member
  - GET `action=signin` still exchanges as today
  - Flag off → current GET-creates-member behaviour
- Keep the existing 7-use / 10-minute grace tests; they still apply after the
  first *confirming* use (the POST).

## What not to do in this PR

- Do not fold in Turnstile. That is PR https://github.com/TryGhost/Ghost/pull/29136
  and is a separate product decision (third-party key, privacy policy).
- Do not change token lifetime.
- Do not switch signup to OTC. OTC is sign-in only today
  (`RouterController._handleSignin` sets `includeOTC`; `_handleSignup` does not).
  A click on a hosted page is a better signup UX than typing a code.

## Suggested rollout

1. Forum thread describing the scanner-confirmation bug and this fix.
2. Labs-flagged PR, default off.
3. Enable on Ghost(Pro) after soak, then default on, then a documented
   Settings toggle if anyone needs the old GET-to-confirm behaviour.
