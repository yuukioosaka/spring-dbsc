# Manual testing: form login over HTTPS

An opt-in sample app for driving the DBSC flow from a real browser. It is **not
part of the library** — nothing in `src/demo` ends up in the published JAR.

## 1. Generate a keystore

DBSC needs a secure context. The binding cookie is `__Host-` prefixed, which
requires `Secure`, which requires HTTPS; over plain HTTP the browser drops the
cookies and the flow does nothing, with no error to explain it.

```sh
sh scripts/make-keystore.sh
```

That writes a self-signed EC keystore to `src/demo/resources/keystore.p12` with
`localhost`, `127.0.0.1` and `::1` in the SAN. Your browser will warn about the
certificate the first time — accept it, or `__Host-` cookies will not be stored.

## 2. Run it

```sh
mvn -Pdemo -Dmaven.repo.local=.m2repo spring-boot:run
```

Then open <https://localhost:8443/login> and sign in with `demo` / `demo`.

## 3. What to expect

After login the server calls `dbsc.bind()` with the **servlet session id**, so the
DBSC binding and the login session are the same session. The login response
carries:

- `Secure-Session-Registration: (ES256);path="/dbsc/registration";challenge="…"`
- `__Host-dbsc-reg` and `__Host-dbsc-challenge` cookies

On **Chromium 145+** the browser then POSTs `/dbsc/registration` by itself within
about a second, with a freshly generated key. No client code is involved. On
success it receives the third cookie, `__Host-dbsc-session` (the binding), and the
session tier becomes `dbsc`.

`GET /app` serves the demo page, and `GET /app/whoami` reports the live state as JSON:

```json
{"httpSessionId":"…","dbscSessionId":"…","userId":"demo",
 "tier":"none","deviceKey":false,"skippedReason":null,"coupled":true}
```

`httpSessionId` and `dbscSessionId` are expected to be equal: that equality is the
whole point of passing the application's own session id to `bind()`. `coupled` is
that comparison, pre-computed for you.

### What to look at in the browser DevTools network tab

DBSC is driven by the browser, not by the page, so the network tab is the only
place the protocol is visible. You should see two requests, neither of them
written by any JavaScript in this demo:

| Request | When | What to check |
|---|---|---|
| `POST /dbsc/registration` | about a second after the login response, once, automatically | it carries `Sec-Session-Response` (a JWS signed by the new hardware key) and the `__Host-dbsc-reg` / `__Host-dbsc-challenge` cookies; the response sets `__Host-dbsc-session` — the binding |
| `POST /dbsc/refresh` | on the binding cookie's cadence (`binding-cookie-ttl`, 10 min by default) | the same header, plus `Sec-Session-Id` naming the existing session; a successful refresh pushes the cookie's expiry out |

`GET /.well-known/device-bound-sessions` is **not** in the network tab: Chromium
sends that request itself from its own network stack, and it does not appear there.
Read it by hand instead — logged in, it returns the server's session config.

A refresh can also be triggered on demand from the browser's own session UI, which
is the convenient way to watch one without waiting out the TTL.

### What to look at when it does not bind

| Symptom | Cause |
|---|---|
| No `Secure-Session-Registration` in the login response | `bind()` was not called — check the success handler ran, and that the request was not cross-site (see the OIDC caveat) |
| Header present but no registration POST | browser older than Chromium 145, or the page was loaded over HTTP so the `__Host-` cookies were dropped |
| Registration POST returns `403` | challenge expired (5 min) or was already consumed; sign in again |
| Refresh loops forever after a server restart | in-memory storage. The demo is configured for file-backed H2 precisely to avoid this |

`Sec-Session-Skipped` on a request tells you the browser declined deliberately —
an unsupported platform, or a profile without the hardware key facility. That is
different from a failure, and `GET /app/whoami` reports it as `skippedReason`.

### The tier, and why it can go back down

The demo only ever produces two tiers:

| Tier | Meaning |
|---|---|
| `none` | no usable DBSC session — the state before the browser registers, and the state a failed refresh puts you back into |
| `dbsc` | the browser registered a native, hardware-backed key and the server holds it |

The interesting half is the demotion. `none` → `dbsc` happens by itself on
Chromium 145+, but the reverse is not an error path: if a refresh is refused — the
server restarted without the key, or the binding was terminated — the session
drops back to `none` rather than staying `dbsc` on a stale key. Refresh the
`/app/whoami` output after the browser's next refresh attempt and you can watch
the tier fall. The point of seeing it fall is that the tier is what the server
enforces *right now*, not a label granted once at registration.

## OIDC variant

The `oidc` profile swaps form login for `oauth2Login()`, to show that the DBSC
filters do not care how the user authenticated. It is not part of the library:
the `spring-boot-starter-oauth2-client` dependency is scoped to this profile and
never reaches the published JAR.

Nothing in the config names a particular directory, so point it at your own
provider. Register an app there, add the redirect URI below, and supply the three
values as environment variables:

```sh
ENTRA_TENANT_ID='…' \
ENTRA_CLIENT_ID='…' \
ENTRA_CLIENT_SECRET='…' \
  mvn -Pdemo,oidc -Dmaven.repo.local=.m2repo spring-boot:run
```

| Variable | What it is |
|---|---|
| `ENTRA_TENANT_ID` | Entra directory (tenant) id |
| `ENTRA_CLIENT_ID` | Application (client) id |
| `ENTRA_CLIENT_SECRET` | Client secret value |
| `ENTRA_ISSUER_URI` | Optional. Overrides the issuer entirely — set it for a non-Entra provider that has no tenant URL |

None of them belong in a config file that gets committed, and none are in the
repository. `ENTRA_CLIENT_SECRET` is the one that matters: an id is not a secret,
but a secret is, and it is read from the environment only.

Open <https://localhost:8443/app> and sign in at the identity provider. The
redirect URI to register on the app is Spring Security's callback path, **not**
`/oidc/bind`:

```
https://localhost:8443/login/oauth2/code/entraid
```

The callback itself does not call `bind()`; it answers with a one-line script that
navigates to `/oidc/bind`, where the binding happens. See the next section for why.

`entraid` is only a local registration name; it is what appears in that callback
URL. For a non-Entra provider, change the name (here and in the redirect URI) and
set `ENTRA_ISSUER_URI`. The `user-name-attribute: sub` default suits any provider
that issues a stable subject claim.

### Why the binding happens on `/oidc/bind`

The OIDC callback response is **cross-site**: Chromium makes DBSC requests inherit the
initiator of the request that caused them, and the initiator here is the identity
provider. A registration header returned straight from the callback therefore
produces a registration POST whose `SameSite=Lax` session cookie is withheld, and
Chromium records that failure as permanent and never retries for the rest of the
login.

The trap is that this does **not** stop at the callback. A server-side redirect keeps
the original initiator, so an earlier revision of this demo redirected to `/oidc` and
bound there — and `bind()` set `__Host-dbsc-reg` correctly, yet the very next
`POST /dbsc/registration` still arrived without it and was refused with
`SESSION_NOT_FOUND`. `/oidc` was a redirect target, so it was cross-site too.

What works is a navigation the browser issues on its own. So the success handler answers
the callback with a one-line `text/html` document whose script calls
`location.replace('/oidc/bind')`, and the binding is made on the route it reaches.

There is no relay route and no template: it is one line of script, so it lives inline in
the handler. It has to be HTML rather than bare JavaScript — a navigation response is
only executed when the browser reads it as a document, so serving `text/javascript`
here would get it downloaded or shown as text instead of run. The document needs no
`<html>` wrapper or doctype; a served page whose only content is the script is enough.

This is the pattern the README describes under "Binding behind OIDC or SAML", and it is
the variant that works unconditionally; hanging the binding on a route the user happened
to navigate to needs that navigation to exist, which a redirect chain never provides.

`DbscFilter` plays no part in any of this. It serves the protocol routes only and never
advertises the registration header on an application response, so the `bind()` calls in
`DemoOidcConfig.oidcBindRoute` and `DemoFormLoginConfig` are the whole mechanism.

Form login never hits any of this: it binds from a POST the browser made to this
origin, so the success handler is the right and only place.

### Resetting a poisoned browser

After a failed registration Chromium remembers it and will not retry, so a fixed
server still fails against the same browser profile. To start clean:

1. `chrome://device-bound-sessions` → delete the `https://localhost` entry
2. `chrome://settings/content/all` → `localhost:8443` → delete site data
3. restart the browser (the state can live in-process), and delete
   `data/demo.mv.db` so the server forgets the old session too

## Automated end-to-end test

The browser flow above is the manual check. For a repeatable one, run the suite in
`scripts/e2e.py` against a running demo — it drives the same paths over TLS as a
browser would, plus the ones a browser will not reach on demand (replayed
challenges, malformed headers, expired challenges).

The one-command form, which starts both instances the suite needs and then runs it:

```sh
sh scripts/run-demos.sh                # in another shell
DBSC_CHALLENGE_TTL=2 DBSC_RATE_LIMIT_FAILURES=5 python3 scripts/e2e.py
```

It needs the `cryptography` package (for ES256 signing) and prints a per-check
PASS/FAIL list plus a final tally. It does not test this file's manual steps; it
tests the protocol.

`scripts/check-error-coverage.py` is a companion gate: it fails if an error code is
defined in `DbscErrorCode` but never reached by the suite. That is how `RATE_LIMITED`
and `INVALID_JWK` were found to be unexercised.

### Testing challenge expiry

A challenge lives 5 minutes by default, which is too long to wait out. Start the
demo with a short TTL and declare it to the script:

```sh
mvn -Pdemo -Dmaven.repo.local=.m2repo \
    -Dspring-boot.run.jvmArguments="-Ddbsc.challenge-ttl=2s" spring-boot:run
DBSC_CHALLENGE_TTL=2 python3 scripts/e2e.py
```

Without `DBSC_CHALLENGE_TTL` the expiry check is reported as **skipped**, not
failed. Note that the challenge *cookie's* `Max-Age` tracks the TTL, so a client
honouring cookie expiry stops sending the JTI and the server reports
`CHALLENGE_NOT_FOUND` rather than `CHALLENGE_EXPIRED`. The suite therefore
re-sends the stale JTI by hand to reach the expiry branch.

### Testing rate limiting

`RATE_LIMITED` needs a **second** demo instance. The main one sets its budgets to
1000 (see the comment in `application-demo.yaml`) precisely so that this suite's own
deliberate failures do not throttle the run that is testing them — which leaves the
429 branch unreachable there. Start the low-budget instance alongside it:

```sh
mvn -Pdemo,ratelimit-e2e -Dmaven.repo.local=.m2repo \
    -Dspring-boot.run.jvmArguments="-Ddbsc.challenge-ttl=2s" spring-boot:run
DBSC_RATE_LIMIT_FAILURES=5 python3 scripts/e2e.py
```

It listens on 9443 with its own database file, so it cannot disturb the main run.
`DBSC_RATE_LIMIT_FAILURES` must match `dbsc.rate-limit.failure-capacity` in
`application-ratelimit-e2e.yaml`; nothing reads it from there. The limiter keys on
client IP and holds counters for a whole window, so a suite run right after another
may find the instance already throttled — the check reports that as *skipped*
rather than pretending the attempt count was observed. `scripts/run-demos.sh`
starts both instances for you.

## Notes on the wiring

Two chains, in order, both defined in `DemoFormLoginConfig`. This is the whole
integration — the library declares no chains of its own, so there is nothing to opt out
of or work around here:

- `@Order(0)` — `securityMatcher` on the DBSC paths, with `DbscFilter`, stateless,
  CSRF disabled. Chromium drives these routes before any user session exists and
  posts no CSRF token with them.
- `@Order(1)` — the application chain: form login, logout, the `/app` routes
  (`/app/payment` is an ordinary authenticated POST — nothing per-request is
  verified, because the library no longer ships a proof guard).

`bind()` is called from an `AuthenticationSuccessHandler`, declared inline in the
chain rather than as a separate class, because form login never reaches a handler
method on the way in. The success handler is the only place that sees the request,
the response and the authenticated user together.

Both filters are declared with `FilterRegistrationBean.setEnabled(false)`. Boot
would otherwise auto-register them as plain servlet filters running *outside* the
security chain — before authentication and on every path — which produces
confusing double execution.

## Pitfalls this demo exists to record

Each of these cost real debugging time, and each fails as a `403` that looks like
something else.

### `securityMatcher` is a setter, not an accumulator

The matcher must cover **every** protocol route, not just the obvious one. The
protocol routes have to be reachable unauthenticated — Chromium drives them before
any user session exists, and a `401` from Security's entry point is fatal to the
binding rather than a recoverable error. Leave one out and it falls through to the
application chain, which answers `403` before `DbscFilter` ever runs.

```java
// Wrong: only the LAST matcher survives. /dbsc/** falls through to the app
// chain, which answers Spring's 403 before DbscFilter ever runs.
.securityMatcher(new AntPathRequestMatcher("/dbsc/**"))
.securityMatcher(new AntPathRequestMatcher("/.well-known/device-bound-sessions"))

// Right: one matcher covering both routes.
.securityMatcher(new OrRequestMatcher(
        new AntPathRequestMatcher("/dbsc/**"),
        new AntPathRequestMatcher("/.well-known/device-bound-sessions")))
```

`securityMatcher(...)` is a **setter, not an accumulator** — that is the pitfall,
and it is independent of how many routes there are. Chaining two calls to it
silently keeps only the last, which is why the demo builds one `OrRequestMatcher`
in a single call.

### Anchor the DBSC filter on `CsrfFilter`

The order is `CsrfFilter` → `LogoutFilter` → `UsernamePasswordAuthenticationFilter`.
A filter placed before the last of those still lands *after* CSRF, so the browser's
registration POST is rejected by CSRF first and DBSC never sees it. The demo anchors on
`CsrfFilter` *and* disables CSRF on the protocol chain — either alone would do, but the
demo keeps both so the chain reads correctly on its own.

### An anchor naming a filter *position* does not require that filter

`addFilterBefore(..., CsrfFilter.class)` looks like a dependency on CSRF being enabled,
and `UsernamePasswordAuthenticationFilter.class` looks like one on `formLogin()`. Neither
is. `HttpSecurity` registers those classes as ordering *positions* in
`FilterOrderRegistration` when it is constructed, and anchoring on a position is valid
whether or not an instance ever exists at it — only an anchor naming a filter
**instance** creates a real dependency. That is why the DBSC filter installs identically
in a chain using OIDC (`oauth2Login()`), HTTP Basic, pre-authentication, or no
authentication at all.

### A `403` with a Spring error body did not come from DBSC

DBSC errors are `{"error":"CODE","message":…}`. A body of
`{"timestamp","status","error","path"}` did **not** come from `DbscFilter` — it is
Spring's error page, which means the request never reached the DBSC filter at all.
That distinction localises the bug immediately.

### CSRF token handling for `fetch()`

Form login uses the session CSRF repository, whose default handler only accepts the
token as a *request parameter*. The demo's `fetch()` calls send JSON, so any POST
would be refused by CSRF with a 403 indistinguishable from DBSC's. The demo wires
`HttpSessionCsrfTokenRepository` with `CsrfTokenRequestAttributeHandler` and renders
the token into a `<meta>` tag. The token is also **rotated on authentication**, so a
value read from the login form is stale — read it from a page served after login.

### Call `terminate()` on logout

Without a `LogoutHandler` that calls `dbsc.terminate()`, the device key outlives the
login session: the browser keeps refreshing a session the app has already ended, and
a later login re-couples to a stale key instead of registering fresh.

### Tomcat's header limit vs. the DBSC header limit

Tomcat defaults to an 8 KB *aggregate* header limit, which is smaller than the
8192-byte single-header limit DBSC enforces for `Sec-Session-Response` (the
registration JWS). Left alone, an oversized JWS is rejected by Tomcat with a 400
HTML page before any DBSC filter runs, so the spec's `MALFORMED_JWS` branch is
unreachable. `application-demo.yaml` raises `server.max-http-request-header-size`
so the protocol layer gets to judge it.
