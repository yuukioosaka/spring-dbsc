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

| Route | Guarded | What it shows |
|---|---|---|
| `GET /app/whoami` | no | answers on a bare login cookie — this is what a stolen cookie replays |
| `POST /app/payment` | yes | `403` without a proof; `200` only with a valid body-bound proof |

The difference between those two rows is the whole feature.

### What to look at when it does not bind

| Symptom | Cause |
|---|---|
| No `Secure-Session-Registration` in the login response | `dbsc.enabled=false`, or `bind()` was not called — check the success handler ran |
| Header present but no registration POST | browser older than Chromium 145, or the page was loaded over HTTP so the `__Host-` cookies were dropped |
| Registration POST returns `403` | challenge expired (5 min) or was already consumed; sign in again |
| `/app/payment` always `403` | no `bound` key: the tier is `none` or `dbsc`. Per-request proofs need the **polyfill** key, not the native one |
| Refresh loops forever after a server restart | in-memory storage. The demo is configured for file-backed H2 precisely to avoid this |

`Sec-Session-Skipped` on a request tells you the browser declined deliberately —
an unsupported platform, or a profile without the hardware key facility. That is
different from a failure, and `GET /app/whoami` reports it.

## Automated end-to-end test

The browser flow above is the manual check. For a repeatable one, run the suite in
`scripts/e2e.py` against a running demo — it drives the same paths over TLS as a
browser would, plus the ones a browser will not reach on demand (stale proofs,
replayed challenges, malformed headers, the bound protocol):

```sh
mvn -Pdemo -Dmaven.repo.local=.m2repo spring-boot:run   # in another shell
python3 scripts/e2e.py
```

It needs the `cryptography` package (for ES256 signing) and prints a per-check
PASS/FAIL list plus a final tally. It does not test this file's manual steps; it
tests the protocol.

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

## Notes on the wiring

Two chains, in order, both defined in `DemoFormLoginConfig`. This is the whole
integration — the library declares no chains of its own, so there is nothing to opt out
of or work around here:

- `@Order(0)` — `securityMatcher` on the DBSC paths, with `DbscFilter`, stateless,
  CSRF disabled. Chromium drives these routes before any user session exists and
  posts no CSRF token with them.
- `@Order(1)` — the application chain: form login, the payment route, and
  `DbscProofGuardFilter`.

`bind()` is called from an `AuthenticationSuccessHandler` rather than a
controller, because form login never reaches a handler method on the way in. A
success handler is the only place that sees the request, the response and the
authenticated user together.

Both filters are declared with `FilterRegistrationBean.setEnabled(false)`. Boot
would otherwise auto-register them as plain servlet filters running *outside* the
security chain — before authentication and on every path — which produces
confusing double execution.

## Pitfalls this demo exists to record

Each of these cost real debugging time, and each fails as a `403` that looks like
something else.

### `securityMatcher` is a setter, not an accumulator

```java
// Wrong: only the LAST matcher survives. /dbsc/** falls through to the app
// chain, which answers Spring's 403 before DbscFilter ever runs.
.securityMatcher(new AntPathRequestMatcher("/dbsc/**"))
.securityMatcher(new AntPathRequestMatcher("/dbsc-bound/**"))

// Right:
.securityMatcher(new OrRequestMatcher(
        new AntPathRequestMatcher("/dbsc/**"),
        new AntPathRequestMatcher("/dbsc-bound/**"),
        new AntPathRequestMatcher("/.well-known/device-bound-sessions")))
```

### Anchor the DBSC filter on `CsrfFilter`, not `UsernamePasswordAuthenticationFilter`

The order is `CsrfFilter` → `LogoutFilter` → `UsernamePasswordAuthenticationFilter`.
A filter placed before the last of those still lands *after* CSRF, so the browser's
registration POST is rejected by CSRF first and DBSC never sees it. The demo anchors on
`CsrfFilter` *and* disables CSRF on the protocol chain — either alone would do, but the
demo keeps both so the chain reads correctly on its own.

### The `UsernamePasswordAuthenticationFilter` anchor does not require form login

Anchoring on `UsernamePasswordAuthenticationFilter.class` looks like a dependency on
`formLogin()`, so it is worth stating explicitly that it is not. `HttpSecurity`
registers that class as an ordering *position* in `FilterOrderRegistration` when it is
constructed; `formLogin()` merely adds an instance at that position. Anchoring on a
position is valid whether or not an instance exists, so the DBSC filters install
identically in a chain using OIDC (`oauth2Login()`), HTTP Basic, pre-authentication, or
no authentication at all. Only an anchor naming a filter **instance** creates a real
dependency. Verified in `NonFormLoginChainTest`.

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

### Tomcat's header limit vs. the proof limit

Tomcat defaults to an 8 KB *aggregate* header limit, which is smaller than the
8192-byte single-header limit DBSC enforces for `X-Dbsc-Bound-Proof`. Left alone, an
oversized proof is rejected by Tomcat with a 400 HTML page before any DBSC filter
runs, so spec 04's `MALFORMED_PROOF` branch is unreachable. `application-demo.yaml`
raises `server.max-http-request-header-size` so the protocol layer gets to judge it.
