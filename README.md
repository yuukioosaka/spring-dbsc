# spring-dbsc

[![Build](https://github.com/yuukioosaka/spring-dbsc/actions/workflows/build.yml/badge.svg)](https://github.com/yuukioosaka/spring-dbsc/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

A Spring Boot **library** implementation of **DBSC (Device Bound Session
Credentials)**, built against the [W3C draft](https://w3c.github.io/webappsec-dbsc/)
and the [`dbsc-toolkit`](https://www.npmjs.com/package/dbsc-toolkit) protocol
specification.

This artifact is meant to be **embedded in an existing Spring Boot application**:
it ships no `@SpringBootApplication` and no controllers. You add it as a
dependency, call `bind()` from your own login route, and add its filters to your
own security chain.

The point of DBSC: a session cookie stolen off the wire is useless on another
device, because the session is bound to a private key that never leaves the
browser's hardware. When the owner's browser refreshes the binding and the
attacker's device cannot produce the signature, the session is demoted to `none`
and the theft is reported as `session_stolen`.

## What's implemented

| Area | Status |
|---|---|
| Native protocol | ✅ registration, refresh, well-known document |
| Hardware-backed key binding (TPM / Secure Enclave) | ✅ `ES256` + `RS256` |
| Atomic challenge consumption | ✅ in-memory + JDBC + Redis |
| Tier model + demotion-on-failure | ✅ `dbsc` / `none` |
| Route guard | ✅ opt-in per route; refuses anything not currently `dbsc`, and a bound session that omits its DBSC cookies |
| Telemetry events | ✅ 7 event types |
| Rate limiting | ✅ per-IP, with a separate failure budget |
| Credential rotation on refresh | ✅ always on; bounds how long a captured credential cookie is worth |
| Session scope rules | ✅ `scope.scope_specification` — include/exclude by domain and path |
| Refresh-initiator allow-list | ✅ `allowed_refresh_initiators`, closing the out-of-scope timing side channel |
| Application-session binding | ✅ the DBSC session id is bound to your own session id (`JSESSIONID`, Spring Session, …), so the guard can tell a client that never bound from one that dropped its DBSC cookies — see [What the guard actually decides](#what-the-guard-actually-decides) |

## The protection model

DBSC — the [W3C draft](https://w3c.github.io/webappsec-dbsc/) and what Chromium
implements — is what this library implements, and this library implements *only*
that. The browser mints a key in **hardware-backed, non-extractable storage**, and
no script on the page can ever read or call it. Registering a session therefore
requires **no client code at all**: sending `Secure-Session-Registration` is the
whole handshake.

That is the guarantee, stated precisely: an attacker who steals the session cookie
cannot produce a refresh signature, and the browser cannot be made to produce one
for them. Three properties of the implementation carry it.

**A session's key is the session's key.** The key is stored once per `sessionId`
(`DeviceKey` has no other identity — re-registering replaces it), and registration
is refused outright with `SESSION_ALREADY_REGISTERED` when a key is already
present. There is no second, weaker key type and no path by which a
script-readable credential can stand in for a hardware one.

**Demotion on a failed refresh is the theft response.** A refresh whose signature
fails consumes the challenge, moves the session to `tier: none`, and emits
`session_stolen` — and the key is deliberately **kept**, because it is what makes
the next failure recognisable as a replay. The stored tier is therefore
authoritative: a key sets the *ceiling* a session can reach, not whether it is
currently protected. `dbsc.tierFor(sessionId)` reports `dbsc` only while the
session is actually trustworthy.

**The tier model has two values, not three.** `dbsc` means a hardware-backed key
is registered; `none` means nothing is bound, or a refresh signature failed. There
is no intermediate or weaker tier, and a stored value the library does not
recognise reads as `none` rather than being trusted.

**The credential cookie is worth one refresh window.** The session id never travels in a
cookie at all: `session_identifier` carries the id itself (spec §9.6) but names no cookie,
so the id exists only server-side and a lifted cookie jar contains no long-lived
credential. The one cookie that does travel is `__Host-auth_cookie`, named in
`credentials[]`, and its value is replaced on every successful refresh. A copy of it
therefore goes stale within one refresh rather than staying valid for the session's
lifetime. The one tunable is `dbsc.rotation-grace`, the window in which a retired
credential still resolves so a second tab does not break — and that window is itself
exposure. See [Credential rotation](#credential-rotation).

**The session is confined to the hosts and pages you name.** `scope.include_site`,
`scope.scope_specification` and `allowed_refresh_initiators` are instructions to the
browser, not checks this server performs: they decide where the credential is attached
and which out-of-scope callers may trigger a refresh. By default an out-of-scope
cross-origin fetch to a protected URL blocks on the refresh request, and the delay alone
reveals whether the user is logged in (spec §3.2) — so the initiator list is a security
control, not a convenience. See [Session scope](#session-scope).

### What the library does not do

Two things are easy to assume from the name, and both are false here:

- **It does not verify a per-request proof.** DBSC has none to verify: the browser
  signs only when it registers and when it refreshes, and that signature never
  leaves the browser's own protocol flow. What the library gives you is
  **freshness** — a session whose browser has stopped proving possession gets
  demoted — so the decision available to you is "is this session's tier currently
  `dbsc`?", not "did this request carry a valid proof?".
- **It does not authenticate, and it does not replace your authorization.** The
  guard refuses a request whose session is not currently DBSC-protected; it does
  not admit anyone, and it must not be the only thing in front of a route. Every
  route you guard still needs your own authentication, and DBSC's refusal is a
  step-up prompt rather than proof of who the caller is.

DBSC is **additive**: adopting the library never silently changes the behaviour of
an existing endpoint, because nothing is guarded until you declare `DbscGuardRoutes`,
and even then a client that never registered is allowed through unless you opt into
`dbsc.unregistered: deny`.

## Requirements

The library is compiled at the **Java 17** release level, so its class files load on
JDK 17 and every later JDK — 17, 21 and 25 all work. Java 17 is the lowest JDK Spring
Boot 3.5 supports, and it is the CI baseline.

Spring Boot 3.x.x, 4.x.x are the tested versions.

## Getting Started

### 1. Add the dependency

```xml
<dependency>
  <groupId>click.yukio.dbsc</groupId>
  <artifactId>spring-dbsc</artifactId>
  <version>0.6.0</version>
</dependency>
```

That is the whole installation. A normal Boot app picks up `DbscAutoConfiguration`
from the JAR's `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`
— no extra annotation.

### 2. Wire the DBSC filters into your chain

The library ships **two `OncePerRequestFilter` beans and no `SecurityFilterChain`** —
they are *not* wired into Security for you, and are not auto-registered as servlet
filters either, so a JAR that is merely on the classpath does nothing until you add
them. Nothing is registered into Spring Security for you, because *where* the filters
sit, which paths bypass authentication, and what authorization runs elsewhere in the
chain are policy decisions that belong to your application. A library-supplied chain
would either collide with yours (two chains matching `/**` is a hard startup error) or,
worse, be kept and silently replace your authorization rules.

Two beans arrive from `DbscFilterConfiguration`:

| Bean | Serves | Goes in |
|---|---|---|
| `dbscFilter` | the protocol routes (`/dbsc/**`, the well-known document) | its own protocol chain, unauthenticated |
| `dbscGuardFilter` | nothing by default — the routes you declare | your application chain, next to your authorization |

Put them where their subjects live:

```java
@Configuration
@EnableWebSecurity
public class MySecurityConfig {

    /** Protocol routes: driven by the browser, before any session exists. */
    @Bean
    @Order(0)
    public SecurityFilterChain dbscProtocolChain(HttpSecurity http, DbscFilter dbscFilter)
            throws Exception {
        http
                .securityMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/dbsc/**"),
                        new AntPathRequestMatcher("/.well-known/device-bound-sessions")))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(CsrfConfigurer::disable)
                // CsrfFilter, not UsernamePasswordAuthenticationFilter: a filter placed
                // relative to the latter still runs after CSRF, which would reject the
                // browser's registration POST (it carries no CSRF token) before DBSC
                // ever sees it.
                .addFilterBefore(dbscFilter, CsrfFilter.class);
        return http.build();
    }

    /** Your application, under your own authentication and authorization. */
    @Bean
    @Order(1)
    public SecurityFilterChain appChain(HttpSecurity http, DbscGuardFilter dbscGuardFilter)
            throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/css/**").permitAll()
                        .requestMatchers("/api/transfer").authenticated())
                // The guard, after authentication: it answers "is this session
                // currently DBSC-protected?", which is a question about a session
                // that must already exist.
                .addFilterBefore(dbscGuardFilter, CsrfFilter.class);
        return http.build();
    }

    /**
     * The requests whose session must currently be DBSC-protected. Patterns are
     * ordinary Spring Security matchers, so /api/** means what it means anywhere
     * else. Declaring no bean leaves the guard a no-op.
     */
    @Bean
    public DbscGuardRoutes dbscGuardRoutes() {
        return DbscGuardRoutes.of(new AntPathRequestMatcher("/api/**"));
    }
}
```

The three details that actually matter, and how each one fails:

| Detail | If you get it wrong |
|---|---|
| `OrRequestMatcher` for the protocol paths — `securityMatcher()` **sets**, it does not accumulate | Only the last path is matched; the rest fall through to your chain, which answers a Spring 403 before `DbscFilter` runs |
| `addFilterBefore(..., CsrfFilter.class)` **and** CSRF off on the protocol chain | The browser's registration POST carries no CSRF token, so a chain that applies CSRF to `/dbsc/**` rejects it before `DbscFilter` runs |
| Each bean is registered in **one** chain only | `OncePerRequestFilter` records itself in a request attribute, so the same instance in a second chain silently skips it |

**Declaring no `DbscGuardRoutes` guards nothing**, which is the default and the reason
adoption is safe. Note that a wide matcher is not the same as strict enforcement: a
client that never registered is allowed through either way unless you set
`dbsc.unregistered: deny`. That is what makes `/**`-sized coverage reasonable to
write — see [What the guard actually decides](#what-the-guard-actually-decides).

Skipping the guard entirely is also fine — see [Act on the tier](#act-on-the-tier) for
the inline form, which is the same check without a filter.

**Disable Boot's automatic servlet registration.** A `Filter` bean is picked up by the
servlet container as well as by the security chain, which would run each filter a
second time on every request:

```java
@Bean
FilterRegistrationBean<DbscFilter> dbscFilterRegistration(DbscFilter filter) {
    var registration = new FilterRegistrationBean<>(filter);
    registration.setEnabled(false);
    return registration;
}

@Bean
FilterRegistrationBean<DbscGuardFilter> dbscGuardFilterRegistration(DbscGuardFilter filter) {
    var registration = new FilterRegistrationBean<>(filter);
    registration.setEnabled(false);
    return registration;
}
```

Anchoring on `CsrfFilter.class` is not a dependency on CSRF being *enabled* — only on
it being **ordered**, which `HttpSecurity` guarantees whenever it is in the chain. It is
the earliest anchor that is still a Spring Security filter, which is what keeps DBSC's
`403` from being turned into a `401` by Security's entry point. The demo README
(`src/demo/resources/README-DEMO.md`) records what the other anchors cost.

### Examples

#### Form login (password)

Form login owns the POST that ends authentication, so the binding has to be made from
the success handler there too:

```java
@Bean
SecurityFilterChain appChain(HttpSecurity http, DbscService dbsc,
                             DbscFilter dbscFilter) throws Exception {
    http
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/login", "/css/**").permitAll()
                    .requestMatchers("/api/transfer").authenticated())
            .formLogin(form -> form
                    .loginPage("/login")
                    .successHandler((request, response, auth) -> {
                        // The DBSC session id is minted here, independent of the
                        // application's session id, which is passed as the second
                        // argument. Keep the value if you want to call terminate()
                        // by value; otherwise read it back with sessionFor(request)
                        // with sessionFor(request).
                        dbsc.bind(UUID.randomUUID().toString(),
                                  request.getSession().getId(), auth.getName(),
                                  86_400_000L, request, response);
                        response.sendRedirect("/");
                    }))
            .logout(logout -> logout.logoutSuccessHandler((request, response, auth) ->
                    dbsc.sessionFor(request)
                            .ifPresent(s -> dbsc.terminate(s.id(), request, response))))
            .addFilterBefore(dbscFilter, CsrfFilter.class);
    return http.build();
}
```

`src/demo` is a complete, runnable form-login app over HTTPS, and
`src/demo/resources/README-DEMO.md` records the failure modes it exists to catch.

#### OIDC / `oauth2Login()`

DBSC binds a session that already exists, so it composes with any authentication
mechanism — including OIDC, whose callback is cross-site. `bind()` names the session
with a single-use token in the registration URL rather than a cookie, so the
registration POST Chromium issues needs no session cookie and the cross-site initiator
does not matter. There is nothing extra to wire:

```java
@Configuration
@EnableWebSecurity
public class OidcSecurityConfig {

    @Bean
    SecurityFilterChain appChain(HttpSecurity http, DbscService dbsc,
                                 DbscFilter dbscFilter) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login/**", "/oauth2/**", "/error").permitAll()
                        .requestMatchers("/api/transfer").authenticated()
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2.successHandler((request, response, auth) -> {
                    // Force the session to exist: a login always has one, and the id is
                    // passed to bind() so the guard can tell a client that never
                    // registered apart from one that dropped its DBSC cookies.
                    String appSessionId = request.getSession().getId();
                    dbsc.bind(UUID.randomUUID().toString(), appSessionId,
                              auth.getName(), 86_400_000L, request, response);
                    response.sendRedirect("/");
                }))
                .addFilterBefore(dbscFilter, CsrfFilter.class);
        return http.build();
    }
}
```

Historically this did not work, and the reasoning is worth knowing because it explains
why the token is in the URL at all — see
[Binding behind OIDC or SAML](#binding-behind-oidc-or-saml-why-the-first-offer-fails).
`src/demo/java-oidc` is this example, runnable.

**The user id must not come from a mutable claim.** Whichever claim you read, do not
take it from `preferred_username` or `email`: the binding would change owner if the
address did. The OIDC `sub` claim is the stable choice — for `oauth2Login()` that
means setting `user-name-attribute: sub`, which is what `auth.getName()` then returns.

If your app has no `HttpSession`, pass whatever opaque id you already mint per client
for that session — `bind()` takes the application-session id as an argument and does
not care where it came from — rather than inventing one for this.

## Architecture

The protocol is served by **filters that your own Spring Security chain invokes**, not by
controllers:

| Component | Responsibility |
|---|---|
| `DbscFilter` | Owns every protocol route (`/dbsc/*`, `/.well-known/device-bound-sessions`). Terminates the chain for those paths; passes everything else through untouched. |
| `DbscGuardFilter` | Decides whether a request to a route the application declared may proceed, via `DbscService.guardDecision`. Refuses with `403` + `DBSC_REQUIRED`; passes everything else through untouched. |

`DbscService` sits below both as the HTTP facade, and `DbscProtocolEngine` below that as
the protocol itself — neither depends on Spring Security. See
[How it is wired (and why)](#how-it-is-wired-and-why) for the reasoning.

The two filters answer different questions and belong in different chains. `DbscFilter`
is about the browser's protocol flow, which runs before any session exists;
`DbscGuardFilter` is about your routes, which have one. Neither one inspects the other's
paths.

The guard is not a tier comparison, though the tier is most of it — the decision also
covers the session that dropped its DBSC cookies, which no tier check can see. See
[What the guard actually decides](#what-the-guard-actually-decides).

## Wiring it into your own app

### 1. Get the auto-configuration on the classpath

The library ships `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`,
so a normal Boot app picks up `DbscAutoConfiguration` with no extra annotation —
just depend on the JAR.

If you disable Boot's auto-configuration, or want the wiring visible, import it
explicitly:

```java
@SpringBootApplication
@Import(DbscAutoConfiguration.class)
public class MyApplication { ... }
```

The auto-configuration applies whenever the JAR is on the classpath. There is no
enable/disable switch on the library itself — the way to turn DBSC off is to take
the dependency out, since a half-installed filter chain that starts but does not
work is a worse failure mode than an absent one.

### 2. Bind a session from your login route

DBSC does not authenticate. It **binds a session that already exists**, so the call goes
at the end of your existing login handler — see
[The application API](#the-application-api) for what `bind()` does and why the call is
required: the id you pass is the DBSC session id, which you mint, and your application's
own session id goes alongside it so the guard can find the binding later:

```java
@PostMapping("/login")
public Session login(HttpServletRequest request, HttpServletResponse response) {
    Session session = authenticate(request);       // your own auth
    dbsc.bind(UUID.randomUUID().toString(), request.getSession().getId(),
              session.userId(), 86_400_000L, request, response);
    return session;
}
```

On logout, call `dbsc.terminate(...)` so the browser forgets the binding immediately
instead of retrying against a dead session. The record is **kept and marked revoked**, not
deleted: that is what lets a later request from the same session still be recognised as
"was bound" rather than treated as a first-time visitor:

```java
@PostMapping("/logout")
public void logout(HttpServletRequest request, HttpServletResponse response) {
    dbsc.sessionFor(request).ifPresent(s -> dbsc.terminate(s.id(), request, response));
    invalidateYourOwnSession(request);
}
```

### 3. Act on the tier

Your authorization does not change. DBSC is additional state your own code consults, and
nothing is guarded until you say so: declare `DbscGuardRoutes` and `dbscGuardFilter`
enforces the tier where it matches, or read the tier inline. Both forms are in
[Act on the tier](#act-on-the-tier).

## How it is wired (and why)

DBSC is implemented as **`OncePerRequestFilter`s** rather than controllers, and they run
inside the Spring Security chain because that is where your application decides what is
reachable:

```mermaid
flowchart TD
    A[Request] --> B{DBSC protocol paths?}
    B -- yes --> C[DbscFilter<br/>before CsrfFilter]
    C --> C2[terminates:<br/>writes status + headers + body]
    B -- no --> D[your authentication<br/>and authorization]
    D --> G{guarded route?}
    G -- yes --> H[DbscGuardFilter<br/>guardDecision]
    H -- allow --> F[your controller]
    G -- no --> F
```

Each branch is independent. The protocol paths are served and stop there; a guarded
route additionally has to pass the guard's decision; everything else is your
application's chain, unchanged. Gating a single endpoint inline is equally valid — see
[Act on the tier](#act-on-the-tier).

The reasons for filters rather than controllers:

- **These are a protocol surface, not endpoints.** The routes must be reachable
  before any application session exists, and must answer with DBSC's own status
  contract. A filter that terminates the chain enforces that structurally: the
  routes cannot be re-mapped, shadowed by a peer controller, or re-secured.
- **403 vs 401 is load-bearing, and only a filter can guarantee it.** Chromium
  treats a 401 on the refresh route as fatal and terminates the session, so DBSC
  must answer 403. If Spring Security handled these paths itself it would answer
  401 first. `DbscFilter` is registered *before* Spring Security's CSRF filter — the
  earliest anchor that is still a Security filter — so nothing upstream can reject the
  browser's registration POST or replace that status.
- **It owns no state the application needs to configure.** The filters are handed the
  protocol surface and the list of guarded paths, so they add no ordering constraints to
  your chain beyond the two above and no policy of its own over your routes.

### Using your own `SecurityFilterChain`

That is the only way to use the library — [Getting Started](#getting-started) is the
full worked example, and the two chains there are the shape to copy. The four details
worth restating here, because each one fails silently:

- **The protocol paths belong in a chain with CSRF disabled.** The browser's
  registration POST carries no CSRF token, so a chain that applies CSRF to `/dbsc/**`
  rejects it with `403` before `DbscFilter` ever runs — and the status looks like a
  DBSC refusal.
- **`dbscFilter` goes before `CsrfFilter`**, not merely before authentication.
  Anything `addFilterBefore` anchors on is still ordered *after* CSRF, so the
  registration POST would be rejected first.
- **`dbscGuardFilter` goes in the application chain, after authentication.** It asks
  whether an existing session is protected; running it before authentication would
  make it answer questions about a session that has not been established yet.
- **Each filter goes in exactly one chain.** `OncePerRequestFilter` records itself in a
  request attribute, so the same instance in a second chain is skipped without a word.

### Replace the collaborators you have opinions about

`DbscAutoConfiguration` backs off with `@ConditionalOnMissingBean` on every
bean, so defining your own replaces the default. The ones most worth replacing:

| Bean | Default | Replace when |
|---|---|---|
| `StorageAdapter` | JDBC when a `DataSource` is present, else in-memory | You already have a key/session store — implement the interface. The hard requirements are an **atomic** `consumeChallenge`, and `getSessionByAppSessionId` honouring the one-binding-per-application-session rule (the guard relies on it to spot an omitted cookie) |
| `RateLimiter` | In-memory, per-IP | You run more than one process (the in-memory limiter is per-JVM) — or you use a gateway/bucket you already have |
| `CookieScope` | Resolved from `secure` / `cookie-scope` / `cookie-domain` | You build cookie names or attributes yourself |
| `ChallengeService`, `DbscProtocolEngine`, `TelemetryPublisher` | Library defaults | You need different challenge or telemetry behaviour |
| `Clock` | `Clock.systemUTC()` | You need to freeze time. Override the bean **named `dbscClock`** (`@ConditionalOnMissingBean(name = "dbscClock")`) |

```java
@Bean
StorageAdapter dbscStorage(StringRedisTemplate redis) {
    return new RedisStorageAdapter(redis);   // consumeChallenge is atomic via Lua
}
```

`DbscService` itself is also `@ConditionalOnMissingBean`, but it is a plain
facade — wrapping or replacing it is rarely worth it.

## The application API

Three calls are the whole integration surface. The examples above show where they go;
this is what they do.

| Call | When |
|---|---|
| `dbsc.bind(sessionId, appSessionId, userId, ttlMillis, request, response)` | From an authenticated request, usually at the end of your login flow. `sessionId` is the **DBSC** session id, which you mint; `appSessionId` is your application's own session id |
| `dbsc.terminate(sessionId, request, response)` | On logout, so the browser forgets the binding instead of retrying against a dead session |
| `dbsc.sessionFor(request)` / `dbsc.tierFor(sessionId)` | Whenever your own code wants to know whether this browser is bound |
| `dbsc.guardDecision(request, appSessionId)` | When you want the guard's decision without the filter, e.g. to branch on *why* a request was refused |
| `DbscGuardRoutes.of(matchers…)` | To have the filter enforce the tier where the matchers apply |

**The two ids are different concepts and the library never conflates them.** `sessionId`
identifies the DBSC session and the stored device key; `appSessionId` identifies *your*
session, and it is only recorded so the guard can spot a request that dropped its DBSC
cookies. Nothing requires them to match, and nothing derives one from the other:

```
JSESSIONID=72234F6E…               your session   -> appSessionId
__Host-auth_cookie=0Jp36T8T…       the credential -> a rotating ticket
```

`session_identifier` is a different thing again: it is the DBSC session id, sent so
Chromium can key its own session store by it. It names no cookie, so the id stays out of
the cookie jar entirely, and the only cookie that travels is the credential one — named in
`credentials[]`, its value replaced on every refresh. See
[Credential rotation](#credential-rotation).

Mint the DBSC id however you like — a UUID is the obvious choice — and pass your own
session id alongside it. The id is never handed to the browser, so `sessionFor(request)`
is the way to read it back rather than any cookie value.

**`bind()` is the only thing that starts a binding.** It persists the session record,
mints a single-use registration token, sets the challenge and credential cookies, and adds
`Secure-Session-Registration` naming `/dbsc/regist/<token>`; Chromium then calls that
route on its own within about a second, with no client code to write. `DbscFilter` never
adds that header to your application's own responses, so a login flow that never calls
`bind()` produces no binding at all.

The call is cheap but not free — one challenge and two cookie writes — so a route that
binds on every request is fine, and keeping it off hot paths is better. It is **not**
idempotent: each call writes a record, and a second call under the same `sessionId`
replaces the first. That is deliberate, so a re-login can re-key an existing session.

### Act on the tier

Two ways to enforce it, and they check the same thing. **Declaring a matcher** hands the
decision to `DbscGuardFilter`, which refuses with `403` and `DBSC_REQUIRED` before your
handler runs. Patterns are ordinary Spring Security matchers, so the same
`/api/**` you would write in `authorizeHttpRequests` works here:

```java
@Bean
DbscGuardRoutes dbscGuardRoutes() {
    return DbscGuardRoutes.of(
            new AntPathRequestMatcher("/api/**"),
            new AntPathRequestMatcher("/account/**"));
}
```

Several matchers are OR-ed, and `DbscGuardRoutes` is itself a `RequestMatcher`, so it
composes with `AndRequestMatcher` and friends. A matcher is only the **range** — what
happens inside it is the policy below.

**Reading the tier inline** is for a route where a blanket refusal is the wrong answer —
where the response should differ, or where only part of the handler needs protection:

```java
@PostMapping("/api/transfer")
public ResponseEntity<?> transfer(@RequestBody Transfer body, HttpServletRequest request) {
    Optional<Session> session = dbsc.sessionFor(request);
    if (session.isEmpty() || dbsc.tierFor(session.get().id()) != ProtectionTier.DBSC) {
        // Signed in, but this browser is not proving possession of a bound key.
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(stepUpOrReauthenticate());
    }
    return transferService.execute(body);
}
```

#### What the guard actually decides

The tier check above is necessary but not sufficient, because "tier is `none`" covers two
situations that must be answered differently:

| Situation | Decision |
|---|---|
| Registered, currently proving possession | allow |
| Registered once, then demoted (or revoked) | **refuse** |
| Bound, but the record is gone | **refuse** — it was bound and is not any more |
| `bind()` ran, registration has not completed yet | allow (or refuse under `dbsc.unregistered: deny`) |
| No DBSC cookie, and no binding for this application session | allow (or refuse under `dbsc.unregistered: deny`) |
| No DBSC cookie, but a binding exists for this application session | **refuse** |

The two rows marked `dbsc.unregistered` are the one **policy** choice in the table, and
they are what `DbscService.Unregistered` in `DbscProperties` controls:

| `dbsc.unregistered` | Meaning |
|---|---|
| `allow` (default) | DBSC is an **additional layer**. A browser without support for the protocol, and a client that has logged in but not yet registered, both reach the application. A session that bound and then lapsed is still refused. |
| `deny` | DBSC is a **requirement**. Any client that has not registered is refused with `403 DBSC_REQUIRED`, so browsers without support are locked out. Only appropriate when the client population is known to be capable. |

The distinction matters when choosing a matcher: under `allow` a matcher covering `/**`
does not lock anyone out, and still catches every lapsed session. Under `deny` the same
matcher is a hard requirement on every route.

`DbscGuardFilter` therefore delegates to `dbsc.guardDecision(request, appSessionId)`
rather than comparing tiers itself. Use the same call if you want to branch on the reason
(`GuardDecision.Reason` tells you which row above applied) instead of getting a flat
`403`.

The last two rows are the point. **Dropping the DBSC cookies is something the client
controls**, so "no cookie" must not be read as "no binding" — otherwise a stolen
`JSESSIONID` could regain unbound access just by not presenting the cookie it stole. That
is why `bind()` records your application's session id, and why the guard reads it:
without it, a first-time visitor and a client that deliberately omitted its cookies are
indistinguishable.

Both forms make the same decision, so these hold for either:

- **It is a step-up decision, not an authentication one.** A `dbsc` tier never
  substitutes for being authenticated; read it *in addition to* your own checks, as
  above. That is also why the guard lives in the application chain rather than the
  protocol one, and why its refusal is a `403` with `DBSC_REQUIRED` rather than a
  `401` — a `401` reads as signed out, and Chromium treats one on the refresh route
  as fatal.
- **The tier is the live answer, not the value on the record.** It accounts for the
  refresh cadence and the grace window, so a session whose browser has stopped
  refreshing reads `none` — which is the demotion you are actually trying to surface.
  A session with a perfectly good registered key reads `none` too, once it has
  lapsed.
- **An unregistered client is allowed through, by design.** A browser without DBSC
  support (or a user who has just logged in, before registration completes) is
  legitimately unbound. This is what lets one application serve both populations:
  DBSC-capable clients get the binding enforced, everyone else runs on the plain
  session as before. Deciding that a browser which *cannot* do DBSC is refused is a
  policy choice the library deliberately does not make for you.

If your application cannot act on a weaker tier — for example a compliance rule that
says a stolen cookie must never be usable — say so explicitly rather than assuming the
handshake alone covers it: the protocol routes and `bind()` are what the library does,
and it is the guard or a check like the block above that turns a bound session into an
enforced one.

### Riding alongside your own session

The two extensions above are not in the DBSC spec, and they are what make the library a
*fallback* layer rather than an either/or choice — one application can serve
DBSC-capable browsers and ordinary ones at the same time.

**Your session cookie is used in parallel, not replaced.** The DBSC session id and your
application's session id are bound together at `bind()`, and the guard can therefore
answer a question the protocol itself cannot: was *this* session ever bound? Because the
application session id is treated as an opaque string rather than as a container-managed
value, this composes with Spring Session as well as with a plain `HttpSession`.

| Present on the request | Binding exists for the app session? | Decision |
|---|---|---|
| DBSC credential cookie | — | the credential decides; tier and revocation are read from it |
| none | yes | **refused** — the client dropped its DBSC cookies |
| none | no | unregistered: allowed, or refused under `dbsc.unregistered: deny` |

The middle row is the one worth reading twice. "No DBSC cookie" cannot be read as "no
binding", because *omitting* a cookie is something the client controls: otherwise a
stolen `JSESSIONID` would regain plain-cookie access simply by not presenting the
credential cookie. At most one binding per application session id is enforced, so this
lookup has a single answer rather than a picking problem.

The application's session id reaches the guard from `request.getSession(false)` —
deliberately the servlet session rather than the authenticated principal, since it must
be the same value the login route passed to `bind()`. A request with no session has no id
to look up and reads as unregistered. Call `dbsc.guardDecision(request, appSessionId)`
directly if you resolve that id some other way.

## Configuration

All keys are prefixed `dbsc`. Defaults match the toolkit spec.

| Key | Default | Notes |
|---|---|---|
| `secure` | `true` | `__Host-` cookies + `Secure`. **Turn off only for localhost HTTP** |
| `unregistered` | `allow` | What the guard does with a client that has no DBSC binding: `allow` (additive) or `deny` (required) |
| `cookie-scope` | `host` | `site` enables multi-subdomain and requires `cookie-domain` |
| `cookie-domain` | — | e.g. `example.com`; required for `site` scope |
| `registration-path` | `/dbsc/regist` | **prefix** for the registration route, not a full path: the advertised route is `<prefix>/<token>` |
| `refresh-path` | `/dbsc/refresh` | also the `refresh_url` in the JSON config |
| `session-identifier-name` | — | **removed.** `session_identifier` carries the session id itself (spec §9.6), so there was no name left to configure. Setting it now has no effect |
| `credential-cookie-name` | `__Host-auth_cookie` | the protected cookie named in `credentials[].name`, whose value rotates. Used verbatim — a prefix is your choice |
| `binding-cookie-ttl` | `10m` | lifetime of the credential cookie, and the window after which an unrefreshed session demotes. Also the refresh cadence the browser settles into |
| `registration-cookie-ttl` | `24h` | lifetime of the single-use registration token. The token is consumed by a successful registration; this is only the ceiling for one that never completes |
| `challenge-ttl` | `5m` | lifetime of a challenge JTI |
| `refresh-grace` | `30s` | softens the freshness poll across a refresh |
| `rotation-grace` | `60s` | how long a retired credential cookie value keeps resolving. Rotation itself is not optional — see [Credential rotation](#credential-rotation) |
| `session-ttl` | `7d` | default lifetime applied by `bind()` when the caller does not set one |
| `scope-origin` | *derived from the request* | pins `scope.origin`. Set only when the derived value is wrong — a proxy rewriting the host to an internal name. Validated at startup; a wrong value makes Chromium discard the session while the server still answers 200 |
| `scope-specifications` | `[]` | rules written into `scope.scope_specification`. See [Session scope](#session-scope) |
| `allowed-refresh-initiators` | `[]` | hosts outside the scope that may still trigger a refresh. Empty means none — see [Session scope](#session-scope) |
| `rate-limit.enabled` | `true` | |
| `rate-limit.capacity` | `30` | per IP, per window |
| `rate-limit.failure-capacity` | `15` | **failed** attempts per IP, per window — trips long before `capacity` does |
| `rate-limit.window` | `1m` | |
| `storage` | `jdbc` when a `DataSource` is present | `memory` for tests and local dev only; `redis` for a host already running Redis/Valkey with no `DataSource` |
| `trust-forwarded-headers` | `false` | believe `X-Forwarded-For` / `X-Forwarded-Proto`. Leave off unless a reverse proxy is known to overwrite them — they drive the IP used for rate limiting |

### Credential rotation

One cookie is in play, and this is the important part to get right:

| Cookie | Its name appears in | Its value | Set by this library? |
|---|---|---|---|
| `__Host-auth_cookie` | `credentials[].name` | a credential ticket | **yes** — replaced on every successful refresh |

Per spec §9.6 `session_identifier` is "the identifier for the newly created session" —
the session id **itself**, not the name of a cookie holding it. Chromium keys its session
store by this value (§8.1 Identify session) and echoes it back in `Sec-Secure-Session-Id`
on every refresh (§9.4), so the server resolves the session by exactly this string. It is
therefore whatever you passed to `bind()`, and it never changes for the life of the
binding — rotating it would orphan the registration.

The id is still **not a cookie**: nothing is read from or written to a cookie of that
name, and `credentials[]` names a different cookie entirely. So there is no long-lived
value in the cookie jar to lift, and the refresh path needs no cookie to agree with.

The `dbsc.session-identifier-name` property is **gone**, not deprecated: it now has no
reader. It dated from an earlier reading of §9.6 in which this field held a fixed key
name; that was wrong, and the field is the id. A configuration file that still sets it
will not fail to start — Spring ignores unknown keys — so remove it yourself.

Every successful refresh mints a new credential ticket and hands it back in the
`Set-Cookie` of the `credentials[]` cookie. This is not optional: that cookie can be
copied, and a copy is only ever worth as little as the value's remaining life. Making it a
setting would mean the safe behaviour is the one you have to know to ask for.

The one tunable is the grace:

```yaml
dbsc:
  rotation-grace: 60s
```

**What it does not do.** It does **not** make the session proof-free, and it does not
invalidate a key. A refresh *is* the browser's proof of possession, so whoever holds the
cookie and the device still refreshes successfully — the server cannot tell a stolen
cookie from the real browser. What rotation buys is narrower and worth stating plainly: a
captured credential cookie stops resolving `rotation-grace` after the real browser's next
refresh, instead of staying valid for the session's whole lifetime. What stops a stolen
*key* is `terminate()` and the demote-on-failure path, and neither is a substitute for
treating a leaked binding as everything it is worth.

**How the grace works, and why it has to exist.** The browser only learns the new ticket
from the refresh *response*, so any request already in flight — a second tab, a retry, a
slow proxy — still carries the old one. For `grace`, the retired ticket keeps resolving to
the same session. Without that, a second tab's refresh would be refused, and Chromium
records a refresh failure as permanent and will not retry, which would silently kill DBSC
for the whole browser.

The grace is the exposure. It is the window in which a stolen credential still works, so
set it to the longest gap between refresh attempts you need to survive, not to a round
number:

| `grace` | Behaviour |
|---|---|
| short (a few seconds) | Less exposure, but a slow tab or an idle one that wakes up late gets refused and has to re-register |
| `60s` (default) | Survives a normal multi-tab refresh race |
| long (minutes) | The rotation buys much less than it costs — the retired ticket outlives the reason to retire it |

A retired ticket used *within* the grace is answered normally and rotated again, so a
lagging tab cannot pin the old value — each successful refresh moves the credential
forward while the session id stays put.

**Cost.** One extra record write and one expired-row sweep per refresh, plus a row (or a
key) per retired ticket held for the grace. Rotation happens only after the signature
verifies, so an unauthenticated request can never retire anything: minting the new value
first would be a denial-of-service primitive that needs no key at all.

### Session scope

Three keys tell the browser where the session applies and who may make it refresh. All
three are **advisory**: the user agent enforces them, and this server never consults them
when handling a request. That means a mistake here does not produce a server-side error —
it produces a browser that quietly applies the session somewhere you did not intend.

```yaml
dbsc:
  cookie-scope: site
  cookie-domain: example.com

  # Which URLs are in scope: walked in REVERSE, first match wins.
  scope-specifications:
    - type: exclude
      domain: "*.example.com"
      path: /static
    - type: include
      domain: trusted.example.com
      path: /only_trusted_path

  # Hosts OUTSIDE the scope that may still trigger a refresh.
  allowed-refresh-initiators:
    - example.com
    - "*.example.com"
```

**`include_site` is set by `cookie-scope`, not by its own key.** `host` (the default)
means the origin only; `site` means the whole registrable domain. Scope is decided in the
same place the cookie is, so the credential and the scope can never disagree. Note that
`include_site: true` takes precedence over every rule in `scope_specification` (§8.2):
the domain check happens first, so an `exclude` rule cannot narrow a site-scoped session
back to a single host.

**`scope_specification` rules are applied in reverse.** §8.2 walks the list from last to
first and stops at the first match, which makes the natural spelling outermost-first: put
the broad `exclude` first and the narrower `include` after it, as above. Order is
preserved exactly as written for this reason; re-ordering the array inverts the meaning.

Each rule has three keys, all of which are written out even when you omit them:

| Key | Default when omitted | Meaning |
|---|---|---|
| `type` | — (required) | `include` adds the match to the scope, `exclude` removes it |
| `domain` | `*` | `*` matches every host; `*.example.com` matches subdomains but **not** `example.com` itself; a bare host matches only itself |
| `path` | `/` | Matches when the URL path is exactly this, starts with it followed by `/`, or — when the pattern ends in `/` — starts with it |

**`allowed_refresh_initiators` closes a timing side channel.** By default an out-of-scope
request can trigger a refresh, and the refresh is slow: the browser has to reach the
hardware key before it can continue. A cross-origin page that fetches a protected endpoint
therefore learns whether the user is logged in from the delay alone, with no error and no
response body. Listing the embedding or calling hosts here confines that to the ones you
chose; every other initiator gets no refresh, so there is nothing to time. In-scope
requests are always allowed (§8.3), so the list concerns out-of-scope callers only.

Both lists default to empty, which means "the whole origin (or site)" and "no out-of-scope
initiator" respectively. Both are also the spec's own defaults — an empty
`allowed_refresh_initiators` is what a browser assumes when the key is absent.

**Pinning `scope.origin`.** `scope.origin` is normally derived from the request, which is
the only value that can be right for every deployment. Set `dbsc.scope-origin` only when
that derivation is known to be wrong:

```yaml
dbsc:
  scope-origin: https://example.com:8443
```

Prefer `trust-forwarded-headers: true` where that applies: it stays correct if the public
name changes, whereas a pinned origin has to be updated by hand. The value must be an
absolute origin with no path (`https://example.com`, not `https://example.com/app`), and
it is validated at startup — because on the wire a mismatch is invisible. §8.9 requires
`origin` to be same-site with the destination and terminates the session on a mismatch,
and it does so **in the browser**: the server still answers 200 and logs nothing, while
the session silently fails to exist. Failing the context start is the only way that
mistake is ever visible.

### Storage

Three stores, chosen by `dbsc.storage`. The property decides, never the classpath: an
application that happens to have both a `DataSource` and a Redis client is never in
doubt about which one DBSC uses.

| Value | Store | Use when |
|---|---|---|
| `jdbc` | `JdbcStorageAdapter`, on your `DataSource` | Default. Your state already lives in a database |
| `redis` | `RedisStorageAdapter`, on `StringRedisTemplate` | You already run Redis, Valkey, KeyDB, Dragonfly or ElastiCache and have no `DataSource` |
| `memory` | `InMemoryStorageAdapter` | Tests and local dev. **Not for production** — every restart breaks live sessions, because the browser still holds a cookie for a key the server no longer remembers |

```yaml
dbsc:
  storage: jdbc          # or: redis, memory
  secure: true
  cookie-scope: site
  cookie-domain: example.com
```

With a `DataSource` on the classpath, sessions, keys and challenges all live in the
database (`dbsc.storage: jdbc`).

Every store has to satisfy the same two hard requirements, which are worth restating
because both are easy to get wrong in a way that only shows up as a security bug:

- `consumeChallenge` and `consumeRegistrationToken` must be **atomic**. Two concurrent
  refresh attempts on one challenge MUST yield exactly one `true`; a read followed by a
  separate write lets an attacker race a captured proof against the legitimate client
  and have both accepted.
- `getSessionByAppSessionId` must honour **one binding per application session id**.
  The guard relies on it to tell a browser that never registered from one that
  registered and then dropped its cookies.

#### Redis (and Valkey)

The adapter talks to anything speaking RESP, so Valkey needs no separate adapter — the
protocol is the same, and so are the commands it uses.

**Why it exists.** Sessions, device keys, challenges and registration tokens are all
small values with an expiry, which is what a Redis-compatible server is good at. If you
already run one and have no database, this is the durable store that does not make you
add one. The property is what decides, never the classpath: an app with both a
`DataSource` and a Redis client is never in doubt about which DBSC uses.

**The dependency is optional.** `spring-data-redis` and `lettuce-core` are declared
`<optional>`, so a host that stores DBSC state in its database does not inherit a Redis
client. A host that sets `dbsc.storage: redis` needs both on the classpath *and*
`spring.data.redis.*` configured; without a `StringRedisTemplate` the context fails at
startup with a message naming the property, rather than at class-load time somewhere
unrelated.

**Keys are not namespaced by tenant.** All keys are prefixed `dbsc:`, so two
applications sharing one server (or one database index) would share sessions. Give each
its own server or its own database index. The key layout is:

| Key | Type | TTL |
|---|---|---|
| `dbsc:session:<id>` | hash | the session's own retention deadline |
| `dbsc:app-session:<appSessionId>` | string | the session's own retention deadline |
| `dbsc:device-key:<sessionId>` | hash | the session's deadline, or 24h when orphaned |
| `dbsc:challenge:<jti>` | hash | the challenge's expiry **+ 1h** |
| `dbsc:registration-token:<token>` | hash | the token's expiry **+ 1h** |
| `dbsc:credential-ticket:<ticket>` | string | the rotation grace, no longer |

The `+ 1h` on challenges and registration tokens is deliberate: the record has to outlive
its stated expiry, or a client presenting a JTI that lapsed a moment ago would get
`CHALLENGE_NOT_FOUND` where the protocol says `CHALLENGE_EXPIRED`. After that hour the
two answers are equivalent and the key is reclaimed.

Every consume is one Lua script, evaluated server-side:

```lua
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if redis.call('HGET', KEYS[1], 'consumed') == '1' then return 0 end
redis.call('HSET', KEYS[1], 'consumed', '1')
return 1
```

Lua runs to completion without interleaving, so the check and the write are one step and
exactly one concurrent caller can observe `1`. A read-then-write would be a replay
vulnerability: an attacker could race a captured proof against the legitimate client and
have both accepted.

**That atomicity is not covered by the test suite, and cannot be.** `RedisStorageAdapterTest`
runs against a mocked `StringRedisTemplate`, and a stub is happy to accept three
concurrent `consumeChallenge` calls that a real server would resolve to one — it would pass
just as well against the read-then-write implementation the script exists to avoid. The
test pins the surrounding work instead: key layout, field encoding, TTLs, and the direction
of the script's `1`/`0` reply. The concurrency guarantee rests on the script above being
correct, which is why it is quoted here in full rather than described.

#### Schema

The tables are created on startup by `JdbcStorageAdapter.initialize()`, which issues
`CREATE TABLE IF NOT EXISTS` and is safe to run on every boot. A fresh database needs
no setup.

That default is convenient, but in production the schema should be owned by a migration
tool (Flyway, Liquibase, or whatever the application already uses), for two reasons:

- The runtime database user otherwise needs **DDL rights**, which many production
  setups deliberately withhold.
- Schema changes then get reviewed, versioned and rolled out like every other change,
  instead of silently appearing on the first boot of a new release.

The DDL is shipped for exactly that, at
[`src/main/resources/db/migration/V1__dbsc_storage.sql`](./src/main/resources/db/migration/V1__dbsc_storage.sql):

| Table | Contents |
|---|---|
| `dbsc_sessions` | one row per bound session (`id` PK, `app_session_id`, `user_id`, `tier`, `revoked`, timestamps). `app_session_id` is uniquely indexed, so there is at most one binding per application session |
| `dbsc_device_keys` | the registered hardware key it holds — `session_id` PK, so **one key per session** |
| `dbsc_challenges` | outstanding JTIs, with the `consumed` flag that makes consumption atomic |
| `dbsc_credential_tickets` | tickets that still resolve to a session, with their expiry. Written by [credential rotation](#credential-rotation); a row is dropped when it is read after its expiry |

The `dbsc_sessions` table references the DBSC session id (`id`) and your application's
session id (`app_session_id`) as two independent columns — see
[The application API](#the-application-api). Only `id` is a foreign key target;
`app_session_id` exists solely to answer "is there a binding for this application
session?" when a request arrives without DBSC cookies.

> **Upgrading from a build before 0.6.0:** `dbsc_sessions` gained `app_session_id`
> (`NOT NULL`) and `revoked` (`BOOLEAN NOT NULL`), plus a unique index on
> `app_session_id`. `CREATE TABLE IF NOT EXISTS` will **not** add them to an existing
> table — it silently skips it, and the app then fails at runtime on the missing column.
> Apply an `ALTER TABLE` before deploying:
>
> ```sql
> ALTER TABLE dbsc_sessions ADD COLUMN app_session_id VARCHAR(255);
> ALTER TABLE dbsc_sessions ADD COLUMN revoked BOOLEAN NOT NULL DEFAULT false;
> UPDATE dbsc_sessions SET app_session_id = id WHERE app_session_id IS NULL;
> ALTER TABLE dbsc_sessions ALTER COLUMN app_session_id SET NOT NULL;
>
> > CREATE UNIQUE INDEX dbsc_sessions_app_session_idx ON dbsc_sessions (app_session_id);
> ```
>
> The same release added a new table, `dbsc_registration_tokens`, which holds the
> single-use registration tokens. `CREATE TABLE IF NOT EXISTS` creates it on its own, so
> no manual step is needed for it — but note that `__Host-dbsc-reg` no longer exists, so
> any code or test of yours referencing that cookie name must be updated.
>
> Existing rows are backfilled with their own DBSC id as the application session id,
> which is a safe placeholder: it preserves the "a binding exists" answer for those
> sessions and can never collide, since `id` is already unique. Those sessions will be
> refused once by the guard and recover on the next login, which re-binds them with the
> real application session id.
>
> The release that added [credential rotation](#credential-rotation) replaced
> `dbsc_session_aliases` with `dbsc_credential_tickets`. `CREATE TABLE IF NOT EXISTS`
> creates the new table on its own, so an upgrade needs no manual step — but the old
> table is neither migrated nor dropped, and is left as dead weight. It held only
> retired session ids from a scheme that no longer exists, so dropping it is safe and
> loses nothing:
>
> ```sql
> DROP TABLE IF EXISTS dbsc_session_aliases;
> ```
>
> The same release settled the cookie layout on a single cookie. `credentials[].name`
> names `__Host-auth_cookie`, whose value is a rotating ticket. `session_identifier` is
> unrelated to it: it carries the DBSC session id itself (spec §9.6), names no cookie, and
> so keeps the id out of the cookie jar. A browser holding a binding from an older build
> re-registers on its own; there is nothing to change on the server side.

The file is a plain `CREATE TABLE IF NOT EXISTS` migration: drop it into your
migration tool's directory, or run its statements however you already run schema
changes. It is **byte-identical** to what `initialize()` issues and both are
idempotent, so there is no conflict either way — applying it and then starting the app
leaves the schema unchanged, and you can adopt it on an existing deployment without a
baseline step.

The SQL is deliberately portable — no vendor-specific types, no sequences — so it works
on PostgreSQL, MySQL, MariaDB, H2 and SQL Server. Timestamps are `BIGINT` epoch
milliseconds throughout, matching how the protocol carries them.

If you would rather not carry the migration at all, `initialize()` is also safe to call
yourself from a schema-management hook — the DDL statements are quoted at the top of
`JdbcStorageAdapter`.

## Binding behind OIDC or SAML: why the first offer fails

This section explains why the registration token travels in the URL rather than in a
cookie. The failure it describes is real and worth understanding — it is what the design
solves — but with the current library there is nothing for you to do about it.

Cross-site is a problem for the registration POST however the session is identified in
a cookie, because Chromium withholds *all* of them from that POST:

```
GET  /login/oauth2/code/entraid   302   cookies set
POST /dbsc/regist/<token>         200   no cookie sent
```

That is why nothing on the registration path may depend on a cookie naming the
session, and it is worth knowing even though the library has already arranged it: if
you are reading a cookie of your own in a component that runs on that path, it will be
absent exactly when the login callback is what triggered the request.

### How the token in the path removes the problem

An earlier design named the session with a `__Host-dbsc-reg` cookie. Cross-site, that
cookie was withheld along with your own session cookie, so the registration route saw a
request with no session and answered `403` — and Chromium records that failure as
permanent and does not retry for the rest of that login, leaving the session at
`tier: none` no matter how long it lives.

`bind()` no longer sets that cookie. It mints a **single-use registration token** and
advertises the session's identity in the registration **URL**:

```
POST /dbsc/regist/1234-56789-01234-56789
```

The POST is resolvable from the path alone, so it does not matter that cookies were
withheld and the cross-site initiator stops being a problem. Binding in the
OIDC success handler — the obvious place — now works, with no relay hop and no
application-side workaround.

A server-side redirect does **not** reset the initiator: `302`/`303` to your own page
still leaves the callback as the initiator. Only a navigation the *browser* issues on
its own — a click, a page load, a script-driven location change — does. Nothing in this
library needs one any more; the note is here because it still governs what `bind()`
may rely on if you call it somewhere else.

Two consequences worth knowing:

- **The token is single-use**, consumed by a successful registration. A second
  registration on an already-registered session is an error
  (`SESSION_ALREADY_REGISTERED`) — that is the protocol, not a limitation.
- **`registration-path` is a prefix**, not a fixed path. The concrete route is
  `<prefix>/<token>`. Never build the header yourself; `bind()` does it, and
  `DbscService.registrationPathFor(token)` is the accessor if you need it.

The challenge cookie is unaffected and still required: it is how the server knows which
JTI was signed.

For form login none of this ever applied. Form login owns the POST the browser made to
your own origin, so the success handler *is* same-site and a single `bind()` there is
complete.

`bind()` is safe to call more than once: it costs one challenge plus two cookie writes
and a fresh token each time, and Chromium ignores the offer once the session has
registered. Each call writes its own session record, so a second call under the same id
replaces the first. Keep it off hot paths, and never call it from an unauthenticated
route — `bind()` trusts its arguments.

## Things worth knowing

A few behaviours are load-bearing and easy to get wrong if you reimplement or
extend this:

- **Never 401 on the refresh route.** Chromium ignores 401 there and the
  session silently dies. Every DBSC failure is 403, except a structurally incomplete
  request (400) and a tripped rate limit (429).
- **A failed refresh signature must consume the challenge and demote to
  `none`.** That demotion is the actual theft response, not a side effect.
- **`200` with no JSON body on a protocol route means opt-out**, and the browser
  drops the session. Always return the JSON config on success.
- **The `attributes` string in the JSON config must match the real
  `Set-Cookie` bytes**, so the browser's cookie matcher recognises it. It
  deliberately excludes `Max-Age`, which the spec's match set does not include.
- **`tier` is what makes a session protected, not the presence of a key.** A
  demoted session keeps its key on purpose (so a later failure is still recognisable
  as `session_stolen`), which is why `tierFor()` reads the stored tier rather than
  inferring protection from the key.
- **`scope_specification` is read in reverse by the browser**, so the array order you
  write is the precedence — last match wins. Sorting or de-duplicating the list would
  silently invert it.
- **Nothing on the server enforces scope.** `scope_specification` and
  `allowed_refresh_initiators` are instructions to the user agent; the server happily
  answers a refresh for a URL the browser should never have attached the credential to.
  Do not treat them as authorization.
- **A wrong `scope.origin` fails in the browser, not here.** §8.9 terminates the session
  on a same-site mismatch, so the server answers 200 while Chromium discards it. That is
  why `dbsc.scope-origin` is validated at startup instead of at first use.

## License

[MIT](./LICENSE).
