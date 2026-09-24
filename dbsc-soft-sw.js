// Soft DBSC, as a Service Worker.
//
// The specification describes a user agent doing this on its own (§5 and §6 of the
// DBSC draft):
//
//   * "The refresh endpoint is contacted every time a request is made with an
//     expired bound cookie, and its response blocks the original request."
//   * "If a session credential will expire soon, and an in-scope document is
//     active, the user agent can refresh proactively."
//
// A Service Worker is the only place a script can do the first of those, because it
// is the only place a script sees a request before it goes to the network. That is
// the whole reason this file exists: a timer can approximate the second trigger, but
// nothing else can observe the first, and the first is the one that keeps a session
// alive when a page is doing something other than sitting idle.
//
// It is deliberately thin. Everything protocol-shaped -- the key, the JWS, the
// refresh exchange, the IndexedDB record -- lives in dbsc-soft-client.js, loaded
// below and never duplicated. This file decides *when* to call it, and what to do
// about the request that asked.
//
// WHY A SERVICE WORKER AND NOT A SHARED WORKER. A SharedWorker cannot see a fetch.
// It can hold one timer for the origin, which covers the proactive trigger, but the
// reactive one -- the specification's primary mechanism -- is unreachable from there.
// Worse, it is unreachable on Safari, which does not implement SharedWorker at all
// and is one of the two browsers this fallback exists for. A Service Worker is
// supported everywhere this client runs, sees every request, and survives page
// navigations and tab closes, which a document-local timer does not.
//
// A CLASSIC WORKER, NOT A MODULE. `importScripts()` below loads the shared client,
// and that forces the choice: a classic worker cannot use `import`, and a module
// worker -- which could -- is not implemented in Safari, which is one of the two
// browsers this whole file exists for. Registering this file has to stay plain
// `register('/dbsc-soft-sw.js')`, with no `{ type: "module" }`.

// The shared client, loaded into this worker's own scope. It publishes itself as
// `self.DbscSoft` rather than as bare globals precisely because of what just happened
// here: `importScripts()` evaluates into the worker's scope, so a bare `refresh` from
// the client would collide with anything this file declares. Every call below is
// therefore qualified.
importScripts("/dbsc-soft-client.js");

/**
 * The deployment's `dbsc.binding-cookie-ttl`.
 *
 * There is nowhere to read this from. The JSON session config carries no cadence,
 * and a native browser learns it off the credential cookie's `Max-Age`, which is
 * HttpOnly and therefore invisible to a script. So it is configured here, and it has
 * to match the server. Too long is the failure to watch for: the cookie lapses
 * between refreshes, the tier drops to `none`, and every guarded route starts
 * refusing a client that looks otherwise healthy.
 *
 * EDIT THIS BY HAND when you deploy. This file is served verbatim -- there is no
 * build step and no template -- so the value below is what the browser runs. The
 * README's "Telling it how long the cookie lives" says the same thing at more
 * length.
 */
const BINDING_COOKIE_TTL_MS = 180_000;

/** How far ahead of the TTL to refresh. The exchange costs a round trip. */
const REFRESH_MARGIN_MS = 5_000;

/**
 * Paths worth refreshing ahead of, as a prefix test.
 *
 * AN ALLOWLIST, NOT A DENYLIST, and that is the security-relevant choice. The
 * question this answers is "could this request's outcome depend on the credential
 * cookie?", and only the application knows -- so the honest default for a route the
 * deployer has not thought about is "no", not "yes". A denylist gets that backwards:
 * anything not named is swept in, and the sweep is invisible.
 *
 * KEEP THIS IN STEP WITH THE ROUTES YOU GUARD. The cost of a route listed here that is
 * not guarded is a wasted refresh round trip on it; the cost of a guarded route missing
 * here is that its credential is never refreshed proactively and the route starts
 * refusing at the TTL. List what your isProtected rules cover.
 */
const PROTECTED_PREFIXES = ["/app/"];

/**
 * Request destinations that carry a session.
 *
 * `document` is a page load and `""` is a fetch/XHR (the spec leaves destination
 * empty for those). Everything else -- images, fonts, stylesheets, scripts -- is a
 * subresource whose response does not depend on the credential, and a page load pulls
 * in dozens of them at once. This is the check that keeps one navigation from
 * launching a refresh per asset.
 */
const SESSION_DESTINATIONS = new Set(["", "document"]);

/**
 * Requests worth refreshing ahead of.
 *
 * A refresh exists to keep a *session* usable, so only requests that carry it matter:
 * same-origin, a session-bearing destination, and a path the application has declared
 * protected. Anything else is passed straight through, untouched.
 */
function isSessionRequest(request) {
    if (request.method !== "GET" && request.method !== "POST") return false;

    // An absent destination is treated as session-bearing rather than skipped: the
    // property is missing on some synthetic requests, and a missing value is not
    // evidence of a subresource.
    if (request.destination && !SESSION_DESTINATIONS.has(request.destination)) return false;

    let url;
    try {
        url = new URL(request.url);
    } catch {
        return false;
    }
    if (url.origin !== self.location.origin) return false;

    return PROTECTED_PREFIXES.some(prefix => url.pathname.startsWith(prefix));
}

self.addEventListener("install", () => {
    // Take over as soon as possible: an unclaimed worker sees no requests, and the
    // point of this client is to see them.
    self.skipWaiting();
});

self.addEventListener("activate", event => {
    event.waitUntil(self.clients.claim());
});

/**
 * The specification's primary trigger: a request arrives, the binding is old, so
 * refresh before letting the request go.
 *
 * The refresh is awaited, and the original request is only issued afterwards. That
 * is what "its response blocks the original request" means, and it is the property
 * that makes the binding useful: the request that would otherwise have been refused
 * for a stale credential instead arrives with a fresh one.
 *
 * A failed refresh does not fail the request. The server is the authority on whether
 * the session is still good, and it is about to answer this very request; injecting
 * a synthetic error here would replace a real answer with a worse one, and would
 * break the routes that do not care about DBSC at all.
 */
self.addEventListener("fetch", event => {
    const request = event.request;
    if (!isSessionRequest(request)) return;

    event.respondWith((async () => {
        try {
            await self.DbscSoft.refreshIfStale({
                intervalMs: BINDING_COOKIE_TTL_MS,
                marginMs: REFRESH_MARGIN_MS
            });
        } catch {
            // refreshIfStale() already swallows its own failures; this is belt and
            // braces so that nothing here can turn into a network error.
        }
        return fetch(request);
    })());
});

// ------------------------------------------------------------------- the API
//
// What a page asks the worker to do. A page cannot call the protocol directly any
// more -- the cookies are HttpOnly, the worker owns the clock, and two contexts
// refreshing one binding is exactly the race the record is there to prevent -- so
// these messages are the interface.
//
// The CSRF token travels with the bind request rather than being fetched by the
// worker. The token is a secret the page was handed, it only ever reaches here
// through a postMessage, and the worker must not go and GET the app page to scrape
// one: it runs on every request, including those from pages that never loaded this
// client, and that would be a request the user did not make.

/**
 * Hands the CSRF token to the client module.
 *
 * Wrapped rather than called inline so the qualification is in one place: the module
 * is reached through `self.DbscSoft`, and a destructured `setCsrfToken` would collide
 * with this file's own scope the way every other name would.
 */
function setCsrfTokenFor(token, header) {
    self.DbscSoft.setCsrfToken(token, header);
}

self.addEventListener("message", event => {
    const data = event.data || {};
    const reply = event.ports && event.ports[0];
    const respond = payload => reply && reply.postMessage(payload);

    if (data.type === "refresh") {
        event.waitUntil(self.DbscSoft.refresh().then(
            ok => respond({ ok }),
            e => respond({ ok: false, error: String(e) })));
        return;
    }

    if (data.type === "state") {
        event.waitUntil(self.DbscSoft.getRecord().then(
            rec => respond({
                bound: Boolean(rec && rec.sessionId),
                sessionId: rec ? rec.sessionId : null,
                refreshedAt: rec ? rec.refreshedAt ?? null : null
            }),
            e => respond({ bound: false, error: String(e) })));
        return;
    }

    if (data.type === "bind") {
        // The page has authenticated and is telling the worker to establish a
        // binding. The token is passed in rather than read from a meta tag, because
        // there is no document here to read one from.
        //
        // bindSession() refuses on its own when this browser should register
        // natively, so nothing here has to ask -- but the answer is surfaced rather
        // than swallowed, so a page can tell "the browser is handling this" from
        // "we bound a software key".
        setCsrfTokenFor(data.csrfToken || null, data.csrfHeader || null);
        event.waitUntil(self.DbscSoft.bindSession().then(report => respond(report)));
    }
});
