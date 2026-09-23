// DBSC for browsers that do not implement it.
//
// Native DBSC (Chromium 145+) is driven by the browser: the server writes
// Secure-Session-Registration on a navigation response and the browser registers
// a hardware-backed key on its own. Firefox and Safari do none of that, so this
// script does the same work with Web Crypto and IndexedDB:
//
//   * the key is an ECDSA P-256 CryptoKey pair in IndexedDB, non-extractable
//   * registration signs { "jti": <challenge> } as a JWS with typ="dbsc+jwt"
//     and the public key in the "jwk" header parameter
//   * refresh signs the same shape, with NO "jwk" -- the server already has it
//   * the proof travels in the Secure-Session-Response *header*, never the body
//
// This file is the protocol implementation and nothing else. It is deliberately
// context-free: it works in a document, and it works in a Service Worker, where
// there is no `document`, no `window` and no page to render into. Who drives it is
// the caller's business -- see dbsc-soft-sw.js, which drives it from a fetch hook
// the way the specification describes a user agent doing it.
//
// A CLASSIC SCRIPT, NOT A MODULE. It exports through `self.DbscSoft` rather than
// `export`, and that is load-bearing rather than stylistic. A Service Worker can
// only import a module if it was registered with `{ type: "module" }`, and Safari --
// one of the two browsers this client exists for -- does not implement module
// workers at all. So a module here would be a client written for Safari that does
// not run on Safari. `importScripts()` in a classic worker works everywhere,
// including Safari, and it can only load classic scripts. Hence one shared scope and
// a namespace object at the bottom of the file; see `self.DbscSoft` there for what is
// public.
//
// WHAT THIS IS WORTH. The key lives where page script can reach it, so an XSS on
// this origin can ask it to sign. That is strictly weaker than the native tier,
// which is why the server reports these sessions differently. What it still buys
// is that a cookie stolen from another machine cannot be replayed: the thief does
// not have the private key. Treat it as an oracle, not a secret.

const DB_NAME = "dbsc-client";
const STORE = "keys";
const KEY_ID = "device-key";

/**
 * The server's routes. Mirrors dbsc.registration-path / refresh-path / bind-path.
 *
 * EDIT THIS BY HAND if your paths differ from the defaults -- like the worker's
 * BINDING_COOKIE_TTL_MS, this file is served verbatim and nothing rewrites it.
 */
const CONFIG = {
    bindPath: "/dbsc/bind",
    refreshPath: "/dbsc/refresh"
};

/**
 * The CSRF token the bind route needs, supplied by the caller.
 *
 * It cannot be read here. `POST /dbsc/bind` is a state-changing request on a route
 * the application authenticates, so a deployment that protects its routes with CSRF
 * refuses the offer without this -- and the 403 is indistinguishable from DBSC's own
 * refusals at the call site, which makes it a confusing failure to debug. The token
 * is a secret the page was handed, and the only place it exists is the page: in a
 * Service Worker there is no `document` to read a meta tag from, so it is passed in
 * (`setCsrfToken`) rather than discovered.
 *
 * Refresh is deliberately not covered: it is the browser's refresh route, driven by
 * the native protocol in a native browser, and this client keeps it protocol-shaped
 * by sending no CSRF token there. A deployment that applies CSRF to the refresh route
 * breaks the native flow too, so this is not a fallback-client gap.
 */
let csrf = { token: null, header: null };

/** Supplies the CSRF token, and the header name to send it in. */
function setCsrfToken(token, headerName) {
    csrf = { token: token || null, header: headerName || null };
}

/**
 * The CSRF token, falling back to the page's meta tag when there is a document.
 *
 * The fallback exists so a plain `<script type="module">` on a server-rendered page
 * needs no wiring -- the demo used to work that way. A worker has no document and
 * must call `setCsrfToken()`, so this returns null there and the route answers as it
 * would for any request without a token.
 *
 * Both spellings are read because there is no single convention. `_csrf` and
 * `_csrf_header` are what Thymeleaf's Spring Security dialect emits on its own;
 * `csrf` and `csrf-header` are what the demo writes explicitly.
 */
function metaContent(names) {
    if (typeof document === "undefined" || !document.querySelector) return null;
    for (const name of names) {
        const meta = document.querySelector('meta[name="' + name + '"]');
        const value = meta && meta.getAttribute("content");
        if (value) return value;
    }
    return null;
}

function csrfToken() {
    return csrf.token ?? metaContent(["_csrf", "csrf"]);
}

/** The header name the application expects the token in, or none. */
function csrfHeaderName() {
    return csrf.header ?? metaContent(["_csrf_header", "csrf-header"]);
}

// ---------------------------------------------------------------- IndexedDB
//
// Two caches stand between the callers and the database, and both matter because
// refreshIfStale() runs on every intercepted request:
//
//   * the CONNECTION is opened once and reused. Opening it per transaction meant an
//     open/close cycle for every freshness check, which is the cost this file used to
//     pay on every same-origin request.
//   * the RECORD is held in memory, so the common case -- "is this stale?" answered
//     "no" -- never touches IndexedDB at all. The record is small and single-keyed, so
//     there is nothing to page in, and this client is the only writer on the origin.
//
// Neither cache can go stale in a way that matters. A Service Worker is torn down when
// idle, which discards both; and on restart the first getRecord() reads through. The
// one live hazard is another context -- a second tab, or another worker generation --
// writing the record while this one holds a cached copy, so every write that does not
// go through putRecord()/clearRecord() here has to be treated as invisible. In practice
// nothing else writes it: refresh() is serialized behind the Web Lock below.

let dbPromise = null;
let recordCache;
let recordCached = false;

function openDb() {
    if (dbPromise) return dbPromise;

    dbPromise = new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, 1);
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(STORE)) {
                db.createObjectStore(STORE);
            }
        };
        req.onsuccess = () => {
            const db = req.result;
            // Another context is upgrading the database: close so it can proceed, and
            // drop the promise so the next call reopens at the new version. Without
            // this the worker would hold a connection that blocks the upgrade forever.
            db.onversionchange = () => {
                db.close();
                dbPromise = null;
                recordCached = false;
            };
            resolve(db);
        };
        req.onerror = () => {
            // Do not cache a failed open: the next caller should retry rather than
            // inherit this rejection for the worker's lifetime.
            dbPromise = null;
            reject(req.error);
        };
    });

    return dbPromise;
}

/**
 * Runs `work` in one transaction and resolves with the request's result, or null.
 *
 * The resolution point differs by mode, and it has to. A read is finished when its
 * request succeeds. A write is not: `put`/`delete` can report success and still be
 * rolled back if the transaction aborts afterwards, so writes resolve on `oncomplete`
 * and the request's own success is only used to carry a value out. Resolving a write
 * on the request would let refresh() cache a `refreshedAt` the database never kept.
 */
async function withStore(mode, work) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, mode);
        const req = work(tx.objectStore(STORE));
        const readOnly = mode === "readonly";

        if (readOnly && req) {
            req.onsuccess = () => resolve(req.result ?? null);
            req.onerror = () => reject(req.error);
            tx.onerror = () => reject(tx.error);
            tx.onabort = () => reject(tx.error);
            return;
        }

        tx.oncomplete = () => resolve(req ? (req.result ?? null) : null);
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
    });
}

async function putRecord(record) {
    await withStore("readwrite", store => {
        store.put(record, KEY_ID);
        return null;
    });
    // Cached only after the transaction committed, so a failed write cannot leave the
    // cache claiming something the database does not have.
    recordCache = record;
    recordCached = true;
}

async function getRecord() {
    if (recordCached) return recordCache;

    const record = await withStore("readonly", store => store.get(KEY_ID));
    recordCache = record;
    recordCached = true;
    return record;
}

async function clearRecord() {
    await withStore("readwrite", store => {
        store.delete(KEY_ID);
        return null;
    });
    recordCache = null;
    recordCached = true;
}

/**
 * Drops the in-memory record without touching the database.
 *
 * For the one case the cache cannot see on its own: another context is known to have
 * changed the record, so what is held here is of unknown age. The next getRecord()
 * reads through.
 */
function invalidateRecordCache() {
    recordCached = false;
    recordCache = undefined;
}

// ------------------------------------------------------------------- base64url

function base64url(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function utf8(str) {
    return new TextEncoder().encode(str);
}

// ------------------------------------------------------------------------ JWS

/**
 * The signature is raw r||s, which is what WebCrypto's ECDSA returns. Java's
 * Signature returns DER instead, so a signature made here must not be expected to
 * look like one made there -- the server converts.
 */
async function signJws(privateKey, payload, jwk, typ) {
    const header = { typ: typ, alg: "ES256" };
    if (jwk) header.jwk = jwk;

    const segments = base64url(utf8(JSON.stringify(header)))
        + "." + base64url(utf8(JSON.stringify(payload)));
    const sig = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" }, privateKey, utf8(segments));
    return segments + "." + base64url(new Uint8Array(sig));
}

// --------------------------------------------------------------- the protocol

/**
 * True when this browser is expected to implement DBSC natively, in which case
 * this script must stand down: the native key is hardware-backed and strictly
 * better, and a second registration against one session is exactly what the
 * server refuses. Registering a weak key where a strong one would have been used
 * is the failure this guards against, so it errs toward "not native".
 *
 * There is no standard feature-detection for DBSC, so this is a UA-CH test:
 * the Chromium family on Windows, the platform where native DBSC is actually
 * shipped. Android is deliberately excluded -- Chromium's Android
 * implementation is not available yet, so standing down there would skip the
 * registration this script exists for and leave the session unbound.
 * `navigator.userAgentData` is undefined in Firefox and Safari, which is the
 * first check and the one that matters most -- those are the browsers this whole
 * script exists for. User-agent strings are deliberately not used; UA-CH is the
 * supported, low-entropy channel.
 *
 * A false positive is worse than a false negative here: it would skip the
 * registration this script is for, and the native path would not pick it up on a
 * browser that does not really support it, leaving the session unbound with no
 * error. Hence the explicit platform list rather than a guess.
 */
function expectsNativeDbsc() {
    if (typeof navigator === "undefined" || !navigator.userAgentData) return false;

    const brands = navigator.userAgentData.brands || [];
    const isChromiumFamily = brands.some(b =>
        /Chromium|Google Chrome|Microsoft Edge/i.test(b.brand));
    if (!isChromiumFamily) return false;

    const platform = navigator.userAgentData.platform; // low-entropy, sync
    // Windows only: Chromium on Android does not implement DBSC yet, so a
    // worker there is doing real work, not pure overhead. Add it here once the
    // native path ships on that platform.
    return platform === "Windows";
}

/**
 * Reads the offer headers off a response.
 *
 * Both the current and the legacy name are read, because some Chromium builds
 * straddle the rename and the server emits both.
 */
function offerFrom(headers) {
    const reg = headers.get("Secure-Session-Registration")
        || headers.get("Sec-Session-Registration");
    const chal = headers.get("Secure-Session-Challenge")
        || headers.get("Sec-Session-Challenge");
    if (!reg) return null;
    return { registration: reg, challenge: chal, path: pathOf(reg), jti: jtiOf(reg) };
}

/** `<algo>;path="/dbsc/regist/<token>";challenge="<jti>"` -> the path. */
function pathOf(header) {
    const m = /path="([^"]+)"/.exec(header);
    return m ? m[1] : null;
}

/** The JTI the server wants signed, from the registration header's challenge param. */
function jtiOf(header) {
    const m = /challenge="([^"]+)"/.exec(header);
    return m ? m[1] : null;
}

/**
 * The first-leg refresh challenge: `"<jti>"` or `"<jti>";id="<sessionId>"`.
 * A bare sf-string, with no `challenge=` parameter -- unlike the registration offer.
 */
function challengeJti(header) {
    if (!header) return null;
    const m = /^"([^"]+)"/.exec(header.trim());
    return m ? m[1] : null;
}

/** Registers a fresh key against the session named by the offer. */
async function register(offer) {
    const pair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);

    // extractable=false above, and exportKey("jwk") on the *public* half only:
    // the private key never leaves the CryptoKey handle, so this script can sign
    // with it but cannot copy it out.
    const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    delete publicJwk.key_ops;
    delete publicJwk.ext;

    const jws = await signJws(pair.privateKey, { jti: offer.jti }, publicJwk, "dbsc+jwt");

    const res = await fetch(offer.path, {
        method: "POST",
        credentials: "same-origin",
        headers: {
            // The header, not the body: a POST without it is MISSING_RESPONSE_HEADER.
            "Secure-Session-Response": '"' + jws + '"',
            "Content-Type": "application/json"
        },
        body: ""
    });
    if (!res.ok) {
        throw new Error(`registration ${res.status}: ${await res.text()}`);
    }
    const config = await res.json();
    await putRecord({
        sessionId: config.session_identifier,
        privateKey: pair.privateKey,
        publicJwk: publicJwk,
        // When this binding was last established, in ms since the epoch. The
        // credential cookie's own Max-Age is the authority on when it expires, but
        // nothing exposes it here -- `document.cookie` cannot see an HttpOnly
        // cookie, and a Service Worker has no access to the cookie jar at all. So
        // the client keeps its own clock from the last exchange that the server
        // answered, and refreshes ahead of the TTL it was configured with.
        refreshedAt: Date.now()
    });
    return config;
}

/**
 * One refresh: leg 1 asks for a challenge, leg 2 presents the proof.
 *
 * `X-Session-Id` rather than `Sec-Secure-Session-Id`: the Sec- prefix is outside
 * the CORS safelist, so a fetch carrying it is preflighted and every deployment
 * would have to allow the name. Both are read by the server.
 *
 * The id sent is the one the server issued to this browser at registration and that
 * this client stored with its key. It is never taken from a URL, a form field, a
 * query parameter or anything else that could be pointed at someone else's session:
 * the header names which session to refresh, and the server trusts it, so a value a
 * caller could choose would be a way to refresh -- and thereby keep alive -- a
 * session that is not this browser's. The record is the only source, which is also
 * why the argument is not accepted from a caller.
 */
async function doRefresh() {
    const rec = await getRecord();
    if (!rec) return false;

    // The id comes from the record and from nowhere else. A second tab sharing the
    // record is the one case where the stored id can lag the server's, and refresh
    // is the account of it: a rejected id drops the record rather than being
    // overridden by anything the page supplies.
    const sessionId = rec.sessionId;
    if (!sessionId) return false;

    const leg1 = await fetch(CONFIG.refreshPath, {
        method: "POST",
        credentials: "same-origin",
        headers: {
            "Content-Type": "application/json",
            "X-Session-Id": sessionId
        },
        body: ""
    });

    // A 403 here is the challenge, not a failure: the first leg carries no proof,
    // so it is answered with one to sign. 401 would be fatal for a native browser
    // and this client treats it the same way.
    if (leg1.status === 401) return false;
    const jti = challengeJti(
        leg1.headers.get("Secure-Session-Challenge")
        || leg1.headers.get("Sec-Session-Challenge"));
    if (!jti) return false;

    // No jwk on a refresh: the server already holds the key, and spec 02 calls an
    // embedded jwk here a protocol error.
    const jws = await signJws(rec.privateKey, { jti: jti }, null, "dbsc+jwt");

    const leg2 = await fetch(CONFIG.refreshPath, {
        method: "POST",
        credentials: "same-origin",
        headers: {
            "Content-Type": "application/json",
            "X-Session-Id": sessionId,
            "Secure-Session-Response": '"' + jws + '"'
        },
        body: ""
    });
    if (!res2ok(leg2)) return false;

    const config = await leg2.json();
    // The session id does not move; the credential ticket does, and the response's
    // Set-Cookie already replaced it in the cookie jar. The id in the response is
    // written back rather than assumed unchanged: it is still the server that owns
    // the value, and this client mirrors it.
    //
    // `refreshedAt` is stamped only on success, and only here: it is the client's
    // record of when the server last confirmed this binding, which is what
    // refreshIfStale() schedules against.
    await putRecord({
        ...rec,
        sessionId: config.session_identifier || sessionId,
        refreshedAt: Date.now()
    });
    return true;
}

/** The lock name every context on this origin contends for. */
const REFRESH_LOCK_NAME = "dbsc-refresh";

/**
 * Refreshes, with at most one exchange in flight per origin.
 *
 * The protocol tolerates a second refresh -- the challenge is consumed atomically
 * server-side, so a duplicate loses the race and fails rather than corrupting
 * anything -- but it does not tolerate one for free: every duplicate is two wasted
 * round trips, and the loser also consumes the challenge the winner was about to
 * need. Ten subresources arriving together used to mean ten refreshes racing, nine of
 * which could only fail.
 *
 * `ifAvailable: true` is the important part, and it is a deliberate asymmetry against
 * the obvious implementation. Waiting for the lock would serialize every caller behind
 * one exchange, and each waiter would then run a refresh of its own for a record that
 * is already fresh -- the same duplicate work, just in a queue. Instead, a caller that
 * cannot take the lock immediately concludes that someone else is doing the work and
 * returns without touching the network.
 *
 * A browser without Web Locks (older Safari and Firefox) falls through to the
 * unguarded exchange, which is what this did before. That is safe rather than merely
 * tolerable: the server is the arbiter, and the worst case is the duplicate above.
 */
async function refresh() {
    if (typeof navigator === "undefined" || !navigator.locks) {
        return doRefresh();
    }

    return navigator.locks.request(REFRESH_LOCK_NAME, { ifAvailable: true }, async lock => {
        if (!lock) {
            // Someone else holds it. Their exchange will have stamped a fresh
            // `refreshedAt`, but that write may land after this call returns, so the
            // cached record is of unknown age and must be re-read next time.
            invalidateRecordCache();
            return false;
        }

        // Re-read inside the lock. The record may have been refreshed by another tab
        // between the caller's staleness check and this point, and the cache would
        // still be showing the pre-refresh value.
        invalidateRecordCache();
        return doRefresh();
    });
}

function res2ok(res) {
    return res.status === 200;
}

// ---------------------------------------------------------------- entry points

/**
 * The bind exchange: ask for an offer, register against it, and report the outcome.
 *
 * This is `initDbsc()` without the refresh schedule, because `initDbsc()` is a
 * document-shaped thing -- it starts a timer and expects a page to live long enough
 * to fire it. A Service Worker drives the same exchange and schedules nothing
 * itself: its trigger is the next request that arrives. Splitting the two keeps the
 * wire exchange in one place instead of forking a worker-specific copy of it.
 *
 * Order matters, and it is the whole reason this is one function:
 *
 *   1. If the server already has a device key for this session, this client has
 *      nothing to do -- it may be a second tab, or the native tier may have
 *      registered. Refused with SESSION_ALREADY_REGISTERED either way.
 *   2. Otherwise ask for an offer with POST /dbsc/bind. The session comes from the
 *      login cookie, so this only works when the user is authenticated, and it is
 *      why the route is not the same one a browser uses.
 *   3. Register.
 *
 * Returns a small report rather than throwing, so a caller has one shape to read
 * whichever way it went.
 */
async function bindSession() {
    // Standing down on a browser that should register natively is the FIRST thing
    // this does, and it lives here rather than in one of the callers on purpose.
    // There are two callers now -- this file's own initDbsc(), and the Service Worker
    // -- and a check that only one of them performed would leave the other binding a
    // weak software key to a session that was about to get a hardware-backed one.
    // That is exactly the bug this placement fixes: the worker called this function
    // directly and skipped the check, so Soft DBSC ran on Chromium/Windows, where the
    // native tier would have handled it.
    if (expectsNativeDbsc()) {
        return { phase: "native", detail: "this browser should register natively on its own" };
    }

    try {
        const bindHeaders = { "Content-Type": "application/json" };
        const token = csrfToken();
        if (token) bindHeaders[csrfHeaderName() || "X-CSRF-TOKEN"] = token;

        const offerRes = await fetch(CONFIG.bindPath, {
            method: "POST",
            credentials: "same-origin",
            headers: bindHeaders,
            body: ""
        });

        if (offerRes.status === 403) {
            const body = await offerRes.json().catch(() => ({}));
            if (body.error === "SESSION_NOT_FOUND") {
                // Not signed in, or the DBSC record is gone. Nothing to bind to.
                await clearRecord().catch(() => {});
                return { phase: "unbound", detail: body.message };
            }
            if (body.error === "SESSION_ALREADY_REGISTERED") {
                // A second tab, or the native tier got there first. There is already
                // a key on the server for this session, and this client does not
                // replace it -- one binding per session either way.
                return { phase: "already-bound", detail: body.message };
            }
            return { phase: "refused", detail: body.error || String(offerRes.status) };
        }
        if (!offerRes.ok) {
            return { phase: "error", detail: String(offerRes.status) };
        }

        // The offer is in the response headers, exactly as bind() writes it, so the
        // client parses one wire format whichever route offered it.
        const offer = offerFrom(offerRes.headers);
        if (!offer || !offer.path || !offer.jti) {
            return { phase: "error", detail: "the re-offer carried no registration header" };
        }

        const config = await register(offer);
        return { phase: "registered", sessionId: config.session_identifier };
    } catch (e) {
        return { phase: "error", detail: String(e) };
    }
}

/**
 * Binds this browser to its session, if that is possible and not already done, and
 * then keeps it alive with a timer.
 *
 * The timer is the document-shaped part and the reason a page might prefer
 * dbsc-soft-sw.js: it dies with the document, so a page nobody is looking at stops
 * refreshing. A Service Worker-driven client does the same work from a fetch hook
 * instead, and is the recommended shape -- this entry point remains for deployments
 * that cannot register a worker.
 *
 * @param options.refreshIntervalMs how often to refresh. The protocol response
 *        carries no such value -- native browsers learn the cadence from the
 *        credential cookie's own Max-Age -- so a script client has to be told it,
 *        and it must match `dbsc.binding-cookie-ttl` of the deployment it talks to.
 *        Defaults to 10m, which is the library's own default TTL.
 */
async function initDbsc(options = {}) {
    const refreshMarginMs = options.refreshMarginMs ?? 5000;
    const refreshIntervalMs = options.refreshIntervalMs ?? 10 * 60 * 1000;

    const report = await bindSession();

    // A second tab, or the native tier got there first: the useful thing is to resume
    // the schedule, but only if this client holds a key, which it will not in the
    // native case.
    if (report.phase === "already-bound") {
        const rec = await getRecord().catch(() => null);
        if (rec) scheduleRefresh(refreshIntervalMs, refreshMarginMs);
        return report;
    }

    if (report.phase === "registered") {
        scheduleRefresh(refreshIntervalMs, refreshMarginMs);
    }
    return report;
}

let timer = null;

/**
 * Refreshes only if the last confirmed exchange is old enough to be worth it.
 *
 * This is the spec's primary refresh trigger (§5: "contacted every time a request is
 * made with an expired bound cookie"), reduced to what a script can observe. A real
 * user agent reads the credential cookie's expiry off the response; a script client
 * cannot see an HttpOnly cookie, so it keeps its own clock -- `refreshedAt`, stamped
 * by the last successful exchange -- and treats `intervalMs` as the TTL it was told.
 *
 * A margin is subtracted so the refresh lands while the cookie is still valid: the
 * exchange costs a round trip, and the request that triggered it is waiting on it in
 * the Service Worker case, so firing exactly at the TTL would mean the browser has
 * already decided the cookie is stale.
 *
 * Returns true only when a refresh actually ran and succeeded. A client with no key,
 * or one whose binding was made recently enough, returns false without touching the
 * network -- which is the common case, since this runs on every intercepted request.
 *
 * The staleness test is repeated inside the refresh lock, because between the check
 * here and the exchange there is a window in which another tab can complete one. The
 * outer check stays because it is free (a cached record) and because it keeps a
 * fresh client from queueing on the lock at all.
 *
 * @param options.intervalMs the deployment's `dbsc.binding-cookie-ttl`, in ms
 * @param options.marginMs how far ahead of the TTL to fire; defaults to 5s
 * @param options.now injectable clock, for tests
 */
async function refreshIfStale(options = {}) {
    const intervalMs = options.intervalMs ?? 10 * 60 * 1000;
    const marginMs = options.marginMs ?? 5000;
    const now = options.now ?? Date.now();
    const threshold = Math.max(0, intervalMs - marginMs);

    const rec = await getRecord().catch(() => null);
    if (!rec || !rec.sessionId) return false;

    if (now - (rec.refreshedAt ?? 0) < threshold) return false;

    if (typeof navigator === "undefined" || !navigator.locks) {
        return doRefresh().catch(() => false);
    }

    return navigator.locks.request(REFRESH_LOCK_NAME, { ifAvailable: true }, async lock => {
        if (!lock) {
            // Another context is mid-exchange. It is about to stamp a fresh
            // `refreshedAt`, so treat the binding as being handled and let the request
            // that triggered this one proceed without another round trip.
            invalidateRecordCache();
            return false;
        }

        // Re-check under the lock: a tab that held it until a moment ago has already
        // refreshed this binding, and doing it again would only burn a challenge.
        invalidateRecordCache();
        const fresh = await getRecord().catch(() => null);
        if (!fresh || !fresh.sessionId) return false;
        if (Date.now() - (fresh.refreshedAt ?? 0) < threshold) return false;

        return doRefresh().catch(() => false);
    });
}

/**
 * Refreshes on the server's own interval, less a margin.
 *
 * Nothing does this for a script client: there is no browser-side scheduler to
 * rely on, so it is explicit here. Refresh before the credential cookie's TTL
 * elapses or the session demotes to tier `none` and guarded routes refuse it.
 */
function scheduleRefresh(intervalMs, marginMs = 5000) {
    if (timer !== null) clearTimeout(timer);
    const wait = Math.max(1000, intervalMs - marginMs);
    timer = setTimeout(async () => {
        const ok = await refresh().catch(() => false);
        if (ok) {
            scheduleRefresh(intervalMs, marginMs);
        } else {
            timer = null;
        }
    }, wait);
}

function stopDbsc() {
    if (timer !== null) {
        clearTimeout(timer);
        timer = null;
    }
}

/** Forgets the key, e.g. on logout. */
async function forgetDbsc() {
    stopDbsc();
    await clearRecord().catch(() => {});
}

// ------------------------------------------------------------------- the export
//
// One namespace object rather than a pile of globals, because this file and the
// worker share a single scope once `importScripts()` has run: an unqualified
// `refresh` would collide with anything else in that scope, and a deployment has no
// way to rename it.
//
// `self` rather than `window`: a Service Worker has no `window`, and `self` is the
// global object in both contexts. This is the only line in the file that has to know
// which one it is running in.
self.DbscSoft = {
    // Entry points a page or a worker drives directly.
    initDbsc,
    bindSession,
    refresh,
    refreshIfStale,
    scheduleRefresh,
    stopDbsc,
    forgetDbsc,
    setCsrfToken,

    // Lower-level pieces, exported because a test fixture or a custom client may
    // need them; nothing in this repository's own flows calls them from outside.
    register,
    getRecord,
    expectsNativeDbsc,

    // Test seam, and the only one in this file. The record is cached in memory, so a
    // probe cannot age it by writing to IndexedDB behind the client's back -- the
    // cache would not see the change and refreshIfStale() would still read a fresh
    // record. Reaching the store through putRecord() is the only way to age a record
    // the client will believe, and it is also the path a real writer takes.
    __probePutRecord: putRecord
};
