// Runs the demo's actual /dbsc-soft-client.js against a live demo, outside a
// browser. Node 20 has WebCrypto and fetch; only IndexedDB, a cookie jar and the
// `self` global are missing, and those are shimmed below.
//
// This is the strongest check available without a browser: the client under test is
// the shipped file, verbatim, and every signature it produces is verified by the
// real server. What remains untested is only DOM and worker plumbing.
//
//   node scripts/probe-script-client.mjs

// The demo serves a self-signed certificate. Setting NODE_TLS_REJECT_UNAUTHORIZED in a
// shell only reaches the process if it is exported, and the equivalent flag (--use-system-
// ca) is not available on every Node that runs this, so the opt-out is set in-process.
// It must happen before the first fetch, which is why it is not inside main().
if (process.env.DBSC_TLS_INSECURE === "1") {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

const BASE = process.env.DBSC_BASE ?? "https://localhost:8443";

// --- IndexedDB shim: enough for a single key/value store. In-memory is fine --
// the client only needs a record to survive between calls in one process.
const mem = new Map();

function fakeRequest(result) {
    const req = { result, onsuccess: null, onerror: null };
    queueMicrotask(() => req.onsuccess && req.onsuccess());
    return req;
}

globalThis.indexedDB = {
    open() {
        const req = { result: null, onupgradeneeded: null, onsuccess: null, onerror: null };
        const store = {
            put: (v, k) => { mem.set(k, v); return fakeRequest(undefined); },
            get: (k) => fakeRequest(mem.get(k)),
            delete: (k) => { mem.delete(k); return fakeRequest(undefined); }
        };
        const db = {
            objectStoreNames: { contains: () => true },
            createObjectStore() {},
            // Each transaction fires oncomplete on its own microtask, after the
            // request's onsuccess has had a chance to run. Firing it eagerly would
            // resolve reads before get()'s callback ran; never firing it would
            // deadlock every write, which is what an earlier version did.
            transaction() {
                const tx = { objectStore: () => store, oncomplete: null, onerror: null };
                queueMicrotask(() => queueMicrotask(() => tx.oncomplete && tx.oncomplete()));
                return tx;
            },
            close() {}
        };
        req.result = db;
        queueMicrotask(() => { req.onupgradeneeded && req.onupgradeneeded(); req.onsuccess && req.onsuccess(); });
        return req;
    }
};

// --- cookie jar, so the login session survives between fetches
const jar = new Map();

function cookieHeader() {
    return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

function absorb(res) {
    const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const line of raw) {
        const [pair] = line.split(";");
        const idx = pair.indexOf("=");
        if (idx > 0) jar.set(pair.slice(0, idx).trim(), pair.slice(idx + 1).trim());
    }
}

const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init = {}) => {
    const target = typeof url === "string" && url.startsWith("/") ? BASE + url : url;
    const headers = new Headers(init.headers || {});
    if (jar.size) headers.set("Cookie", cookieHeader());
    const res = await realFetch(target, { ...init, headers, redirect: "manual" });
    absorb(res);
    return res;
};

// The client is served from the demo; run the same bytes it serves.
//
// A CLASSIC SCRIPT, SO IT IS EVALUATED, NOT IMPORTED. `import` would be a syntax error
// on a file with no `export` (and `export` is what the client had to drop for Safari,
// which has no module workers -- see the header of dbsc-soft-sw.js). Evaluating it also
// puts the test closer to how it actually runs: the worker does `importScripts()`,
// which is an evaluation into a shared scope, not a module link. `self` is provided
// because that is where the client publishes itself, and a Service Worker's global is
// the same object.
const src = await (await realFetch(BASE + "/dbsc-soft-client.js")).text();

globalThis.self = globalThis;
// btoa/atob are not Node globals; the client needs btoa to base64url a signature.
if (typeof globalThis.btoa === "undefined") {
    globalThis.btoa = s => Buffer.from(s, "binary").toString("base64");
    globalThis.atob = s => Buffer.from(s, "base64").toString("binary");
}

// Evaluated as a classic script rather than a module: no `return` at top level, no
// import/export, and the last expression is not the value. `DbscSoft` appears on the
// global object it was evaluated against.
new Function(src)();
const dbsc = globalThis.DbscSoft;
if (!dbsc) throw new Error("the client did not publish self.DbscSoft");

// ---------------------------------------------------------------- assertions

const PASS = [];
const FAIL = [];
function check(name, ok, detail = "") {
    (ok ? PASS : FAIL).push(name);
    console.log(`[${ok ? "PASS" : "FAIL"}] ${name}` + (ok || !detail ? "" : `  -- ${detail}`));
}

// 0. expectsNativeDbsc(): the gate that decides whether this script stands down.
// A false positive would skip the registration this script exists for, so each
// branch is pinned. navigator is undefined in Node, so it is stubbed per case.
const sawNavigator = typeof globalThis.navigator !== "undefined";
function withUserAgentData(uad, fn) {
    const saved = globalThis.navigator;
    Object.defineProperty(globalThis, "navigator", { value: { userAgentData: uad }, configurable: true });
    try { return fn(); } finally {
        Object.defineProperty(globalThis, "navigator", { value: saved, configurable: true });
    }
}

check("no navigator.userAgentData (Firefox/Safari) -> not native",
    withUserAgentData(undefined, () => dbsc.expectsNativeDbsc() === false));
check("Chrome on Windows -> native",
    withUserAgentData({ brands: [{ brand: "Google Chrome", version: "145" }], platform: "Windows" },
        () => dbsc.expectsNativeDbsc() === true));
check("Chromium on Android -> NOT native (not shipped there yet)",
    withUserAgentData({ brands: [{ brand: "Chromium", version: "145" }], platform: "Android" },
        () => dbsc.expectsNativeDbsc() === false));
check("Edge on Windows -> native",
    withUserAgentData({ brands: [{ brand: "Microsoft Edge", version: "145" }], platform: "Windows" },
        () => dbsc.expectsNativeDbsc() === true));
check("Chrome on macOS -> not native (no hardware key facility)",
    withUserAgentData({ brands: [{ brand: "Chromium", version: "145" }], platform: "macOS" },
        () => dbsc.expectsNativeDbsc() === false));
check("a non-Chromium brand on Windows -> not native",
    withUserAgentData({ brands: [{ brand: "Firefox", version: "140" }], platform: "Windows" },
        () => dbsc.expectsNativeDbsc() === false));
check("no brands at all -> not native",
    withUserAgentData({ platform: "Windows" }, () => dbsc.expectsNativeDbsc() === false));

// 0b. The gate has to be *inside* bindSession(), not merely in one of its callers.
// Answering the predicate correctly is not the same as acting on it, and the Service
// Worker calls bindSession() directly: a check that only initDbsc() performed was
// skipped there, and Soft DBSC bound a software key on Chromium/Windows, where the
// native tier would have handled it. Pinning the predicate above did not catch that,
// so this drives the real entry point and asserts nothing went to the network.
{
    const uad = { brands: [{ brand: "Google Chrome", version: "146" }], platform: "Windows" };
    const saved = globalThis.navigator;
    Object.defineProperty(globalThis, "navigator", { value: { userAgentData: uad }, configurable: true });
    let attempts = 0;
    const realFetch = globalThis.fetch;
    globalThis.fetch = (...args) => { attempts++; return realFetch(...args); };
    let report;
    try {
        report = await dbsc.bindSession();
    } finally {
        globalThis.fetch = realFetch;
        Object.defineProperty(globalThis, "navigator", { value: saved, configurable: true });
    }
    check("bindSession() stands down on a native browser (Windows Chromium)",
        report.phase === "native", JSON.stringify(report));
    check("  ...and does not touch the network on the way", attempts === 0,
        `${attempts} fetch(es) attempted`);
}

// 1. Log in with form auth, so the demo's session cookie is in the jar.
const loginPage = await fetch("/login");
const html = await loginPage.text();
const csrf = /name="_csrf" value="([^"]+)"/.exec(html)?.[1] ?? "";
await fetch("/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ username: "demo", password: "demo", _csrf: csrf }).toString(),
    redirect: "manual"
});
check("the demo login establishes a session", jar.has("JSESSIONID"), [...jar.keys()].join(","));

// The CSRF token the bind route requires, as a browser would take it from the page.
// The module reads it from a meta tag, so rather than special-casing Node we give it a
// `document` that answers the same queries -- the code path under test stays the one
// that ships. Installing it here rather than from the start keeps the `expectsNativeDbsc`
// checks above honest about a page-less environment.
const appHtml = await (await fetch("/app")).text();
const csrfMeta = /name="csrf" content="([^"]+)"/.exec(appHtml)?.[1] ?? "";
const csrfHeaderMeta = /name="csrf-header" content="([^"]+)"/.exec(appHtml)?.[1] ?? "";

globalThis.document = {
    querySelector(selector) {
        const match = /^meta\[name="([^"]+)"\]$/.exec(selector);
        if (!match) return null;
        const values = { csrf: csrfMeta, "csrf-header": csrfHeaderMeta };
        const value = values[match[1]];
        return value ? { getAttribute: () => value } : null;
    }
};
check("the app page carries the CSRF meta the bind route needs", csrfMeta !== "",
    `csrf=${csrfMeta === "" ? "absent" : "present"}`);

// 2. The real bind exchange. With the Service Worker refactor the page no longer
// calls initDbsc() -- it registers the worker and asks it to bind -- so the probe
// drives the same exported function the worker does. That keeps the probe on the
// shipped path: dbsc-soft-sw.js contains no protocol logic of its own, only the
// decision of when to call this.
const report = await dbsc.bindSession();
check("bindSession() binds this client", report.phase === "registered", JSON.stringify(report));
check("and reports the session id it bound", typeof report.sessionId === "string",
    JSON.stringify(report));

// 2b. A second bindSession() must not double-register: the server refuses, and the
// client must report that rather than throwing.
const second = await dbsc.bindSession();
check("a second bindSession() reports already-bound rather than failing",
    second.phase === "already-bound", JSON.stringify(second));

// 3. The server must agree the session is now DBSC-protected.
const who = await (await fetch("/app/whoami")).json();
check("the server reports tier dbsc for the bound session", who.tier === "dbsc", JSON.stringify(who));
check("and the DBSC id matches what the client recorded", who.dbscSessionId === report.sessionId,
    `${who.dbscSessionId} vs ${report.sessionId}`);

// 4. The refresh path, driven directly so the timer is not involved. It takes no
// argument: the client reads the session id from its own record, never from a caller --
// a caller-supplied id would be a way to aim a refresh at someone else's session.
const refreshed = await dbsc.refresh();
check("refresh() succeeds against the live server", refreshed === true, "refresh returned false");

// 4b. The Service Worker's trigger: refreshIfStale() is what runs on every
// intercepted request, so it must be a no-op when the record is fresh -- otherwise
// every request in the page would cost a refresh round trip.
const fresh = await dbsc.refreshIfStale({ intervalMs: 180000, marginMs: 5000 });
check("refreshIfStale() is a no-op while the binding is fresh", fresh === false,
    "it refreshed a fresh record");

// 4c. And it must fire once the record is older than the TTL, which is the whole
// point of the fetch hook. A new binding is fresh by construction, so the probe
// ages the stored record -- the same shape refresh() itself writes, only with a
// `refreshedAt` in the past.
const rec = await dbsc.getRecord();
check("the client keeps a record of when the server last confirmed the binding",
    typeof rec.refreshedAt === "number", JSON.stringify(rec.refreshedAt));

// AGED THROUGH THE CLIENT, NOT THROUGH THE SHIM. Writing to __dbscTestStore
// directly was how this used to work, and it stopped being the same thing: the
// client caches the record in memory, so a write it did not make leaves that cache
// untouched and refreshIfStale() would still see a fresh record. The probe has to
// drive the path the client actually reads from, which is putRecord().
//
// The exported set is deliberately small, so the write goes through -- see below.
await dbsc.__probePutRecord({ ...rec, refreshedAt: 0 });
check("refreshIfStale() refreshes a record past its TTL",
    await dbsc.refreshIfStale({ intervalMs: 180000, marginMs: 5000 }) === true,
    "a record past its TTL was not refreshed");
check("and the record is restamped afterwards, so the next request is a no-op",
    await dbsc.refreshIfStale({ intervalMs: 180000, marginMs: 5000 }) === false,
    "the restamp did not take");

// 5. The guarded route: only a currently-DBSC session gets through.
const payment = await fetch("/app/payment", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-TOKEN": csrfMeta },
    body: JSON.stringify({ amount: 1000, currency: "usd" })
});
check("the guarded route admits the script-bound session", payment.status === 200,
    `${payment.status} ${await payment.text()}`);

// 6. A proof-less refresh must be refused, which is what makes the guard meaningful.
const noProof = await fetch("/dbsc/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Session-Id": report.sessionId },
    body: ""
});
check("a refresh with no proof is challenged, not accepted", noProof.status === 403,
    String(noProof.status));

console.log(`\n=== ${PASS.length} passed, ${FAIL.length} failed ===`);
if (FAIL.length) {
    console.log("failed: " + FAIL.join(", "));
}
// initDbsc() arms a refresh timer, which would keep Node's event loop alive forever.
// The probe drives bindSession() and refresh() directly instead, so nothing is armed --
// but exit explicitly anyway rather than depend on that staying true.
process.exit(FAIL.length ? 1 : 0);
