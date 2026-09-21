// src/client/keystore.ts
var DB_NAME = "dbsc-toolkit";
var STORE_NAME = "bound";
var KEY_RECORD_KEY = "key-record";
function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function getKeyRecord() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const req = tx.objectStore(STORE_NAME).get(KEY_RECORD_KEY);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}
async function setKeyRecord(rec) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).put(rec, KEY_RECORD_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
async function clearKeyRecord() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).delete(KEY_RECORD_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// src/client/clockSync.ts
async function recordServerTime(response) {
  const hdr = response.headers.get("X-Server-Time");
  if (!hdr) return;
  const serverTime = Number(hdr);
  if (!Number.isFinite(serverTime)) return;
  const rec = await getKeyRecord().catch(() => null);
  if (!rec) return;
  const offset = serverTime - Date.now();
  if (rec.clockOffsetMs === offset) return;
  await setKeyRecord({ ...rec, clockOffsetMs: offset });
}

// src/client/wrapFetch.ts
function wrapFetch(opts = {}) {
  const base = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const headerName = opts.headerName ?? "X-Dbsc-Bound-Proof";
  const signBody = opts.signBody ?? true;
  return (async (input, init = {}) => {
    const rec = await getKeyRecord().catch(() => null);
    if (!rec) return base(input, init);
    const url = new URL(
      typeof input === "string" || input instanceof URL ? input.toString() : input.url,
      typeof window !== "undefined" ? window.location.href : "http://localhost"
    );
    const method = (init.method ?? "GET").toUpperCase();
    const offset = rec.clockOffsetMs ?? 0;
    const ts = Date.now() + offset;
    let bodyHash = "";
    let finalBody = init.body;
    if (signBody) {
      const bodyBytes = init.body === void 0 || init.body === null ? new Uint8Array(0) : await readBodyBytes(init.body);
      if (bodyBytes.byteLength > 0) {
        finalBody = new Blob([bodyBytes]);
      }
      bodyHash = await sha256B64Url(bodyBytes);
    }
    const message = signBody ? `${rec.sessionId}.${method}.${url.pathname}.${ts}.${bodyHash}` : `${rec.sessionId}.${method}.${url.pathname}.${ts}`;
    const sigBytes = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      rec.keyPair.privateKey,
      new TextEncoder().encode(message)
    );
    const sig = base64url(new Uint8Array(sigBytes));
    const headers = new Headers(init.headers);
    const headerValue = signBody ? `ts=${ts};sig=${sig};bh=${bodyHash}` : `ts=${ts};sig=${sig}`;
    headers.set(headerName, headerValue);
    const nextInit = {
      ...init,
      headers,
      credentials: init.credentials ?? "include"
    };
    if (finalBody !== void 0 && finalBody !== null) {
      nextInit.body = finalBody;
    }
    return base(input, nextInit);
  });
}
async function readBodyBytes(body) {
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (body instanceof Blob) return new Uint8Array(await body.arrayBuffer());
  if (body instanceof FormData || body instanceof URLSearchParams) {
    return new TextEncoder().encode(body.toString());
  }
  if (body instanceof ReadableStream) {
    throw new Error("wrapFetch with signBody: ReadableStream body is not supported");
  }
  return new TextEncoder().encode(String(body));
}
async function sha256B64Url(bytes) {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const digest = await crypto.subtle.digest("SHA-256", copy);
  return base64url(new Uint8Array(digest));
}
function base64url(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

// src/client/installFetchInterceptor.ts
function installFetchInterceptor(opts) {
  if (!opts.pathPrefixes || opts.pathPrefixes.length === 0) {
    throw new Error("installFetchInterceptor: pathPrefixes must be a non-empty array");
  }
  for (const prefix of opts.pathPrefixes) {
    if (typeof prefix !== "string" || prefix.length === 0) {
      throw new Error("installFetchInterceptor: each prefix must be a non-empty string");
    }
    if (prefix === "/") {
      throw new Error(
        "installFetchInterceptor: pathPrefixes cannot include '/' \u2014 specify explicit route prefixes (e.g. '/api/secure/') to avoid signing static assets, health checks, or third-party requests"
      );
    }
    if (prefix.startsWith("http://") || prefix.startsWith("https://")) {
      throw new Error(
        "installFetchInterceptor: pathPrefixes must be path-only (e.g. '/api/secure/') \u2014 absolute URLs are not allowed; the interceptor never signs cross-origin requests"
      );
    }
    if (!prefix.startsWith("/")) {
      throw new Error(
        "installFetchInterceptor: each prefix must start with '/' (e.g. '/api/secure/')"
      );
    }
  }
  const upstreamFetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const priorGlobalFetch = globalThis.fetch;
  const signed = wrapFetch({
    fetch: upstreamFetch,
    ...opts.signBody !== void 0 && { signBody: opts.signBody },
    ...opts.headerName !== void 0 && { headerName: opts.headerName }
  });
  const interceptor = async (input, init) => {
    const url = resolveUrl(input);
    if (url && isSameOrigin(url) && matchesAnyPrefix(url.pathname, opts.pathPrefixes)) {
      return signed(input, init);
    }
    return upstreamFetch(input, init);
  };
  globalThis.fetch = interceptor;
  return () => {
    globalThis.fetch = priorGlobalFetch;
  };
}
function resolveUrl(input) {
  try {
    const raw = typeof input === "string" || input instanceof URL ? input.toString() : input.url;
    const base = typeof window !== "undefined" ? window.location.href : "http://localhost";
    return new URL(raw, base);
  } catch {
    return null;
  }
}
function isSameOrigin(url) {
  if (typeof window === "undefined") return true;
  return url.origin === window.location.origin;
}
function matchesAnyPrefix(pathname, prefixes) {
  for (const p of prefixes) {
    if (pathname.startsWith(p)) return true;
  }
  return false;
}

// src/client/index.ts
async function clearBoundKey() {
  await clearKeyRecord().catch(() => {
  });
  if (refreshTimer !== null) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  }
}
var DEFAULTS = {
  statePath: "/dbsc-bound/state",
  challengePath: "/dbsc-bound/challenge",
  registrationPath: "/dbsc-bound/registration",
  refreshPath: "/dbsc-bound/refresh",
  nativeProbeWindowMs: 5e3,
  refreshMarginMs: 5e3,
  pollIntervalMs: 1e3
};
var MIN_POLL_INTERVAL_MS = 250;
var refreshTimer = null;
async function initBoundDbsc(options = {}) {
  if (typeof window === "undefined" || typeof indexedDB === "undefined") {
    return { phase: "error", error: "window or indexedDB unavailable" };
  }
  const cfg = {
    statePath: options.statePath ?? DEFAULTS.statePath,
    challengePath: options.challengePath ?? DEFAULTS.challengePath,
    registrationPath: options.registrationPath ?? DEFAULTS.registrationPath,
    refreshPath: options.refreshPath ?? DEFAULTS.refreshPath,
    nativeProbeWindowMs: options.nativeProbeWindowMs ?? DEFAULTS.nativeProbeWindowMs,
    refreshMarginMs: options.refreshMarginMs ?? DEFAULTS.refreshMarginMs,
    pollIntervalMs: Math.max(MIN_POLL_INTERVAL_MS, options.pollIntervalMs ?? DEFAULTS.pollIntervalMs)
  };
  try {
    const state = await fetchState(cfg.statePath);
    if (state.phase === "unbound") {
      await clearKeyRecord().catch(() => {
      });
      return { phase: "unbound" };
    }
    if (state.phase === "bound") {
      if (state.tier === "dbsc") return { phase: "native-dbsc", tier: "dbsc" };
      const rec = await getKeyRecord().catch(() => null);
      if (!rec || rec.sessionId !== state.sessionId) {
        await clearKeyRecord().catch(() => {
        });
        const fresh = await fetchState(cfg.statePath);
        if (fresh.phase === "needs-registration") {
          await runRegistration(fresh.sessionId, fresh.challenge, cfg);
          scheduleRefresh(cfg, state.refreshIntervalMs);
          return outcomeFromSkip("polyfill-bound", fresh.nativeSkipped);
        }
        if (fresh.phase === "needs-bound-registration") {
          try {
            await runRegistration(fresh.sessionId, fresh.challenge, cfg);
          } catch {
            return { phase: "native-dbsc", tier: "dbsc", skipReason: "polyfill-co-registration-failed" };
          }
          return { phase: "native-dbsc", tier: "dbsc" };
        }
        if (fresh.phase === "bound" && fresh.tier === "dbsc") {
          return { phase: "native-dbsc", tier: "dbsc" };
        }
        return { phase: "polyfill-bound", tier: "bound" };
      }
      scheduleRefresh(cfg, state.refreshIntervalMs);
      return { phase: "polyfill-bound", tier: "bound" };
    }
    if (state.phase === "needs-bound-registration") {
      try {
        await runRegistration(state.sessionId, state.challenge, cfg);
      } catch {
        return { phase: "native-dbsc", tier: "dbsc", skipReason: "polyfill-co-registration-failed" };
      }
      return outcomeFromSkipNative(state.nativeSkipped);
    }
    if (state.nativeSkipped && state.nativeSkipped.length > 0) {
      await runRegistration(state.sessionId, state.challenge, cfg);
      const final2 = await fetchState(cfg.statePath);
      if (final2.phase === "bound") scheduleRefresh(cfg, final2.refreshIntervalMs);
      return { phase: "polyfill-bound", tier: "bound", skipReason: state.nativeSkipped[0] };
    }
    const deadline = Date.now() + cfg.nativeProbeWindowMs;
    let last = state;
    while (Date.now() < deadline) {
      await sleep(cfg.pollIntervalMs);
      const s = await fetchState(cfg.statePath);
      last = s;
      if (s.phase === "needs-bound-registration") {
        try {
          await runRegistration(s.sessionId, s.challenge, cfg);
        } catch {
          return { phase: "native-dbsc", tier: "dbsc", skipReason: "polyfill-co-registration-failed" };
        }
        return outcomeFromSkipNative(s.nativeSkipped);
      }
      if (s.phase === "bound" && s.tier === "dbsc") {
        return { phase: "native-dbsc", tier: "dbsc" };
      }
      if (s.phase === "bound" && s.tier === "bound") {
        scheduleRefresh(cfg, s.refreshIntervalMs);
        return { phase: "polyfill-bound", tier: "bound" };
      }
      if (s.phase === "needs-registration" && s.nativeSkipped && s.nativeSkipped.length > 0) {
        await runRegistration(s.sessionId, s.challenge, cfg);
        const finalState = await fetchState(cfg.statePath);
        if (finalState.phase === "bound") scheduleRefresh(cfg, finalState.refreshIntervalMs);
        return { phase: "polyfill-bound", tier: "bound", skipReason: s.nativeSkipped[0] };
      }
      if (s.phase === "unbound") {
        return { phase: "unbound" };
      }
    }
    if (last.phase === "needs-bound-registration") {
      try {
        await runRegistration(last.sessionId, last.challenge, cfg);
      } catch {
        return { phase: "native-dbsc", tier: "dbsc", skipReason: "polyfill-co-registration-failed" };
      }
      return outcomeFromSkipNative(last.nativeSkipped);
    }
    if (last.phase !== "needs-registration") {
      return { phase: "unbound" };
    }
    await runRegistration(last.sessionId, last.challenge, cfg);
    const final = await fetchState(cfg.statePath);
    if (final.phase === "bound") scheduleRefresh(cfg, final.refreshIntervalMs);
    return outcomeFromSkip("polyfill-bound", last.nativeSkipped);
  } catch (err) {
    return { phase: "error", error: err instanceof Error ? err.message : String(err) };
  }
}
function outcomeFromSkip(phase, skipped) {
  if (skipped && skipped.length > 0) {
    return { phase, tier: "bound", skipReason: skipped[0] };
  }
  return { phase, tier: "bound" };
}
function outcomeFromSkipNative(skipped) {
  if (skipped && skipped.length > 0) {
    return { phase: "native-dbsc", tier: "dbsc", skipReason: skipped[0] };
  }
  return { phase: "native-dbsc", tier: "dbsc" };
}
function stopBoundDbsc() {
  if (refreshTimer !== null) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  }
}
async function fetchState(path) {
  const r = await fetch(path, { credentials: "include" });
  await recordServerTime(r);
  return await r.json();
}
async function runRegistration(sessionId, challenge, cfg) {
  await clearKeyRecord().catch(() => {
  });
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"]
  );
  const publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const signature = await signMessage(keyPair.privateKey, challenge);
  const res = await fetch(cfg.registrationPath, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ publicKey, signature, challenge })
  });
  if (!res.ok) {
    throw new Error(`bound registration failed: ${res.status}`);
  }
  await setKeyRecord({ sessionId, keyPair });
  await recordServerTime(res);
}
async function runRefresh(cfg) {
  const rec = await getKeyRecord().catch(() => null);
  if (!rec) return false;
  const cRes = await fetch(cfg.challengePath, { credentials: "include" });
  if (!cRes.ok) return false;
  const { challenge } = await cRes.json();
  const timestamp = Date.now();
  const message = `${challenge}.${timestamp}`;
  const signature = await signMessage(rec.keyPair.privateKey, message);
  const res = await fetch(cfg.refreshPath, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challenge, signature, timestamp })
  });
  await recordServerTime(res);
  return res.ok;
}
function scheduleRefresh(cfg, intervalMs) {
  if (refreshTimer !== null) clearTimeout(refreshTimer);
  const wait = Math.max(1e3, intervalMs - cfg.refreshMarginMs);
  refreshTimer = setTimeout(async () => {
    const ok = await runRefresh(cfg).catch(() => false);
    if (ok) {
      scheduleRefresh(cfg, intervalMs);
    } else {
      refreshTimer = null;
    }
  }, wait);
}
async function signMessage(privateKey, message) {
  const data = new TextEncoder().encode(message);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, data);
  return base64urlEncode(new Uint8Array(sig));
}
function base64urlEncode(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
export {
  clearBoundKey,
  initBoundDbsc,
  installFetchInterceptor,
  stopBoundDbsc,
  wrapFetch
};
