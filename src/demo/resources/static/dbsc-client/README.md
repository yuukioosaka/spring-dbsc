# `dbsc-client/index.js` — provenance

This directory is the **browser client SDK** the `bound` (Web Crypto polyfill)
protocol is driven by. The server side in `src/main` implements only the
protocol; nothing in the library signs anything on the page's behalf, so a
browser needs this script for a `bound` session to exist at all.

## What these files are

| File | Origin |
|---|---|
| `index.js` | Bundle of `dbsc-toolkit/src/client/index.ts` |
| `LICENSE-dbsc-toolkit.txt` | Unmodified copy of the toolkit's license |

Upstream: <https://github.com/SulimanAbdulrazzaq/dbsc-toolkit> — **Apache License
2.0**, not the MIT license that covers the rest of this repository. The license
text is kept beside the bundle because the two differ; `LICENSE-dbsc-toolkit.txt`
is the one that governs `index.js`.

The bundle is **checked in on purpose.** The demo has to be runnable with
`mvn -Pdemo spring-boot:run` alone, and the toolkit is a TypeScript source tree
with no published browser bundle and no `node_modules`, so regenerating it at
build time would make a running demo depend on a Node toolchain and network
access. It is a demo asset, not part of the published JAR.

## How to regenerate it

The client imports nothing outside its own directory (`index.ts`, `wrapFetch.ts`,
`installFetchInterceptor.ts`, `keystore.ts`, `clockSync.ts`), so a plain esbuild
bundle with no plugins is enough:

```sh
# 1. Copy the client sources out of the toolkit.
mkdir -p /tmp/dbsc-client-build/src/client
cp dbsc-toolkit/src/client/*.ts /tmp/dbsc-client-build/src/client/
rm /tmp/dbsc-client-build/src/client/*.test.ts

# 2. Bundle. ESM, because the page loads it with <script type="module">.
cd /tmp/dbsc-client-build
npx esbuild src/client/index.ts \
    --bundle --format=esm --target=es2020 \
    --outfile=src/demo/resources/static/dbsc-client/index.js
```

The expected exports are exactly:

```
clearBoundKey, initBoundDbsc, installFetchInterceptor, stopBoundDbsc, wrapFetch
```

If a regeneration changes that list, the demo page's imports have to change with
it.

## Rebuilding after a toolkit upgrade

Re-copy, re-bundle, and check the **wire contract** the server has to satisfy —
these are the parts that break silently across a toolkit bump:

- `GET /dbsc-bound/state` must answer `200` with one of `unbound`,
  `needs-registration`, `needs-bound-registration` or `bound`, and the `bound`
  form must carry `sessionId`, `tier` and `refreshIntervalMs`.
- `POST /dbsc-bound/registration` takes `{publicKey, signature, challenge}`.
- `POST /dbsc-bound/refresh` takes `{challenge, signature, timestamp}`, where the
  signed message is `${challenge}.${timestamp}`.
- The per-request proof header is
  `X-Dbsc-Bound-Proof: ts=<ms>;sig=<b64url>[;bh=<b64url>]`, and the signed message
  is `${sessionId}.${METHOD}.${path}.${ts}[.${bodyHash}]`.

Those are asserted by `scripts/e2e.py`, which drives the routes directly rather
than through this bundle, so a toolkit change that alters them will show up there
even though the bundle itself is not executed by the suite.
