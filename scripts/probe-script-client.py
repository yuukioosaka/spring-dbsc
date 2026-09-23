#!/usr/bin/env python3
"""Drives the fallback JS client's protocol from outside a browser.

The demo's /dbsc-client/index.js cannot be executed here (no JS runtime), so this
replays the exact wire exchange it performs, in the same order, against a live
demo. It is the server-side half of the proof: if this passes, the only thing left
unverified is the script's own WebCrypto/IndexedDB plumbing.

The exchange, as index.js performs it:

  1. POST /dbsc/bind               -> 200 + Secure-Session-Registration header
  2. POST <path from that header>  + Secure-Session-Response: "<jws>"  -> 200
  3. POST /dbsc/refresh            + X-Session-Id                       -> 403
  4. POST /dbsc/refresh            + X-Session-Id + proof               -> 200
  5. POST /app/payment (guarded)                                        -> 200

Usage:  python3 scripts/probe-script-client.py [base]
"""
import base64
import http.cookiejar
import json
import re
import ssl
import sys
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://localhost:8443"
USER, PASSWORD = "demo", "demo"

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail and not ok else ""))


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def new_client():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx), NoRedirect()), jar


def request(opener, method, path, body=None, headers=None, form=False):
    url = BASE + path
    data = None
    if body is not None:
        data = urllib.parse.urlencode(body).encode() if form else (
            body if isinstance(body, bytes) else json.dumps(body).encode())
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with opener.open(req) as r:
            return r.status, r.headers, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode("utf-8", "replace")


class Key:
    """An ES256 pair, signed the way WebCrypto does: raw r||s, not DER."""

    def __init__(self):
        self.priv = ec.generate_private_key(ec.SECP256R1())

    def public_jwk(self):
        n = self.priv.public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256",
                "x": b64u(n.x.to_bytes(32, "big")),
                "y": b64u(n.y.to_bytes(32, "big"))}

    def jws(self, payload: dict, include_jwk=True) -> str:
        header = {"typ": "dbsc+jwt", "alg": "ES256"}
        if include_jwk:
            header["jwk"] = self.public_jwk()
        seg = b64u(json.dumps(header, separators=(",", ":")).encode()) + "." \
            + b64u(json.dumps(payload, separators=(",", ":")).encode())
        der = self.priv.sign(seg.encode(), ec.ECDSA(hashes.SHA256()))
        # DER SEQUENCE( INTEGER r, INTEGER s ) -> raw r||s, which is the shape
        # WebCrypto returns and the server's verifier expects.
        assert der[0] == 0x30
        i = 2
        assert der[i] == 0x02
        r_len = der[i + 1]
        r = int.from_bytes(der[i + 2:i + 2 + r_len], "big")
        i = i + 2 + r_len
        assert der[i] == 0x02
        s_len = der[i + 1]
        s = int.from_bytes(der[i + 2:i + 2 + s_len], "big")
        return seg + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def path_of(header):
    m = re.search(r'path="([^"]+)"', header)
    return m.group(1) if m else None


def jti_of(header):
    m = re.search(r'challenge="([^"]+)"', header)
    return m.group(1) if m else None


def challenge_jti(header):
    """`"<jti>"` or `"<jti>";id="<id>"` -> the jti."""
    m = re.match(r'^"([^"]+)"', (header or "").strip())
    return m.group(1) if m else None


def login(opener):
    status, headers, html = request(opener, "GET", "/login")
    token = re.search(r'name="_csrf" value="([^"]+)"', html)
    request(opener, "POST", "/login",
            body={"username": USER, "password": PASSWORD, "_csrf": token.group(1) if token else ""},
            form=True)
    # The login 302s to /app, which is where the fallback client runs.
    status, headers, page = request(opener, "GET", "/app")
    return status, headers, page


def csrf_meta(page):
    """
    The token POST /dbsc/bind requires, as the page hands it to index.js.

    The bind route is an ordinary application route, so Spring Security's CsrfFilter
    protects it. A client that cannot read this meta tag cannot bind at all -- which is
    the intended shape: a caller without a page of ours has no business binding.
    """
    match = re.search(r'name="csrf" content="([^"]+)"', page or "")
    return match.group(1) if match else ""


def main():
    opener, jar = new_client()
    status, _, page = login(opener)
    check("the fallback client's page loads after form login", status == 200, f"got {status}")

    token = csrf_meta(page)
    check("the page carries the CSRF meta the bind route needs", token != "", repr(token[:16]))

    # --- step 1: the re-offer. index.js calls this first, unauthenticated callers
    # are refused, and the offer arrives as response headers.
    status, headers, text = request(opener, "POST", "/dbsc/bind",
                                    body=b"", headers={"Content-Type": "application/json",
                                                       "X-CSRF-TOKEN": token})
    check("step 1: POST /dbsc/bind -> 200", status == 200, f"got {status}: {text[:160]}")
    reg = headers.get("Secure-Session-Registration")
    check("step 1: the offer is a response header", reg is not None, str(reg))
    offer_path, offer_jti = path_of(reg or ""), jti_of(reg or "")
    check("step 1: it names a registration path and a challenge",
          bool(offer_path) and bool(offer_jti), f"{offer_path} / {offer_jti}")

    # --- step 2: register with a WebCrypto-shaped proof.
    key = Key()
    status, _, text = request(opener, "POST", offer_path, body=b"", headers={
        "Secure-Session-Response": '"' + key.jws({"jti": offer_jti}) + '"',
        "Content-Type": "application/json"})
    check("step 2: registration over the offered path -> 200", status == 200,
          f"got {status}: {text[:200]}")
    try:
        config = json.loads(text)
    except ValueError:
        config = {}
    session_id = config.get("session_identifier")
    check("step 2: the response carries the session config", bool(session_id), text[:200])

    # --- the app must now see the session as bound.
    status, _, who = request(opener, "GET", "/app/whoami")
    try:
        report = json.loads(who)
    except ValueError:
        report = {}
    check("the session reports tier dbsc after the fallback registers",
          report.get("tier") == "dbsc", str(report)[:200])
    check("and the DBSC id matches the one registration returned",
          report.get("dbscSessionId") == session_id, f"{report.get('dbscSessionId')} vs {session_id}")

    # --- step 3: the first refresh leg asks for a challenge. 403, never 401.
    status, headers, text = request(opener, "POST", "/dbsc/refresh", body=b"",
                                    headers={"Content-Type": "application/json",
                                             "X-Session-Id": session_id or ""})
    chal_header = headers.get("Secure-Session-Challenge")
    jti = challenge_jti(chal_header)
    check("step 3: a refresh naming the session with X-Session-Id -> 403 + challenge",
          status == 403 and jti is not None, f"got {status}: {text[:160]} / {chal_header}")
    check("step 3: and it is never the 401 that kills the session", status != 401)

    # --- step 4: the proof, with no jwk in its header.
    status, _, text = request(opener, "POST", "/dbsc/refresh", body=b"", headers={
        "Content-Type": "application/json",
        "X-Session-Id": session_id or "",
        "Secure-Session-Response": '"' + key.jws({"jti": jti}, include_jwk=False) + '"'})
    check("step 4: the proof over X-Session-Id -> 200", status == 200,
          f"got {status}: {text[:200]}")

    # --- step 5: the guarded route opens.
    #
    # The CSRF token rotates on authentication, so it has to be read from the page
    # as it is *now*, not from the login response: the value scraped before logging
    # in is already stale by the time the session exists.
    status, _, page = request(opener, "GET", "/app")
    token = re.search(r'name="csrf" content="([^"]+)"', page or "")
    status, _, text = request(opener, "POST", "/app/payment",
                              body={"amount": 1000, "currency": "usd"},
                              headers={"X-CSRF-TOKEN": token.group(1) if token else "x"})
    check("step 5: the guarded route admits the fallback-bound session",
          status == 200, f"got {status}: {text[:160]}")

    print(f"\n=== {len(PASS)} passed, {len(FAIL)} failed ===")
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
