import re, ssl, http.cookiejar, urllib.request, urllib.parse, sys

ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj),
                                 urllib.request.HTTPSHandler(context=ctx))
BASE = "https://localhost:8443"

def show(label, r):
    print(f"== {label}: {r.status}")
    for k, v in r.headers.items():
        if k.lower().startswith(("secure-session", "sec-session", "set-cookie")):
            print(f"   {k}: {v[:150]}")

html = op.open(BASE + "/login").read().decode()
tok = re.search(r'name="_csrf" value="([^"]+)"', html).group(1)

req = urllib.request.Request(BASE + "/login",
    data=urllib.parse.urlencode({"username": "demo", "password": "demo", "_csrf": tok}).encode())
try:
    r = op.open(req); show("POST /login", r); print("   body:", r.read().decode()[:120])
except urllib.error.HTTPError as e:
    show("POST /login", e); print("   body:", e.read().decode()[:200])

print("\n-- cookies after login --")
for c in cj:
    print("  ", c.name, "=", c.value[:40], "secure=", c.secure)

for path in ["/app", "/app/whoami"]:
    try:
        r = op.open(BASE + path)
        body = r.read().decode()
        print(f"\n== GET {path}: {r.status} ({len(body)} bytes)")
        if path.endswith("whoami"):
            print("  ", body)
        else:
            print("   has form:", "sign in" in body.lower() or "Signed in" in body)
    except urllib.error.HTTPError as e:
        print(f"\n== GET {path}: ERR {e.code}")
        print("  ", e.read().decode()[:200])

# the guarded route, with no proof
req = urllib.request.Request(BASE + "/app/payment",
    data=b'{"amount":1000,"currency":"usd"}',
    headers={"Content-Type": "application/json"}, method="POST")
try:
    r = op.open(req); print(f"\n== POST /app/payment (no proof): {r.status}"); print("  ", r.read().decode()[:200])
except urllib.error.HTTPError as e:
    print(f"\n== POST /app/payment (no proof): {e.code} (expected 403)"); print("  ", e.read().decode()[:200])
