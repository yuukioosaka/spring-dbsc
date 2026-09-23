#!/usr/bin/env python3
"""Check that every DBSC error code reachable from the wire is exercised by the E2E suite.

Codes are read from DbscErrorCode.java so the list cannot drift. A few of them are
deliberately unreachable through the HTTP surface and are excluded explicitly; if any
ever becomes reachable, this script should be updated rather than the check being
silently relaxed.

A code counts as covered only when it appears inside a string literal that the suite
could be asserting on -- not merely somewhere in the file. Matching raw text meant an
incidental mention in a comment could satisfy the check for a code no scenario ever
produced, which is what this script exists to prevent.
"""
import re, sys

# Not reachable from the wire, so the E2E suite cannot and should not observe them:
#
#   KEY_NOT_FOUND is superseded on the HTTP path by SESSION_NOT_FOUND: a session with
#   no key is indistinguishable from a session that was never registered, and reporting
#   the difference would leak which sessions exist.
#
#   UNSUPPORTED_CLIENT is a corroboration that holds by construction once Spring
#   Security has accepted the session's token (see DbscService.requireAppSessionId).
#   Reaching it needs a session the container resolved whose id is not among the
#   request's cookie values, and a servlet container only ever resolves a session from
#   a cookie -- an id offered by a header is not adopted, and the request fails CSRF
#   first. Probing the live demo confirms it: POST /dbsc/bind answers 200 with the
#   caller's own cookie, 302 from the security entry point when no session resolves,
#   and a Spring Security 403 (body "Forbidden", no Cache-Control: no-store) on a CSRF
#   mismatch -- never a DBSC 403. MockMvc can inject a container session that no cookie
#   named, which is why ScriptClientTest.bindRouteRefusesASessionThatIsNotInACookie can
#   cover it and this suite cannot.
UNREACHABLE = {"KEY_NOT_FOUND", "UNSUPPORTED_CLIENT"}

# A code is covered by a quoted literal in the suite: 'CODE' or "CODE". Anchored on the
# quotes so a bare mention in prose or a comment does not count.
LITERAL = re.compile(r"""['"]([A-Z][A-Z_]{4,})['"]""")

codes = []
for line in open("src/main/java/click/yukio/dbsc/core/DbscErrorCode.java"):
    m = re.match(r"\s{4}([A-Z][A-Z_]{4,}),\s*$", line)
    if m:
        codes.append(m.group(1))

asserted = set(LITERAL.findall(open("scripts/e2e.py").read()))
missing = [c for c in codes if c not in UNREACHABLE and c not in asserted]

print(f"defined:  {len(codes)}")
print(f"expected: {len(codes) - len(UNREACHABLE)}")
print(f"covered:  {len(codes) - len(UNREACHABLE) - len(missing)}")
if missing:
    print("MISSING: " + ", ".join(missing))
    sys.exit(1)
print("every reachable error code is exercised by the E2E suite")
