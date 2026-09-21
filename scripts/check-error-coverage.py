#!/usr/bin/env python3
"""Check that every DBSC error code reachable from the wire is exercised by the E2E suite.

Codes are read from DbscErrorCode.java so the list cannot drift. Two of them are
deliberately unreachable through the HTTP surface and are excluded explicitly;
if either ever becomes reachable, this script should be updated rather than the
check being silently relaxed.
"""
import re, sys

# Not reachable from the wire, so the E2E suite cannot and should not observe them:
#   KEY_NOT_FOUND_NATIVE is superseded on the HTTP path by SESSION_NOT_FOUND: a
#   session with no key is indistinguishable from a session that was never
#   registered, and reporting the difference would leak which sessions exist.
UNREACHABLE = {"KEY_NOT_FOUND_NATIVE"}

codes = []
for line in open("src/main/java/click/yukio/dbsc/core/DbscErrorCode.java"):
    m = re.match(r"\s{4}([A-Z][A-Z_]{4,}),\s*$", line)
    if m:
        codes.append(m.group(1))

e2e = open("scripts/e2e.py").read()
missing = [c for c in codes if c not in UNREACHABLE and c not in e2e]

print(f"defined:  {len(codes)}")
print(f"expected: {len(codes) - len(UNREACHABLE)}")
print(f"covered:  {len(codes) - len(UNREACHABLE) - len(missing)}")
if missing:
    print("MISSING: " + ", ".join(missing))
    sys.exit(1)
print("every reachable error code is exercised by the E2E suite")
