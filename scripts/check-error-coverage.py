#!/usr/bin/env python3
"""Check that every DBSC error code is exercised by the E2E suite."""
import re, sys

codes = []
for line in open("src/main/java/click/yukio/dbsc/core/DbscErrorCode.java"):
    m = re.match(r"\s{4}([A-Z][A-Z_]{4,}),\s*$", line)
    if m:
        codes.append(m.group(1))

e2e = open("scripts/e2e.py").read()
missing = [c for c in codes if f'"{c}"' not in e2e and f"'{c}'" not in e2e]

print(f"defined: {len(codes)}")
print(f"covered: {len(codes) - len(missing)}")
if missing:
    print("MISSING: " + ", ".join(missing))
    sys.exit(1)
print("every defined error code is exercised by the E2E suite")
