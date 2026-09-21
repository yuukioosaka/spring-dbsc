#!/bin/sh
# Starts both demo instances scripts/e2e.py needs, and waits for them.
#
# One instance is not enough. The main demo (8443) raises its rate-limit budgets to
# 1000 so the suite's own deliberate failures -- bad signatures, replayed
# challenges, malformed proofs -- do not throttle the run that is testing them.
# That leaves RATE_LIMITED unreachable there, so the throttling checks need the
# second instance (9443) from the ratelimit-e2e profile, whose failure budget is 5.
#
# Usage:
#   sh scripts/run-demos.sh                       # in one shell
#   DBSC_CHALLENGE_TTL=2 DBSC_RATE_LIMIT_FAILURES=5 python3 scripts/e2e.py
#
# The 2-second challenge TTL is what makes CHALLENGE_EXPIRED observable at test
# speed; the suite reports those checks as skipped rather than failed without it.

set -e
cd "$(dirname "$0")/.."

MVN="mvn -B --no-transfer-progress -Dmaven.repo.local=.m2repo"
TTL="-Ddbsc.challenge-ttl=2s"

rm -f /tmp/demo.log /tmp/demo-ratelimit.log

nohup $MVN -Pdemo \
  -Dspring-boot.run.jvmArguments="$TTL" \
  spring-boot:run > /tmp/demo.log 2>&1 &

nohup $MVN -Pdemo,ratelimit-e2e \
  -Dspring-boot.run.jvmArguments="$TTL" \
  spring-boot:run > /tmp/demo-ratelimit.log 2>&1 &

wait_for() {
  log=$1
  name=$2
  for _ in $(seq 1 90); do
    if grep -q "Started DemoApplication" "$log" 2>/dev/null; then
      echo "$name is up"
      return 0
    fi
    if grep -qE "BUILD FAILURE|APPLICATION FAILED TO START" "$log" 2>/dev/null; then
      echo "$name failed to start"
      tail -40 "$log"
      return 1
    fi
    sleep 2
  done
  echo "$name did not start within 180s"
  tail -40 "$log"
  return 1
}

wait_for /tmp/demo.log "demo (8443)"
wait_for /tmp/demo-ratelimit.log "rate-limit demo (9443)"
