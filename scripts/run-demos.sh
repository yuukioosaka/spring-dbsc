#!/bin/sh
# Starts the demo instances scripts/e2e.py needs, and waits for them.
#
# One instance is not enough, because a server-side policy is a property of the
# process. The dbsc.unregistered policy is one, so the second instance (9444) runs
# the deny-e2e profile for the suite to compare against the main demo (8443). The
# third (9445) is the same server with a short dbsc.rotation-grace: rotation is
# unconditional, but the suite has to outwait the grace to prove the alias expires.
# The fourth (9446) has a short dbsc.session-ttl, because a binding's deadline is
# stamped by bind() from the server's configuration and a 1d default cannot be
# waited out.
#
# Usage:
#   sh scripts/run-demos.sh                       # in one shell
#   DBSC_CHALLENGE_TTL=2 DBSC_DENY_BASE=https://localhost:9444 \
#       DBSC_ROTATION_BASE=https://localhost:9445 DBSC_ROTATION_GRACE=5 \
#       DBSC_TTL_BASE=https://localhost:9446 DBSC_SESSION_TTL=25 \
#       python3 scripts/e2e.py
#
# The 2-second challenge TTL is what makes CHALLENGE_EXPIRED observable at test
# speed; the suite reports those checks as skipped rather than failed without it.
# DBSC_ROTATION_GRACE is that instance's dbsc.rotation-grace in seconds, which the
# suite outwaits to prove a retired id stops resolving. DBSC_SESSION_TTL is the ttl
# instance's dbsc.session-ttl, which the suite outwaits to prove a binding dies at
# its deadline.

set -e
cd "$(dirname "$0")/.."

MVN="mvn -B --no-transfer-progress -Dmaven.repo.local=.m2repo"
# The demo profile adds src/demo to the build, so the profile has to be on the
# compile below as well as on the launches -- it is what puts DemoApplication on
# the classpath.
MVN="$MVN -Pdemo"
TTL="-Ddbsc.challenge-ttl=2s"

rm -f /tmp/demo.log /tmp/demo-deny.log /tmp/demo-rotation.log /tmp/demo-ttl.log

# Compile once, before launching anything. All three instances share one
# target/classes, and spring-boot:run compiles as part of its lifecycle, so three
# simultaneous launches race each other: the loser of that race starts against a
# half-written directory and dies with "Could not find or load main class
# click.yukio.dbsc.demo.DemoApplication". Compiling up front leaves every launch
# with nothing to do, which is also what makes them cheap to start.
$MVN -DskipTests test-compile > /tmp/demo-compile.log 2>&1 || {
  echo "demo sources failed to compile"
  tail -40 /tmp/demo-compile.log
  exit 1
}

# The H2 files live under ./data, which four JVMs starting at once would each try to
# create. H2's createDirectory is not atomic: the losers fail with "Error while
# creating file .../data (a file with this name already exists)" at startup, so the
# directory is made here, once, before any instance is launched.
mkdir -p data

nohup $MVN -Pdemo \
  -Dspring-boot.run.jvmArguments="$TTL" \
  spring-boot:run > /tmp/demo.log 2>&1 &

# The deny instance needs no JVM property: dbsc.unregistered comes from its profile's
# config file, which is where an adopter would set it too.
nohup $MVN -Pdemo,deny-e2e \
  -Dspring-boot.run.jvmArguments="$TTL" \
  spring-boot:run > /tmp/demo-deny.log 2>&1 &

# Same for rotation: only the grace lives in the profile's config file, since that is
# the shape an adopter's application.yaml would take.
nohup $MVN -Pdemo,rotation-e2e \
  -Dspring-boot.run.jvmArguments="$TTL" \
  spring-boot:run > /tmp/demo-rotation.log 2>&1 &

# Same for the binding's lifetime: only dbsc.session-ttl lives in the profile's config
# file, since that is the shape an adopter's application.yaml would take.
nohup $MVN -Pdemo,ttl-e2e \
  -Dspring-boot.run.jvmArguments="$TTL" \
  spring-boot:run > /tmp/demo-ttl.log 2>&1 &

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
wait_for /tmp/demo-deny.log "deny demo (9444)"
wait_for /tmp/demo-rotation.log "rotation demo (9445)"
wait_for /tmp/demo-ttl.log "ttl demo (9446)"
