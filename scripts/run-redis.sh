#!/bin/sh
# Starts a Redis server for the redis-demo profile, using the test-scoped
# embedded-redis binary so no separate Redis installation is needed.
#
#   sh scripts/run-redis.sh &
#
# The library's Redis dependency is optional and the test scope has the binary, so
# this is the least intrusive way to get a real server for manual testing. Nothing
# in src/main depends on it.
set -e
cd "$(dirname "$0")/.."

CP_FILE=$(mktemp)
mvn -B --no-transfer-progress -q -Dmaven.repo.local=.m2repo \
  dependency:build-classpath -Dmdep.outputFile="$CP_FILE" -Dmdep.includeScope=test >/dev/null

exec java -cp "$(cat "$CP_FILE")" scripts/RedisMain.java "$@"
