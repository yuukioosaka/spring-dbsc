#!/bin/sh
# Throwaway: kill whatever holds 8443/9444/9445/9446, then optionally start one instance.
#
# The port scan is the primary sweep, but it misses a process that failed to bind its
# port -- an instance that died during startup still holds its H2 file lock, and the
# next start of the same profile then fails with "Database may be already in use".
# So the pattern sweep below is not redundant: it is what clears those orphans.
for port in 8443 9444 9445 9446; do
  pid=$(ss -ltnp 2>/dev/null | grep ":$port " | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1)
  if [ -n "$pid" ]; then
    echo "killing pid $pid on $port"
    kill -9 "$pid" 2>/dev/null
  fi
done
pkill -9 -f "DemoApplication" 2>/dev/null
pkill -9 -f "spring-boot:run" 2>/dev/null
sleep 4
ss -ltnp 2>/dev/null | grep -E ":(8443|9444|9445|9446) " || echo "all ports free"
