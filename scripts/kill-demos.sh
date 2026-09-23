#!/bin/sh
# Throwaway: kill whatever holds 8443/9444/9445, then optionally start one instance.
for port in 8443 9444 9445; do
  pid=$(ss -ltnp 2>/dev/null | grep ":$port " | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1)
  if [ -n "$pid" ]; then
    echo "killing pid $pid on $port"
    kill -9 "$pid" 2>/dev/null
  fi
done
pkill -9 -f "spring-boot:run" 2>/dev/null
sleep 4
ss -ltnp 2>/dev/null | grep -E ":(8443|9444|9445) " || echo "all ports free"
