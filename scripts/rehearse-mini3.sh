#!/bin/sh
# Pre-install rehearsal on mini3 (macOS): real mihomo + real subscription, proxy on mini3's LAN IP.
# Usage (from the Mac): scripts/rehearse-mini3.sh start|stop
# The subscription URL is sent over ssh stdin from $SUBFILE; it is never put on a command line.
set -eu
HOST=${HOST:-mini3lan}
case "$1" in
start)
  ssh "$HOST" 'zsh -lc "cd ~/lanproxy-build && go build -o ~/lanproxy-rehearsal/lanproxy ./cmd/lanproxy"'
  ssh "$HOST" 'mkdir -p ~/lanproxy-rehearsal/data ~/lanproxy-rehearsal/rules && cp ~/lanproxy-build/vendor-rules/*.mrs ~/lanproxy-rehearsal/rules/'
  ssh "$HOST" 'cd ~/lanproxy-rehearsal && R=$PWD && (nohup ./lanproxy admin -dev -dir $R/data -addr 127.0.0.1:18080 > admin.log 2>&1 & echo $! > admin.pid) && sleep 1 && ./lanproxy set-sub -dir $R/data' < "$SUBFILE"
  ssh "$HOST" 'cd ~/lanproxy-rehearsal && R=$PWD && (nohup ./lanproxy core -dir $R/data -mihomo $R/mihomo -assets $R/rules > core.log 2>&1 & echo $! > core.pid) && (nohup ./lanproxy proxy -dir $R/data > proxy.log 2>&1 & echo $! > proxy.pid) && sleep 2 && cat data/status.json | head -20'
  ;;
stop)
  ssh "$HOST" 'cd ~/lanproxy-rehearsal && for p in proxy core admin; do [ -f $p.pid ] && kill $(cat $p.pid) 2>/dev/null; rm -f $p.pid; done; echo stopped'
  ;;
esac
