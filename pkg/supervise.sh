#!/bin/sh
# Runs "$@" and starts it again if it exits (crash, out-of-memory kill), so
# one process dying does not leave the app down until someone restarts it.
# On SIGTERM/SIGINT (app stop or upgrade) the child is stopped and we exit.
p=
trap '[ -n "$p" ] && kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; exit 0' TERM INT
n=0
while :; do
	"$@" &
	p=$!
	wait "$p"
	code=$?
	n=$((n + 1))
	echo "supervise: $1 $2 exited with status $code (restart $n), restarting in 2s" >&2
	sleep 2
done
