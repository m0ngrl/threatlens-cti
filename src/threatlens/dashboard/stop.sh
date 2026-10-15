#!/usr/bin/env bash
#
# Stops a dashboard started with start.sh.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/.server.pid"

if [[ ! -f "$PID_FILE" ]]; then
    echo "No pid file found - dashboard doesn't look like it's running."
    exit 0
fi

pid="$(cat "$PID_FILE")"
if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    echo "Stopped dashboard (pid $pid)."
else
    echo "Process $pid is not running (stale pid file)."
fi
rm -f "$PID_FILE"
