#!/usr/bin/env bash
#
# Starts the ThreatLens dashboard in the background. Pairs with stop.sh.
#
# Usage:
#   ./start.sh [port]
#
# Defaults to port 8000, bound to 0.0.0.0 so it's reachable from other
# devices on the local network. Set THREATLENS_DASHBOARD_HOST=127.0.0.1 to
# restrict it to this machine instead.
#
# WARNING: this dashboard can edit and delete database rows and has no
# authentication - anyone who can reach the bound address can modify the
# database. Only bind 0.0.0.0 on a network you trust.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

PID_FILE="$SCRIPT_DIR/.server.pid"
LOG_FILE="$SCRIPT_DIR/server.log"
PORT="${1:-8000}"
HOST="${THREATLENS_DASHBOARD_HOST:-0.0.0.0}"

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "Dashboard is already running (pid $(cat "$PID_FILE"))."
    echo "Run stop.sh first if you want to restart it."
    exit 1
fi
rm -f "$PID_FILE"

if [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
    PYTHON="$REPO_ROOT/.venv/bin/python"
else
    PYTHON="python3"
fi

LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

echo "Starting ThreatLens dashboard..."
echo "  Local:   http://127.0.0.1:$PORT/"
if [[ "$HOST" == "0.0.0.0" && -n "$LAN_IP" ]]; then
    echo "  Network: http://$LAN_IP:$PORT/"
    echo
    echo "WARNING: this dashboard can edit and delete database rows and has no"
    echo "authentication - anyone on the local network who reaches this URL can"
    echo "modify the database."
fi
echo "Logging to $LOG_FILE"

nohup "$PYTHON" -m threatlens.dashboard.server --host "$HOST" --port "$PORT" \
    > "$LOG_FILE" 2>&1 &
server_pid=$!
disown "$server_pid"
echo "$server_pid" > "$PID_FILE"

sleep 0.5
if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "Error: dashboard exited immediately, check the log:"
    echo "  $LOG_FILE"
    rm -f "$PID_FILE"
    exit 1
fi

echo "Started (pid $server_pid). Stop with ./stop.sh"
