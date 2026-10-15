#!/usr/bin/env bash
# Run all N batches of run_ex_pipeline.py back to back into one database,
# one log per batch (<prefix>_batchK.log in the repo root). A batch that ends
# with failures is re-run once - stored reports are skipped, so only the
# failed ones are retried.
#
# Meant to be launched detached so it survives a dropped SSH/VS Code session:
#   systemd-run --user --unit=ex4-batches --same-dir \
#       .dev_tools/run_ex_batches.sh db/ex4_threatlens.db ex4 3
#
# Usage: run_ex_batches.sh <db-path> <log-prefix> [num-batches]
set -u

DB_PATH=${1:?db path required}
PREFIX=${2:?log prefix required}
N=${3:-3}

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT" || exit 1
PY="$REPO_ROOT/.venv/bin/python"

rc_all=0
for k in $(seq 1 "$N"); do
    log="${PREFIX}_batch${k}.log"
    for attempt in 1 2; do
        [ "$attempt" -gt 1 ] && echo "[$(date +%H:%M:%S)] Retrying batch $k/$N (attempt $attempt)" >>"$log"
        "$PY" -u .dev_tools/run_ex_pipeline.py --db-path "$DB_PATH" --batch "$k/$N" >>"$log" 2>&1
        rc=$?
        [ "$rc" -eq 0 ] && break
    done
    [ "$rc" -ne 0 ] && rc_all=$rc
done
echo "[$(date +%H:%M:%S)] All $N batches finished (exit $rc_all)" >>"${PREFIX}_batch${N}.log"
exit "$rc_all"
