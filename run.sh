#!/usr/bin/env bash
# Build everything and start ProcSentinel: engine (dashboard) + collector daemon.
# Usage: ./run.sh [--host 0.0.0.0] [--port 8080] [--interval 1000]
set -euo pipefail
cd "$(dirname "$0")"

HOST=127.0.0.1 PORT=8080 INTERVAL=1000
while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST=$2; shift 2 ;;
    --port) PORT=$2; shift 2 ;;
    --interval) INTERVAL=$2; shift 2 ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
done

[ -d /proc/self ] || { echo "ProcSentinel needs Linux (/proc)."; exit 1; }

echo "==> building collector (C++17)"
cmake -S collector -B collector/build -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build collector/build -j >/dev/null
echo "==> building test workloads"
make -s -C workloads

PY=python3
if [ -x .venv/bin/python ]; then PY=.venv/bin/python
elif ! python3 -c 'import numpy, sklearn' 2>/dev/null; then
  echo "==> creating .venv with numpy + scikit-learn"
  python3 -m venv .venv && .venv/bin/pip install -q -r engine/requirements.txt
  PY=.venv/bin/python
fi

SOCK=${PROCSENTINEL_SOCKET:-/tmp/procsentinel-$(id -u).sock}
export PROCSENTINEL_SOCKET=$SOCK

cleanup() { kill "$ENGINE" "$COLLECTOR" 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT INT TERM

(cd engine && exec "$PY" -m procsentinel --host "$HOST" --port "$PORT" --socket "$SOCK") &
ENGINE=$!
for _ in $(seq 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
./collector/build/procsentinel-collector --socket "$SOCK" --interval "$INTERVAL" &
COLLECTOR=$!

echo "==> ProcSentinel running: open http://$HOST:$PORT   (Ctrl+C to stop)"
wait -n "$ENGINE" "$COLLECTOR"
