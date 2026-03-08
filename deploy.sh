#!/bin/bash
set -e

echo "[deploy] Fetching latest from origin..."
cd /opt/moltgrid
git fetch origin
git reset --hard origin/main

echo "[deploy] Pulling internal config..."
cd /opt/moltgrid-internal
git fetch origin
git reset --hard origin/main

echo "[deploy] Pulling frontend..."
cd /opt/moltgrid-web
git fetch origin
git reset --hard origin/main

echo "[deploy] Restoring symlinks..."
ln -sf /opt/moltgrid-internal/CLAUDE.md /opt/moltgrid/CLAUDE.md
ln -sf /opt/moltgrid-internal/.planning /opt/moltgrid/.planning

echo "[deploy] Syncing skills from internal repo..."
mkdir -p /opt/moltgrid/.claude/commands/moltgrid
cp -r /opt/moltgrid-internal/.claude/commands/moltgrid/. /opt/moltgrid/.claude/commands/moltgrid/

echo "[deploy] Installing dependencies..."
cd /opt/moltgrid
source venv/bin/activate
pip install -r requirements.txt --quiet --no-cache-dir

echo "[deploy] Restarting service..."
systemctl restart moltgrid

echo "[deploy] Waiting for server to boot..."
for i in $(seq 1 12); do
  if curl -sf http://127.0.0.1:8000/v1/health > /dev/null 2>&1; then
    VER=$(curl -sf http://127.0.0.1:8000/v1/health | python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"{d['version']} - {d['status']}\")" )
    echo "[deploy] $VER"
    echo "[deploy] Done."
    exit 0
  fi
  sleep 5
done

echo "[deploy] ERROR: health check failed after 60s"
exit 1
