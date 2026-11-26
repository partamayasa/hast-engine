#!/bin/bash
# Menjalankan Backend API + Streamlit Dashboard dalam sesi tmux.
# Produksi: ./app.sh
# Pengembangan (auto-reload): HAST_DEV=1 ./app.sh
# Prasyarat: uv (https://docs.astral.sh/uv/), tmux, .env, dan backend/config/dss_config.json.

set -e

SESSION="cvss_project"
export TERM="${TERM:-xterm-256color}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$SERVER_IP" ] && SERVER_IP="127.0.0.1"

RELOAD_FLAG=""
[ "${HAST_DEV:-0}" = "1" ] && RELOAD_FLAG="--reload"

echo "1. Cleaning up active ports and previous sessions"
tmux kill-session -t "$SESSION" 2>/dev/null || true
fuser -k 8000/tcp 2>/dev/null || true
fuser -k 8501/tcp 2>/dev/null || true
sleep 1

echo "2. Syncing locked dependencies"
(cd "${ROOT_DIR}" && uv sync --frozen --no-dev)

echo "3. Starting Backend API in Window 0 (Port 8000)"
tmux -2 new-session -d -s "$SESSION" -n 'Backend' </dev/null
tmux send-keys -t "$SESSION:Backend" "cd \"${ROOT_DIR}\" && uv run uvicorn backend.api:app --host 0.0.0.0 --port 8000 ${RELOAD_FLAG}" C-m
sleep 3

echo "4. Starting Streamlit Dashboard in Window 1 (Port 8501)"
tmux new-window -t "$SESSION" -n 'Dashboard' </dev/null
tmux send-keys -t "$SESSION:Dashboard" "cd \"${ROOT_DIR}\" && uv run streamlit run \"${ROOT_DIR}/frontend/app.py\" --server.port 8501 --server.address 0.0.0.0 --server.headless true" C-m

echo "[Status]: All services started in tmux session '$SESSION'"
echo "Dashboard URL : http://${SERVER_IP}:8501"
echo "API Docs URL  : http://${SERVER_IP}:8000/docs"
echo "Attach session: tmux attach -t $SESSION"
