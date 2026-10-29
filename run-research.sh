#!/bin/bash
# 24/7 research loop for ~/pdf-encryption-research on VPS
# Runs inside tmux session `research`. Logs to findings/24-7.log
set -u
cd "$HOME/pdf-encryption-research"
export PATH="$HOME/.local/bin:$PATH"
mkdir -p findings

echo "[$(date -u +%FT%TZ)] boot: $(git rev-parse --short HEAD 2>/dev/null) $(.venv/bin/python --version 2>&1) $(node --version)" >> findings/24-7.log

CYCLE=0
while true; do
  CYCLE=$((CYCLE+1))
  echo "[$(date -u +%FT%TZ)] cycle $CYCLE start" >> findings/24-7.log
  opencode run --model opencode-go/deepseek-v4.1-flash "$(cat VPS_BRIEF.md; echo; echo 'Work one track for this cycle only, smallest verifiable step. Append results to findings/24-7.log and findings/LOG.md. Change nothing else without a PoC.')" >> findings/24-7.log 2>&1
  echo "[$(date -u +%FT%TZ)] cycle $CYCLE exit=$? — sleeping 120s" >> findings/24-7.log
  sleep 120
done
