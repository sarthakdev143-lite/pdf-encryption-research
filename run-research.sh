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
  TODAY=$(date -u +%F)
  BRANCH="research/vps-$TODAY"
  mkdir -p findings/daily
  # 1 day = 1 branch: checkout today, create from HEAD on rollover
  if ! git rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
    git checkout -b "$BRANCH" 2>&1 | tail -1 >> findings/24-7.log
  else
    git checkout "$BRANCH" 2>&1 | tail -1 >> findings/24-7.log
  fi
  echo "[$(date -u +%FT%TZ)] cycle $CYCLE start branch=$BRANCH" >> findings/24-7.log
  opencode run --model opencode-go/muse-spark-1.3-contributor "$(cat VPS_BRIEF.md; echo; echo \"Today is $TODAY, branch is $BRANCH (already checked out). Work one track for this cycle only, smallest verifiable step. Commit to $BRANCH only. Update findings/daily/$TODAY.md and append to findings/24-7.log and findings/LOG.md.\")" >> findings/24-7.log 2>&1
  echo "[$(date -u +%FT%TZ)] cycle $CYCLE exit=$? branch=$BRANCH — daily push" >> findings/24-7.log
  # guaranteed daily update: commit daily file + findings if changed, push research branch only
  git add findings/daily/"$TODAY".md findings/LOG.md findings/report.md findings/report.csv findings/authmatrix.md findings/authmatrix.csv findings/incremental.md findings/incremental.csv findings/prevchain.md findings/prevchain.csv 2>/dev/null
  git diff --cached --quiet || git commit -qm "daily: $TODAY update cycle $CYCLE" 2>&1 | tail -1 >> findings/24-7.log
  git push -u origin "$BRANCH" 2>&1 | tail -2 >> findings/24-7.log
  sleep 120
done
