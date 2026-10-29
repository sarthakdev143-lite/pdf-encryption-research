#!/bin/bash
# 24/7 research loop for ~/pdf-encryption-research on VPS
# Runs inside tmux session `research`. Logs to findings/24-7.log
# Policy: 1 day = 1 branch research/vps-YYYY-MM-DD, daily push to GitHub
set -u
cd "$HOME/pdf-encryption-research"
export PATH="$HOME/.local/bin:$PATH"
mkdir -p findings findings/daily

echo "[$(date -u +%FT%TZ)] boot: $(git rev-parse --short HEAD 2>/dev/null) $(.venv/bin/python --version 2>&1) $(node --version)" >> findings/24-7.log

CYCLE=0
while true; do
  CYCLE=$((CYCLE+1))
  TODAY=$(date -u +%F)
  BRANCH="research/vps-$TODAY"
  if ! git rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
    git checkout -b "$BRANCH" >> findings/24-7.log 2>&1
  else
    git checkout "$BRANCH" >> findings/24-7.log 2>&1
  fi
  echo "[$(date -u +%FT%TZ)] cycle $CYCLE start branch=$BRANCH" >> findings/24-7.log
  PROMPT_FILE=$(mktemp)
  cat VPS_BRIEF.md > "$PROMPT_FILE"
  {
    echo ""
    echo "Today is $TODAY, branch is $BRANCH (already checked out)."
    echo "Work one track for this cycle only, smallest verifiable step."
    echo "Commit to $BRANCH only. Update findings/daily/$TODAY.md and append to findings/24-7.log and findings/LOG.md."
  } >> "$PROMPT_FILE"
  MSG="Today is $TODAY branch $BRANCH. Read the attached brief and do one cycle."
  opencode run --model opencode-go/muse-spark-1.3-contributor -f "$PROMPT_FILE" "$MSG" >> findings/24-7.log 2>&1
  rm -f "$PROMPT_FILE"
  echo "[$(date -u +%FT%TZ)] cycle $CYCLE exit=$? branch=$BRANCH daily-push" >> findings/24-7.log
  git add findings/daily/"$TODAY".md findings/LOG.md findings/report.md findings/report.csv findings/authmatrix.md findings/authmatrix.csv findings/incremental.md findings/incremental.csv findings/prevchain.md findings/prevchain.csv 2>/dev/null || true
  git diff --cached --quiet || git commit -qm "daily: $TODAY update cycle $CYCLE"
  git push -u origin "$BRANCH" >> findings/24-7.log 2>&1 || true
  sleep 120
done
