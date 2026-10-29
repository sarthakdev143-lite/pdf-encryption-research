#!/bin/bash
# 2h/day research loop for ~/pdf-encryption-research on VPS
# Runs inside tmux session `research`. Logs to findings/24-7.log
# Policy: 1 day = 1 branch research/vps-YYYY-MM-DD, daily push to GitHub
# Schedule: runs only 02:00-04:00 UTC daily (07:30-09:30 IST), idle otherwise
set -u
cd "$HOME/pdf-encryption-research"
export PATH="$HOME/.local/bin:$PATH"
mkdir -p findings findings/daily

START_HOUR_UTC=2
RUN_MINUTES=120

echo "[$(date -u +%FT%TZ)] boot 2h/day window ${START_HOUR_UTC}:00 UTC +${RUN_MINUTES}min: $(git rev-parse --short HEAD 2>/dev/null)" >> findings/24-7.log

CYCLE=0
while true; do
  NOW_EPOCH=$(date -u +%s)
  DAY_START=$(date -u -d "$(date -u +%F) ${START_HOUR_UTC}:00:00" +%s)
  WINDOW_END=$((DAY_START + RUN_MINUTES * 60))
  if [ "$NOW_EPOCH" -lt "$DAY_START" ]; then
    SLEEP_SEC=$((DAY_START - NOW_EPOCH))
    if [ "$SLEEP_SEC" -lt 60 ]; then SLEEP_SEC=60; fi
    if [ "$SLEEP_SEC" -gt 600 ]; then SLEEP_SEC=600; fi
    echo "[$(date -u +%FT%TZ)] idle until window ${START_HOUR_UTC}:00 UTC, sleep ${SLEEP_SEC}s" >> findings/24-7.log
    sleep "$SLEEP_SEC"
    continue
  fi
  if [ "$NOW_EPOCH" -ge "$WINDOW_END" ]; then
    NEXT_DAY=$(date -u -d "tomorrow" +%F)
    NEXT_START=$(date -u -d "$NEXT_DAY ${START_HOUR_UTC}:00:00" +%s)
    SLEEP_SEC=$((NEXT_START - NOW_EPOCH))
    if [ "$SLEEP_SEC" -lt 60 ]; then SLEEP_SEC=60; fi
    if [ "$SLEEP_SEC" -gt 600 ]; then SLEEP_SEC=600; fi
    echo "[$(date -u +%FT%TZ)] window done, next ${NEXT_DAY} ${START_HOUR_UTC}:00 UTC, sleep ${SLEEP_SEC}s" >> findings/24-7.log
    sleep "$SLEEP_SEC"
    continue
  fi
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
