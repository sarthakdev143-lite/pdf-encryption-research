# Migrate THIS project to VPS + 24/7 Muse Spark — paste ready, fill nothing

Agent: do everything below end-to-end. Do not ask for repo names, paths, or tokens. Derive everything. Model for all 24/7 work is always `opencode-go/muse-spark-1.3-contributor`. Never use deepseek or any other model.

## 0. Detect what this project is (do this first, it changes the workflow)

Read `README.md`, file list, `package.json` / `requirements.txt` / `go.mod` / `Cargo.toml`, `src/` / `app/` layout.

- RESEARCH = hypothesis + proofs output. Signals: `findings/`, `corpus/`, `triage.py`, papers, PoCs, goal is prove/gather evidence, not ship a product. Example: pdf-encryption-research.
- DEVELOPMENT = shippable product. Signals: `src/`, `app/`, `components/`, `pages/`, `server/`, `Dockerfile`, build/start scripts, API routes, DB migrations, goal is ship features. Output is PRs.

Decide once, write it to `VPS_TYPE` file containing one word (`research` or `development`), commit it. All steps below branch on this.

## 0.5 Stop limits — ask the user (do not assume)

Before starting the loop, ask these three, with defaults if they say skip/default. Use the question tool if available, else plain text. One round, then proceed.

1. Time: how many hours per day should it run, which UTC window, until what date? Default: `2h/day, 02:00-04:00 UTC, no end date`.
2. Budget/dev limit: max cycles per day, max API cost, max PRs/files? Default: `no cap except time window`.
3. Stop metric: what counts as done to stop early? Research: `first reportable leak`, `all tracks exhausted`. Development: `plan complete`, `all CI green`, `N PRs merged`. Default: `never stop early, keep logging negatives`.

Write answers to `VPS_LIMITS.md` (time window, budget, stop metric, UTC), commit it. The loop reads it: `START_HOUR_UTC` + `RUN_MINUTES` in `run-*.sh` come from here. If user later changes limits, update the file + script + restart tmux.

## 1. Auto-detect (local, Windows Git Bash)

```
PROJ_DIR=$(pwd)
PROJ_NAME=$(basename "$PROJ_DIR")
REPO="sarthakdev143-lite/$PROJ_NAME"
VPS_DIR="~/$PROJ_NAME"
```

Use these values everywhere below. If `gh auth status` fails, stop and say so.

## 2. Local git (no questions)

- If not a repo: `git init -b main`
- If no `.gitignore`, create one with: `node_modules/`, `__pycache__/`, `.venv/`, `.opencode-logs/`, `*.pyc`
- Stage: sources + docs + findings. Never stage secrets (`.env`, `*_token*`, `secrets.env`), never stage bulk (`node_modules`, `.venv`, `corpus/` if regenerable — stage it only if <5MB and needed).
- Commit if anything staged. Then: `gh repo create sarthakdev143-lite/$PROJ_NAME --private --source=. --push` (if repo exists, just `git push -u origin main`).

## 3. VPS clone (via 8x-desktops MCP `run_command`, token from user message history, else ask once)

```
cd ~ && gh repo clone sarthakdev143-lite/$PROJ_NAME
ls ~/PROJ_NAME
```

Box is `sarthak`. All VPS commands are `bash -lc`, 120s max. Long work goes in tmux, never in `run_command`.

## 4. VPS env (auto-detect)

```
cd ~/PROJ_NAME
if [ -f requirements.txt ]; then curl -LsSf https://astral.sh/uv/install.sh | sh; export PATH="$HOME/.local/bin:$PATH"; uv venv .venv; uv pip install -r requirements.txt; fi
if [ -f package.json ]; then npm install --silent; fi
```

Verify with the project's own entry point from README (one quick command <60s). If it needs longer, run it in tmux.

## 5. Write loop files verbatim (pick A or B by VPS_TYPE, only replace PROJ_NAME)

### 5A. RESEARCH (VPS_TYPE=research) — 1 day = 1 branch, no PRs

`VPS_BRIEF.md`:
```
# VPS 24/7 Brief — PROJ_NAME
You live in ~/PROJ_NAME on box sarthak (Mumbai, 8 vCPU/32GB).
## Hard rules
- Work only from repo files. Never touch real user data.
- Every claim needs PoC + version + 5-15 line repro + cross-check.
- Append to findings/LOG.md (create if missing), update findings/daily/YYYY-MM-DD.md.
## Pipeline
- Read README.md first, then run the project's own verify command.
## Tracks
1. Re-run baseline, confirm state.
2. Smallest next verifiable step from README/TODO/issues.
3. Repeat: prove, log, commit.
## Daily branch policy (strict: 1 day = 1 branch)
- Branch research/vps-YYYY-MM-DD (UTC). Work ONLY there. Never main, never past dates.
- Runner checks out today's branch. Small commits there. End of cycle update findings/daily/YYYY-MM-DD.md and push origin <today-branch>. Never push main from VPS.
```

`run-research.sh` (exact — do not reformat quoting):
```bash
#!/bin/bash
set -u
cd "$HOME/PROJ_NAME"
export PATH="$HOME/.local/bin:$PATH"
mkdir -p findings findings/daily
echo "[$(date -u +%FT%TZ)] boot: $(git rev-parse --short HEAD) $(node --version 2>/dev/null)" >> findings/24-7.log
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
  git add findings/daily/"$TODAY".md findings/LOG.md 2>/dev/null || true
  git diff --cached --quiet || git commit -qm "daily: $TODAY update cycle $CYCLE"
  git push -u origin "$BRANCH" >> findings/24-7.log 2>&1 || true
  sleep 120
done
```

Locally: `git add VPS_BRIEF.md run-research.sh findings/daily/.gitkeep; git commit -m "feat: VPS 24-7 (muse-spark, daily branches)"; git push origin main`.

### 5B. DEVELOPMENT (VPS_TYPE=development) — plan first, many PRs, daily rollup

First cycle the agent writes `VPS_PLAN.md` from README/TODO/issues (milestones → tasks, each task = 1 branch + 1 PR). Then works task-by-task.

`VPS_BRIEF_DEV.md`:
```
# VPS 24/7 Brief DEV — PROJ_NAME
You live in ~/PROJ_NAME on box sarthak.
## Hard rules
- Read README.md, VPS_PLAN.md first. If no plan, write it this cycle and stop.
- One task = one branch feat/YYYY-MM-DD-slug from main, implement + test, push, open PR to main with `gh pr create --fill`. Never push main directly. Never merge your own PRs unless CI green + brief allows.
- Each cycle: pick highest-priority open task from VPS_PLAN.md, do smallest verifiable slice.
- Update docs/daily/YYYY-MM-DD.md every cycle: tasks done, PRs opened/merged/pending CI, failing checks, next task.
## Daily rollup
- Daily branch dev/vps-YYYY-MM-DD holds only status (docs/daily/, VPS_PLAN.md updates). Feature code lives in feat/* branches + PRs.
- Work may touch many feat/* branches per day. That is expected. 1 day = 1 daily rollup, N tasks = N PRs.
```

`run-dev.sh` (exact):
```bash
#!/bin/bash
set -u
cd "$HOME/PROJ_NAME"
export PATH="$HOME/.local/bin:$PATH"
mkdir -p docs/daily
echo "[$(date -u +%FT%TZ)] boot: $(git rev-parse --short HEAD)" >> docs/daily-24-7.log
CYCLE=0
while true; do
  CYCLE=$((CYCLE+1))
  TODAY=$(date -u +%F)
  DAILY="dev/vps-$TODAY"
  if ! git rev-parse --verify "$DAILY" >/dev/null 2>&1; then
    git checkout -b "$DAILY" >> docs/daily-24-7.log 2>&1
  else
    git checkout "$DAILY" >> docs/daily-24-7.log 2>&1
  fi
  echo "[$(date -u +%FT%TZ)] cycle $CYCLE start daily=$DAILY" >> docs/daily-24-7.log
  PROMPT_FILE=$(mktemp)
  cat VPS_BRIEF_DEV.md VPS_PLAN.md 2>/dev/null > "$PROMPT_FILE"
  {
    echo ""
    echo "Today is $TODAY, daily branch is $DAILY (already checked out)."
    echo "Pick next task from VPS_PLAN.md. Create feat/$TODAY-<slug> from main for code, push it, open PR to main. Update docs/daily/$TODAY.md."
  } >> "$PROMPT_FILE"
  MSG="Today is $TODAY daily $DAILY. Read attached plan and do one dev cycle with PRs."
  opencode run --model opencode-go/muse-spark-1.3-contributor -f "$PROMPT_FILE" "$MSG" >> docs/daily-24-7.log 2>&1
  rm -f "$PROMPT_FILE"
  echo "[$(date -u +%FT%TZ)] cycle $CYCLE exit=$? daily=$DAILY push" >> docs/daily-24-7.log
  git add docs/daily/"$TODAY".md VPS_PLAN.md docs/daily-24-7.log 2>/dev/null || true
  git diff --cached --quiet || git commit -qm "daily: $TODAY dev rollup cycle $CYCLE"
  git push -u origin "$DAILY" >> docs/daily-24-7.log 2>&1 || true
  sleep 120
done
```

Locally: `git add VPS_BRIEF_DEV.md VPS_PLAN.md run-dev.sh docs/daily/.gitkeep; git commit -m "feat: VPS 24-7 dev (muse-spark, plan+PRs)"; git push origin main`.
Loop file is `run-dev.sh`, tmux session `dev` (not `research`). Daily branches are `dev/vps-*`, feature branches `feat/*` + PRs to `main`.

## 6. Start loop on VPS (pick by type)

RESEARCH:
```
cd ~/PROJ_NAME && git pull --ff-only
chmod +x run-research.sh
bash -n run-research.sh && echo SYNTAX_OK
tmux kill-session -t research 2>/dev/null; tmux new-session -d -s research -c ~/PROJ_NAME "bash -lc 'bash run-research.sh'"
sleep 8; tmux ls | grep research
```

Verify: `ps aux | grep muse-spark`, `tail findings/24-7.log` shows `muse-spark-1.3-contributor` + `cycle 1 start branch=research/vps-YYYY-MM-DD`.

DEVELOPMENT:
```
cd ~/PROJ_NAME && git pull --ff-only
chmod +x run-dev.sh
bash -n run-dev.sh && echo SYNTAX_OK
tmux kill-session -t dev 2>/dev/null; tmux new-session -d -s dev -c ~/PROJ_NAME "bash -lc 'bash run-dev.sh'"
sleep 8; tmux ls | grep dev
```
Verify: `tail docs/daily-24-7.log` + `gh pr list` shows feat/* PRs. Daily branches `dev/vps-*` hold rollups, code ships via many `feat/*` PRs to `main`.

If `bash -n` fails, restore this exact script (quoting bug comes from hand-editing the opencode line). If checkout blocked by local changes: `git stash push -m wip --keep-index`, checkout/merge, `git stash pop`. If pull on research says diverging: `git fetch origin; git checkout main; git merge --ff-only origin/main; git checkout <research-branch>; git merge main`.

## 7. Done — report this

RESEARCH:
- GitHub repo + `origin/research/vps-YYYY-MM-DD` pushed
- tmux `research` running muse-spark, log `~/PROJ_NAME/findings/24-7.log`
- Portal: `cd ~/PROJ_NAME; git log --oneline -5; tmux attach -t research; tail -f findings/24-7.log`

DEVELOPMENT:
- GitHub repo + `origin/dev/vps-YYYY-MM-DD` (rollup) + `origin/feat/*` + open PRs
- tmux `dev` running muse-spark, log `~/PROJ_NAME/docs/daily-24-7.log`, plan `VPS_PLAN.md`
- Portal: `cd ~/PROJ_NAME; git branch -a; gh pr list; tmux attach -t dev; tail -f docs/daily-24-7.log`
