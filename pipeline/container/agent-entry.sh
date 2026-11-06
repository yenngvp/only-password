#!/usr/bin/env bash
# Runs INSIDE an agent container. Clones the read-only host repo, runs one
# headless Claude Code session on $BRANCH, and hands any new commits back to
# the host as a git bundle in /out. The host never runs anything from here.
set -uo pipefail

: "${ROLE:?}" "${BRANCH:?}" "${BUDGET_USD:?}" "${TIMEOUT_MIN:?}"
BASE="${BASE:-main}"

git config --global user.name "onlypassword-agent (${ROLE})"
git config --global user.email "agent@onlypassword.invalid"
git config --global advice.detachedHead false
# /src can appear owned by another user depending on how Docker maps the mount.
git config --global --add safe.directory '*'

git clone -q /src "${HOME}/work" || { echo "entry: clone of /src failed"; exit 90; }
cd "${HOME}/work" || exit 90
if git rev-parse -q --verify "origin/${BRANCH}" >/dev/null; then
  git checkout -q -b "${BRANCH}" "origin/${BRANCH}"
  # Keep a continued branch on top of main (main moves when the driver records state).
  if ! git merge-base --is-ancestor "origin/${BASE}" HEAD; then
    git merge -q --no-edit "origin/${BASE}" || { git merge --abort; echo "entry: could not merge ${BASE} into ${BRANCH}"; }
  fi
else
  git checkout -q -b "${BRANCH}" "origin/${BASE}"
fi
echo "entry: role=${ROLE} branch=${BRANCH} at $(git rev-parse --short HEAD)"

args=(-p --dangerously-skip-permissions --output-format stream-json --verbose
      --max-budget-usd "${BUDGET_USD}" --disallowedTools "WebSearch,WebFetch")
[ -n "${MODEL:-}" ] && args+=(--model "${MODEL}")
[ -n "${EFFORT:-}" ] && args+=(--effort "${EFFORT}")

timeout --signal=TERM --kill-after=30 "${TIMEOUT_MIN}m" \
  claude "${args[@]}" < /in/prompt.md > /out/claude.jsonl 2> /out/claude.stderr
rc=$?
echo "entry: claude exited with ${rc}"
[ "${rc}" -eq 0 ] || tail -n 20 /out/claude.stderr

if [ "${ROLE}" = "evaluator" ]; then
  exit 0
fi

current="$(git rev-parse --abbrev-ref HEAD)"
if [ "${current}" != "${BRANCH}" ]; then
  echo "entry: warning: session ended on '${current}', not '${BRANCH}'; only '${BRANCH}' is exported"
elif [ -n "$(git status --porcelain)" ]; then
  # Safety net: work the agent forgot to commit is kept rather than lost.
  git add -A && git commit -q -m "wip: uncommitted changes at session end" \
    && echo "entry: committed leftover uncommitted changes"
fi

if [ -n "$(git rev-list -n 1 "origin/${BASE}..${BRANCH}")" ]; then
  git bundle create -q /out/result.bundle "origin/${BASE}..${BRANCH}" \
    && echo "entry: exported $(git rev-list --count "origin/${BASE}..${BRANCH}") commit(s)"
else
  echo "entry: no commits on ${BRANCH} beyond ${BASE}"
fi
exit 0
