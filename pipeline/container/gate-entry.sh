#!/usr/bin/env bash
# Runs INSIDE a container with no credentials. Checks out $BRANCH from a fresh
# clone and runs the gate from the host's trusted copy.
set -uo pipefail

: "${BRANCH:?}"
git config --global advice.detachedHead false
git config --global --add safe.directory '*'
git clone -q /src "${HOME}/work" || { echo "gate: clone of /src failed"; exit 90; }
cd "${HOME}/work" || exit 90
git checkout -q "origin/${BRANCH}" 2>/dev/null || git checkout -q "${BRANCH}" \
  || { echo "gate: unknown branch ${BRANCH}"; exit 91; }
echo "gate: checking ${BRANCH} at $(git rev-parse --short HEAD)"
exec bash /src/pipeline/gate.sh
