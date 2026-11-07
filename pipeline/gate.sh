#!/usr/bin/env bash
# The deterministic quality gate. Run from the root of a checkout, inside the
# agent container. Exit 0 means pass.
#
# The dependency allowlist and the cargo-deny policy are read from $TRUSTED
# (the host's read-only copy), never from the checkout being judged.
set -uo pipefail

TRUSTED="${TRUSTED:-/src}"
ALLOW="${TRUSTED}/spec/approved-deps.txt"
DENY_CFG="${TRUSTED}/pipeline/deny.toml"

fail() { echo; echo "GATE FAILED: $*"; exit 1; }
step() { echo; echo "=== gate step: $* ==="; }

step "workspace present"
[ -f Cargo.toml ] || fail "no Cargo.toml at the repository root"
[ -f Cargo.lock ] || fail "Cargo.lock is missing; it must be committed"

step "direct dependencies are approved"
[ -f "${ALLOW}" ] || fail "approved dependency list not found at ${ALLOW}"
meta="$(cargo metadata --no-deps --format-version 1)" || fail "cargo metadata failed"
approved="$(sed -e 's/#.*//' -e 's/[[:space:]]//g' "${ALLOW}" | grep -v '^$' | sort -u)"
used="$(jq -r '.packages[].dependencies[] | select(.path == null) | .name' <<<"${meta}" | sort -u)"
unapproved="$(comm -23 <(printf '%s\n' "${used}") <(printf '%s\n' "${approved}") | grep -v '^$' || true)"
[ -z "${unapproved}" ] || fail "direct dependencies not in spec/approved-deps.txt: $(echo ${unapproved})"
echo "ok: $(printf '%s\n' "${used}" | grep -c . || true) direct dependencies, all approved"

step "fetch dependencies (locked)"
cargo fetch --locked || fail "cargo fetch --locked failed (is Cargo.lock up to date?)"

step "supply-chain policy (cargo-deny)"
cargo deny --offline --locked --config "${DENY_CFG}" check advisories bans licenses sources \
  || fail "cargo-deny rejected the dependency graph"

step "unsafe code is forbidden in every crate root"
roots="$(jq -r '.packages[].targets[]
  | select(.kind | all(. != "test" and . != "bench" and . != "example" and . != "custom-build"))
  | .src_path' <<<"${meta}")"
[ -n "${roots}" ] || fail "the workspace has no library or binary targets"
while IFS= read -r root; do
  grep -q '^#!\[forbid(unsafe_code)\]' "${root}" || fail "${root} lacks #![forbid(unsafe_code)]"
done <<<"${roots}"
echo "ok"

step "no ignored tests"
if grep -rn --include='*.rs' '#\[ignore' . --exclude-dir=target; then
  fail "tests must not be marked #[ignore]"
fi
echo "ok"

step "formatting"
cargo fmt --all -- --check || fail "cargo fmt found unformatted code (run: cargo fmt --all)"

step "lints"
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings \
  || fail "clippy reported warnings"

step "portability: cargo check for the other desktop targets"
for target in x86_64-pc-windows-msvc aarch64-apple-darwin; do
  if rustup target list --installed 2>/dev/null | grep -qx "${target}"; then
    cargo check --workspace --all-targets --all-features --locked --offline --target "${target}" \
      || fail "cargo check failed for target ${target}"
    echo "ok: ${target}"
  else
    echo "skipped: ${target} is not installed in this image"
  fi
done

step "tests"
cargo test --workspace --all-features --locked --offline || fail "tests failed"

echo
echo "GATE PASSED"
