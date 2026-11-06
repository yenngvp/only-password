#!/usr/bin/env bash
# Runs INSIDE a container. Checks that the boundary actually holds.
set -u
bad=0
pass() { echo "PASS  $*"; }
miss() { echo "FAIL  $*"; bad=1; }

code="$(curl -sS -o /dev/null -m 20 -w '%{http_code}' https://index.crates.io/config.json 2>/dev/null)"
[ "${code}" = "200" ] && pass "allowlisted host reachable through the proxy (crates.io index)" \
  || miss "crates.io index not reachable through the proxy (HTTP ${code})"

if curl -sS -o /dev/null -m 10 https://example.com 2>/dev/null; then
  miss "example.com is reachable: the allowlist is not enforced"
else
  pass "non-allowlisted host blocked by the proxy (example.com)"
fi

if curl -sS -o /dev/null -m 5 --noproxy '*' https://1.1.1.1 2>/dev/null; then
  miss "direct egress works: the container can bypass the proxy"
else
  pass "no direct route to the internet without the proxy"
fi

if touch /src/.smoke-write-test 2>/dev/null; then
  rm -f /src/.smoke-write-test
  miss "the host repository is writable from the container"
else
  pass "host repository is mounted read-only"
fi

[ "$(id -u)" != "0" ] && pass "running as a non-root user" || miss "running as root"

for tool in cargo rustfmt cargo-clippy cargo-deny git jq claude; do
  command -v "${tool}" >/dev/null && pass "tool present: ${tool}" || miss "tool missing: ${tool}"
done

if [ "${LIVE:-0}" = "1" ]; then
  out="$(timeout 120 claude -p "Reply with the single word OK" --max-budget-usd 0.50 \
         --disallowedTools "WebSearch,WebFetch" 2>&1)"
  if [ $? -eq 0 ] && grep -q "OK" <<<"${out}"; then
    pass "Claude Code can authenticate and answer from inside the container"
  else
    miss "Claude Code call failed: $(tail -n 5 <<<"${out}")"
  fi
fi

exit "${bad}"
