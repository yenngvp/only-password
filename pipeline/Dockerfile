# Image for every pipeline container: agents, the gate and the smoke test.
# Tools only. The logic lives in pipeline/container/*.sh, read from the
# read-only /src mount, so changing it does not need a rebuild.
FROM node:22-bookworm-slim AS node

FROM rust:1.99.1-slim-bookworm

ARG UID=1000
ARG GID=1000
ARG CLAUDE_CODE_VERSION=2.1.318
ARG CARGO_DENY_VERSION=0.20.2
ARG CARGO_DENY_SHA256=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git jq ripgrep \
 && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt clippy

# Node is only here to run Claude Code.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && npm install -g --no-fund --no-audit "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
 && claude --version

# cargo-deny: pinned release binary, checksum verified.
RUN curl -fsSL -o /tmp/cargo-deny.tgz \
      "https://github.com/EmbarkStudios/cargo-deny/releases/download/${CARGO_DENY_VERSION}/cargo-deny-${CARGO_DENY_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
 && echo "${CARGO_DENY_SHA256}  /tmp/cargo-deny.tgz" | sha256sum -c - \
 && tar -xzf /tmp/cargo-deny.tgz -C /tmp \
 && install -m 0755 "/tmp/cargo-deny-${CARGO_DENY_VERSION}-x86_64-unknown-linux-musl/cargo-deny" /usr/local/bin/cargo-deny \
 && rm -rf /tmp/cargo-deny*

# Snapshot of the RustSec advisory database. Containers cannot reach GitHub at
# run time, so the gate checks against this copy; rebuild the image to refresh.
COPY deny.toml /opt/onlypassword/deny.toml
RUN mkdir -p /opt/advisory-dbs \
 && cargo new -q --lib /tmp/advisory-seed \
 && cd /tmp/advisory-seed \
 && cargo deny --config /opt/onlypassword/deny.toml fetch db \
 && rm -rf /tmp/advisory-seed \
 && chmod -R a+rwX /opt/advisory-dbs

RUN groupadd -g "${GID}" agent && useradd -m -u "${UID}" -g "${GID}" -s /bin/bash agent
USER agent
WORKDIR /home/agent

ENV CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    DISABLE_AUTOUPDATER=1 \
    CARGO_TERM_COLOR=never \
    CARGO_INCREMENTAL=0
