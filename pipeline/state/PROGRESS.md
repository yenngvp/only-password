# Progress

Written by the pipeline driver. One entry per feature that reached main.

## F001-workspace: Cargo workspace and gate baseline

Merged 2026-11-06 after 1 attempt(s), $0.14. Evaluator: Adds a virtual workspace (resolver 2) with onlypassword-core (lib, non-default features insecure-fast-kdf and test-hooks) and onlypassword-cli (bin 'onlypassword'). It declares no dependencies, carries forbid(unsafe_code) and the cfg_attr clippy denies in both crate roots, and has one trivial test per crate and a committed Cargo.lock. I ran cargo build (produces target/debug/onlypassword), cargo clippy --all-targets -- -D warnings (clean, with unwrap in tests) and cargo test (2 pass). I did not re-run gate.sh; I relied on the stated pass. No crypto or secret code is involved.

## F002-errors-secrets: Error type and secret containers

Merged 2026-11-06 after 1 attempt(s), $0.24. Evaluator: Adds the Error enum (identical to architecture.md, fixed-string Display, std::error::Error, Result alias) and SecretString/SecretVec/SecretBytes<N> secret containers. Each derives Zeroize+ZeroizeOnDrop, has a manual redacted Debug, and has no Display, Serialize or Clone. Only the zeroize dependency was added (derive feature). The new Cargo.lock entries are zeroize_derive and its proc-macro dependencies. I ran cargo test and all 8 core tests pass. No blocker or major findings.

## F003-rng: OS randomness and unbiased uniform sampling

Merged 2026-11-06 after 1 attempt(s), $0.26. Evaluator: Adds rng module: fill_random, random_array::<N>, uniform(n) over an internal RandomSource trait whose only implementation is OsSource (getrandom::fill, errors mapped to Error::Rng). uniform uses from_be_bytes on 8 bytes and threshold n.wrapping_neg() % n exactly as architecture.md says; a width-generic reject_sample helper is tested with an exhaustive 8-bit source. Only getrandom was added (it is in approved-deps). I ran cargo test -p onlypassword-core: 17 passed. I read the diff and found no other randomness source, no unwrap/panic in non-test code, and no unsafe. Only minor test-quality notes remain.
