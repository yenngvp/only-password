# Progress

Written by the pipeline driver. One entry per feature that reached main.

## F001-workspace: Cargo workspace and gate baseline

Merged 2026-11-06 after 1 attempt(s), $0.14. Evaluator: Adds a virtual workspace (resolver 2) with onlypassword-core (lib, non-default features insecure-fast-kdf and test-hooks) and onlypassword-cli (bin 'onlypassword'). It declares no dependencies, carries forbid(unsafe_code) and the cfg_attr clippy denies in both crate roots, and has one trivial test per crate and a committed Cargo.lock. I ran cargo build (produces target/debug/onlypassword), cargo clippy --all-targets -- -D warnings (clean, with unwrap in tests) and cargo test (2 pass). I did not re-run gate.sh; I relied on the stated pass. No crypto or secret code is involved.

## F002-errors-secrets: Error type and secret containers

Merged 2026-11-06 after 1 attempt(s), $0.24. Evaluator: Adds the Error enum (identical to architecture.md, fixed-string Display, std::error::Error, Result alias) and SecretString/SecretVec/SecretBytes<N> secret containers. Each derives Zeroize+ZeroizeOnDrop, has a manual redacted Debug, and has no Display, Serialize or Clone. Only the zeroize dependency was added (derive feature). The new Cargo.lock entries are zeroize_derive and its proc-macro dependencies. I ran cargo test and all 8 core tests pass. No blocker or major findings.

## F003-rng: OS randomness and unbiased uniform sampling

Merged 2026-11-06 after 1 attempt(s), $0.26. Evaluator: Adds rng module: fill_random, random_array::<N>, uniform(n) over an internal RandomSource trait whose only implementation is OsSource (getrandom::fill, errors mapped to Error::Rng). uniform uses from_be_bytes on 8 bytes and threshold n.wrapping_neg() % n exactly as architecture.md says; a width-generic reject_sample helper is tested with an exhaustive 8-bit source. Only getrandom was added (it is in approved-deps). I ran cargo test -p onlypassword-core: 17 passed. I read the diff and found no other randomness source, no unwrap/panic in non-test code, and no unsafe. Only minor test-quality notes remain.

## F004-base32: Base32 codec

Merged 2026-11-06 after 1 attempt(s), $0.38. Evaluator: Adds onlypassword_core::base32 with encode (unpadded upper case), tolerant decode, decode_strict (rejects non-zero trailing bits), parse_totp_secret (10..=128 bytes), normalize_totp_secret and a lower-case strict hex codec. Errors are InvalidInput with a fixed message, there is no panic path in non-test code, and no dependency was added. I ran the 9 base32 tests and they pass. Every acceptance criterion has a test that can fail. Findings are minor only.

## F005-aead-hkdf: AEAD and HKDF primitives with known-answer tests

Merged 2026-11-06 after 1 attempt(s), $0.37. Evaluator: Adds crypto::aead (XChaCha20-Poly1305 via the approved crate, random 24-byte nonce per seal, AD argument, open maps every failure to Error::Authentication and returns a SecretVec), crypto::hkdf (extract+expand and expand-from-PRK, fixed 32-byte output, exact INFO labels matching CS §3.5) and a cfg(test) vector-loading helper with its own hex decoder. I ran cargo test (41 passed, including xchacha_kat, chacha_rfc8439_kat, rfc5869_kat, every_bit_flip_fails, nonces_differ_between_calls, the testutil missing/empty tests). KATs load spec/vectors via CARGO_MANIFEST_DIR; the deterministic-nonce path is private/cfg(test) only. Dependencies are all in approved-deps.txt. No blocker or major issues; only minor notes.
