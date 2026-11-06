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

## F006-kdf: Argon2id key derivation and parameters

Merged 2026-11-06 after 1 attempt(s), $0.33. Evaluator: Adds crypto::kdf with KdfParams (DEFAULT/MIN/cfg-gated FAST_FOR_TESTS, validate, validate_strict), NFKC password normalization returning a zeroizing SecretVec, a separate creation-path length check counted after NFKC, and argon2id() using Argon2id v0x13 with no secret/AD, 32-byte output wrapped in SecretBytes. Params are validated before Argon2 allocates. argon2 (alloc, zeroize; no parallel) and unicode-normalization are on the approved list. I ran the kdf tests with --all-features (13 pass) and a plain build; code matches CS 3.1, 3.3 and 10. No blocker or major findings.

## F007-keys: Secret key and key hierarchy

Merged 2026-11-06 after 1 attempt(s), $0.36. Evaluator: Adds crypto::keys with SecretKey (generate/to_text/from_text/from_key_file_text), MasterKey::derive (Argon2id then HKDF extract+expand, salt=kdf_salt, IKM=pw_key||SK, INFO_MK), VaultKey/ItemKey, and K_iw/K_fa via HKDF-Expand. It matches CS 3.2-3.5. Key types derive Zeroize/ZeroizeOnDrop, have redacted Debug, and are not Clone/Copy. Parsing is panic-free (uses str::get, no indexing) and every failure is InvalidInput. I ran the 11 keys/hkdf tests and all pass. The independent-recompute tests use the argon2 and hkdf crates directly with literal label strings.

## F008-item-model: Item model and versioned serialization

Merged 2026-11-06 after 2 attempt(s), $0.82. Evaluator: Adds core::item: Item/ItemKind/TotpConfig/TotpAlgorithm/CustomField/ItemId, validate(), compact fixed-order schema-1 serialization into a Zeroizing<Vec> with exact preallocation (counting-writer pass), and two-pass reading (i64 schema probe without deny_unknown_fields, then strict deny_unknown_fields structs with deserialize_with 'required' for username/password/totp, no default/flatten). serde and serde_json are in approved-deps. I ran `cargo test -p onlypassword-core item`: 14/14 pass. By reading, the tests assert exact bytes, per-key missing rows (including the three nullable keys absent), duplicates at top level/totp/fields entry, schema 0/2 with unknown fields, canonical TOTP secret cases and Debug redaction. No blocker or major issues found; two spec-deviation notes the owner should see (LimitExceeded on oversize write; to_plaintext/from_plaintext carrying timestamps) are recorded in agent-notes/spec-issues.md.

## F009-format-codec: Vault file byte codec

Merged 2026-11-06 after 1 attempt(s), $0.39. Evaluator: Adds crates/onlypassword-core/src/format.rs: a key-free VaultFile parse/serialize codec using a bounds-checked Reader (checked_add, slice get, try_into; no indexing or unwrap in non-test code). Parse follows CS 9 steps 1-7 in order (length incl. LimitExceeded over 512 MiB, magic, version, flags, kdf id/version, KdfParams::validate mapped to Corrupt, structure). The record_count is bounded by remaining/146 before Vec::with_capacity, so no allocation is fed an untrusted count; body_ct is copied only after record_len and body_ct_len are verified against remaining bytes. Strict ascending ids, trailing bytes and trailer position are checked. I ran `cargo test --all-features format`: 12/12 pass. The tests use a hand-built image from the spec offsets (independent of serialize), and cover versions, flags, magic, KDF bounds, multi-fault ordering, record_count/record_len extremes, truncation at every length, and oversize input. No new deps; only a pub mod line added to lib.rs. Minor gaps only.

## F010-seal: Sealing: header wrap, item records, file trailer

Merged 2026-11-06 after 1 attempt(s), $0.59. Evaluator: Adds crates/onlypassword-core/src/seal.rs: wrap_vk/unwrap_vk (AD_VK = label || 82-byte header prefix), seal_item/open_record (fresh IK, nonces, AD_IK/AD_BODY per CS 6.3), compute/verify_trailer (AEAD over SHA-256 of file prefix with K_fa, CS 6.4), build_image, and open_vault. Records can only be opened through OpenedVault, which open_vault constructs only after unwrap and trailer verification, so no record is decrypted before the trailer passes. Labels, field order and widths match the spec by reading, and the independent-AD test confirms them with the chacha20poly1305 crate directly. Error ordering matches CS 9 steps 8-12: the AEAD failure comes first, then JSON schema != 1 gives UnsupportedVersion, then a record/JSON schema mismatch gives Corrupt. I ran cargo test (all 95 core tests plus the others pass, including the 9 seal tests) and cargo clippy --all-targets (clean). Only minor issues remain.
