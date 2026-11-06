# F022-robustness

Tests only; no production code changed (no panic or unbounded allocation was found).

- `crates/onlypassword-core/tests/robustness.rs` (integration, public API, xorshift in the test):
  every truncation, bit flips (bits 0 and 7 of every byte), 2000 seeded mutations (flip, insert,
  delete, 4-byte zero / 0xFFFFFFFF, 8-byte 0xFF) for vault and export; 2000 garbage buffers
  (0..=4096) and magic/header-prefixed buffers; 5000 random strings (+1 MiB inputs) for
  `SecretKey::from_text`, `from_key_file_text`, `parse_totp_secret`, `ItemId::from_str`;
  huge declared `record_count`/`record_len`/`ct_len`/KDF params on inputs < 1 KiB; hostile generator
  and TOTP options. Every unlock/import is timed (< 5 s); `Ok` must equal the original plaintext, and
  a failed import must leave the target vault file byte-identical.
- `src/vault/robustness_tests.rs` (unit): bodies sealed with `seal::seal_record` so the AEAD is valid:
  invalid JSON / unknown field -> `Corrupt`; schema 2 (also with unknown field) -> `UnsupportedVersion`;
  absent nullable key -> `Corrupt`.
- Decision: `Cargo.toml` gets a self dev-dependency (`onlypassword-core` path, feature
  `insecure-fast-kdf`) so `KdfParams::FAST_FOR_TESTS` exists for integration tests even without
  `--all-features`. It is a path dependency, so the gate's approved-deps check ignores it.
- "Memory-bounded" is shown by completing on < 1 KiB inputs (no custom allocator: it needs `unsafe`).
- The suite takes ~50 s (Argon2 per attempt, optimised via the root profile).
