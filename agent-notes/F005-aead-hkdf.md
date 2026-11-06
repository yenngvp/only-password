# F005-aead-hkdf

Built `crypto::aead` and `crypto::hkdf` in `onlypassword-core`, plus `src/testutil.rs`
(cfg(test) helper that loads `spec/vectors/*.json` via CARGO_MANIFEST_DIR, own hex decoder).

- `aead`: `AeadKey` (redacted Debug), `seal(key, ad, pt) -> Sealed{nonce, ciphertext_and_tag}`,
  `open(key, &nonce, ad, ct) -> SecretVec`. All open failures (including too-short input) are
  `Error::Authentication`. The deterministic-nonce path exists only under `cfg(test)`.
- `hkdf`: `extract_expand(salt, ikm, info)`, `expand(prk, info)` (both 32-byte output), and the
  four INFO_* label constants from CS §3.5. Variable-length expand is private (used by the
  RFC 5869 KAT, which has L=42/82).
- Decisions: helper is a unit-test module (not tests/common) because the nonce-fixing path is
  cfg(test)-only; later integration tests needing vectors will need their own copy or a move.
  hchacha20.json is not exercised (informational, per the acceptance text).
- Deps added: chacha20poly1305, hkdf, sha2; dev: serde_json.
