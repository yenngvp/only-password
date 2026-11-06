# F002-errors-secrets
- `error.rs`: `Error` exactly as architecture.md §2; Display prints fixed strings and never the
  `Corrupt`/`InvalidInput` text or the io kind (decision: payloads are for Debug/callers only).
- `secret.rs`: `SecretString`, `SecretVec`, `SecretBytes<N>`; derive `Zeroize`+`ZeroizeOnDrop`,
  manual redacted `Debug`, no Display/Serialize/Clone. `expose()` accessors.
  Spec sketches `SecretString(Zeroizing<String>)`; I used a plain `String` field with the derive
  (equivalent, and gives `ZeroizeOnDrop` directly).
- Only dependency added: `zeroize` (feature `derive`). Cargo.lock updated.
- `SecretKey` is not here (belongs to the crypto/keys feature).
