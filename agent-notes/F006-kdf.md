# F006-kdf

Built `crypto::kdf`: `KdfParams` (DEFAULT, MIN, FAST_FOR_TESTS under cfg, `validate`, `validate_strict`),
`normalize_password` (NFKC -> UTF-8, returns SecretVec, no length check), `check_new_password`
(>= 8 scalars after NFKC; creation paths only), `argon2id(password, &salt16, &params) -> SecretBytes<32>`.

- Validation runs before Argon2 allocates anything; failures are `InvalidInput` with fixed text.
- Argon2 0.6 with features `alloc`, `zeroize`; no `parallel`. Plain (no secret/AD) context in production;
  the KAT builds its own context with secret and AD (test only).
- Choice: `argon2id` takes `&KdfParams` and calls `validate()` (so the fast floor applies under the test cfg).
  Callers handling real files must additionally call `validate_strict()` per CS §9 step 6 if they want the real floor
  regardless of cfg (the file-open feature should do so).
- Note: `argon2id` has a small unneeded `build` closure parameter in the private `derive`; harmless.
- Tests using DEFAULT take a few seconds in debug builds.
