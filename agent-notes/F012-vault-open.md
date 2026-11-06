# F012-vault-open

`crates/onlypassword-core/src/vault.rs` (+ `vault/tests.rs`): `Clock`, `SystemClock`, `Vault`
(create, create_with_key, unlock, lock, kdf_params, set_clock under cfg(test)/test-hooks).

- Creation checks: `check_new_password` (8 scalars after NFKC), then `KdfParams::validate()` (floor is
  FAST under cfg(test)/insecure-fast-kdf, else the real MIN), both before any disk access.
- Private `create_inner(.., hook)` skips the password check and passes a hook to
  `storage::create_new_atomic_with`; tests use it for the "short password" seam, the race and the crash.
- `unlock` parses once to read the header KDF params, derives MK, then `seal::open_vault` (parses again,
  unwraps VK, verifies trailer). No password minimum. Wrong password/key -> `Authentication`.
- `Vault` keeps path, parsed `VaultFile`, VK, K_iw, K_fa, clock; key types are ZeroizeOnDrop so dropping
  (`lock(self)`) zeroizes. Debug prints `Vault { .. }`. Fields are `allow(dead_code)` until item ops land.
- The in-memory `VaultFile` is the parsed image; later features that mutate must keep it in sync.
