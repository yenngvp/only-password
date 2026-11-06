# F014-vault-rekey

`vault.rs`: `Vault::{change_master_password, rotate_vault_key, change_master_password_and_rotate_key}`,
all through one private `rekey`. Tests: `vault/rekey_tests.rs`.

- Signatures (spec left them open): the Vault does not keep the MK or SK, so every op takes
  `current_password: &SecretString, key: &SecretKey`; the password ops add `new_password, new_params`.
  `rotate_vault_key(current_password, key)` re-wraps under the current MK (same salt/params, new nonce).
- Order: new password (8 scalars) and new params validated first (before any Argon2), then current
  password/key verified by derive + unwrap (also compared with the in-memory VK) -> `Authentication`.
- Atomicity: the full image is built and re-parsed, then `persist` writes; `self.file/vk/k_iw` are replaced
  only after the write succeeds. `persist` has a cfg(test) thread-local `FAIL_WRITE` for deterministic failure injection.
- Rotation opens each record with the old K_iw and re-seals with `seal::seal_item` (new IK, nonces;
  same revision, created_ms, updated_ms). vault_id and SK unchanged.
- Doc test greps `vault.rs` source for the doc of `change_master_password`.
