# F010-seal

`crates/onlypassword-core/src/seal.rs` (+ `seal/tests.rs`), `pub mod seal` in lib.rs.

- `wrap_vk(mk, vk, vault_id, kdf, kdf_salt) -> Header` (fresh `vk_nonce`; the nonce is part of
  AD_VK so `aead::seal_with_nonce` was made `pub(crate)`), `unwrap_vk(mk, &Header)`.
- `seal_item(k_iw, vault_id, item_id, revision, item, created_ms, updated_ms) -> Record`;
  fresh IK and nonces each call; revision 0 is `InvalidInput`.
- `compute_trailer` / `verify_trailer` / `build_image(header, records, vk)`.
- `open_vault(bytes, mk) -> OpenedVault`: parse, unwrap VK, verify trailer. Records can only be
  opened via `OpenedVault::open_item`, so "trailer before any decrypt" is enforced by types.
  `open_vault` takes an already derived MK (deriving it from the header is the vault layer's job).
- open_item: AEAD failure (incl. changed `item_schema`) -> Authentication; then
  `Item::from_plaintext` (JSON schema != 1 -> UnsupportedVersion); record schema != 1 -> Corrupt.
- `seal_record` (pub(crate)) takes an explicit item_schema so tests can seal mismatches.
- `compute_trailer` keeps no cap on revision overflow; `u64::MAX` update check belongs to the vault layer.
- Timestamps are passed through seal_item/open_item (item.rs keeps them outside `Item`).
