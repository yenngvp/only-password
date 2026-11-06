# F008-item-model

Built `core::item`: `Item`, `ItemKind`, `TotpConfig`, `TotpAlgorithm`, `CustomField`, `ItemId`
(hex Display/FromStr, `generate()`), `Item::validate`, `Item::to_plaintext`, `Item::from_plaintext`.
Added `serde` (derive) and `serde_json` to core dependencies (both approved).

Decisions the spec left open:
- The plaintext holds `created_ms`/`updated_ms` but `Item` (per architecture) does not, so
  `to_plaintext(&self, created_ms, updated_ms)` takes them and `from_plaintext(bytes)` returns
  `(Item, created_ms, updated_ms)`. `updated_ms < created_ms` is `InvalidInput` on write, `Corrupt` on read.
- The caller must still compare the record's `item_schema` with 1 (CS §7); the item layer only sees the JSON.
- Over-1-MiB input to `from_plaintext` is `InvalidInput` (checked first). A serialized item over the limit
  returns `LimitExceeded` (matches the `Vault::update` wording in architecture.md).
- Schema probe uses `i64`, so `-1` is `UnsupportedVersion`; floats, strings and out-of-range ints are `Corrupt`.
- Rule violations found after the strict parse (lengths, kind rules, TOTP ranges/canonical secret) map to `Corrupt`.
- Wire types are private; secrets are read straight into `SecretString` (`Sec` wrapper) to avoid extra copies.
  Nullable keys use `deserialize_with = "required"`, which makes an absent key an error (tested per key).
- `Item` does not derive `ZeroizeOnDrop` itself: its secret members (`SecretString`) wipe on drop; title,
  username, URLs and field names are non-secret per architecture.md. `Item`/`SecretString` have no `Clone`/`PartialEq`.
