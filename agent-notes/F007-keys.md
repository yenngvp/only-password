# F007-keys

Added `crypto::keys`: `SecretKey`, `MasterKey`, `VaultKey`, `ItemKey`, `ItemWrapKey` (K_iw), `FileAuthKey` (K_fa).
Each wraps `SecretBytes<32>`, derives Zeroize+ZeroizeOnDrop, has a redacted Debug, no Clone/Copy.

- `SecretKey::to_text` returns a `SecretString`; `from_text`/`from_key_file_text` per CS 3.2. Spaces and `-` are ignored only
  *after* the `OPSK1-` prefix; the prefix is matched case-insensitively. Characters are validated by this module
  (so `=` is rejected) and then `base32::decode_strict` checks trailing bits.
- `MasterKey::derive(password_bytes, kdf_salt, params, sk)` takes already NFKC-normalized bytes (`kdf::normalize_password`).
  Salt is `&[u8;16]` (as in `kdf::argon2id`). Tested against an independent argon2+hkdf computation.
- `VaultKey::{item_wrap_key, file_auth_key}` use `hkdf::expand` with VK as PRK.
- `from_secret(SecretBytes<32>)` is the constructor for unwrapped keys (VK/IK after AEAD open).
- No spec issues found.
