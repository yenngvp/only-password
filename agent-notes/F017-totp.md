# F017-totp

Added `crates/onlypassword-core/src/totp.rs`: `hotp`, `totp`, `totp_for_item`, re-exported from lib.rs.
Dependencies added (both in approved-deps): `hmac 0.13`, `sha1 0.11` (default features).

- `parse_totp_secret` / `normalize_totp_secret` already lived in `base32` (F004); reused.
- `hotp`/`totp` reject secrets outside 10..=128 bytes, digits outside 6..=8 and period outside 1..=300 with `InvalidInput` (the RFC 4226 vectors use 20-byte seeds, so the minimum does not conflict).
- `totp_for_item` parses the stored base32 via `parse_totp_secret` (tolerant parse, not canonical-form check; `Item::validate` enforces canonical form).
- No clock access; `T = unix_secs / period`.
- `pub(crate) hmac()` is the single HMAC helper (tag is `Zeroizing`); the HMAC KATs (hmac-sha1/sha2 vectors) test it directly, so they accept keys of any length.
- All KATs load from spec/vectors at test time. No spec issues.
