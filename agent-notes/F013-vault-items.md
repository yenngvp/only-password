# F013-vault-items

`vault.rs`: `Vault::{add, get, update, delete, list, search}`, `StoredItem`, `ItemSummary` (re-exported).
Tests in `vault/item_tests.rs`.

- Every mutation clones the record list, edits it, `seal::build_image`, checks count/size limits,
  parses the image, `storage::write_atomic`, and only then replaces `self.file`.
- Limits: `max_records()/max_image()` in vault.rs; under cfg(test) they read a thread-local `LIMITS`
  so tests can lower them. Production uses `format::MAX_RECORDS` / `MAX_VAULT_FILE`.
- update: revision overflow -> LimitExceeded before sealing; updated_ms = max(now, created_ms).
  Unknown id is checked before item validation (NotFound wins).
- `ItemSummary` has id, kind, title, username, urls, revision, updated_ms (no secrets).
- `seal::open_record` made `pub(crate)`; `Vault` no longer stores `k_fa` (derived inside build_image).
- list/search decrypt every record (O(n)); fine for now.
- Added a `FileAuthKey` import to existing vault/tests.rs (needed since `super::*` no longer brings it).
- The revision u64::MAX path is untested here (per acceptance; F018).
