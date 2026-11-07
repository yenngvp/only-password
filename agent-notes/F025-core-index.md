# F025-core-index

Built `ItemIndex` (`vault/index.rs`) and `Vault::index()`; re-exported `ItemIndex` at the crate root.

- Index is built in `from_parts` (create and unlock): one decryption pass.
- add/update/delete/import derive the new index from the old one plus the data just sealed
  (no extra decryption); `commit_with_index` replaces file and index only after `persist` succeeds.
- Rekey operations (change_master_password, rotate_vault_key, both) leave the index value
  unchanged because titles/usernames/URLs/revisions/updated_ms do not change; it is not touched
  unless the write succeeds (nothing to replace). Decision: no rebuild there.
- `ItemIndex` Debug is `ItemIndex { .. }`; Drop zeroizes title/username/urls (`wipe_strings`).
- `Vault::decrypt_count()` (test-hooks or cfg(test)) counts `open_at` plus the rekey re-seal decryptions.
- Test-only `commit(records)` helper kept so existing pilot tests compile unchanged; it skips
  records that do not decrypt.
- The "storage failure hook" (FAIL_WRITE) is cfg(test) thread-local, so the failure tests are unit
  tests in `vault/index_tests.rs`.
