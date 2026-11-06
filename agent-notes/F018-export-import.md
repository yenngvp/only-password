# F018-export-import

`vault/export.rs`: `Vault::export(&self, path, export_password, &SecretKey, KdfParams)` and
`Vault::import(&mut self, path, export_password, &SecretKey) -> Result<usize>` (item count). Tests: `vault/export_tests.rs`.
Also `format::MAX_EXPORT_PLAINTEXT`; `item.rs` exposes `wire_out`, `from_wire`, `Probe`, `WireIn/WireOut`, `CountingWriter` as pub(crate).

- Signatures were open: export takes the SK explicitly (the Vault does not hold it); import returns the number imported.
- Export order: password minimum, params, same-file check (all before Argon2), then payload size check (LimitExceeded), then seal and `write_atomic`.
- Import follows CS 9 export table. Payload read in passes: `export_schema` probe, items' `schema` probe (-> UnsupportedVersion), strict pass 2 (Corrupt). Item rule violations are Corrupt.
- Import seals all items once, merges, then `commit` (single write, record/size limits -> LimitExceeded). Count limit is also checked before sealing.
- Test seams: `MAX_PAYLOAD` thread-local (cfg(test)) lowers MAX_EXPORT_PLAINTEXT; the existing `LIMITS` lowers the item count. `seal_export` is pub(super) so tests seal hand-built payloads (schema 2, revision u64::MAX).
- Root Cargo.toml: added `[profile.dev.package.argon2/blake2] opt-level = 3`, because the every-offset flip test was ~70 s unoptimized (now ~4 s).
- KDF-bound violations in an export header map to Corrupt (KdfParams::validate returns InvalidInput; remapped).
