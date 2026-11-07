# F026-core-keyfile

Added `onlypassword_core::keyfile` (`read`, `write_new`, `ct_eq`) and `Vault::create_with_key_file`
(src/keyfile.rs, tests in src/keyfile/tests.rs). The CLI keeps its own keyfile module.

- `read` goes through a private `read_from<R: Read>` seam (a `take(4097)` bounded reader); tests use an
  endless reader to show the read is bounded.
- `write_new`: `create_new`, 0600 on unix, text + `\n`, `sync_all`, file removed if write/sync fails.
  Symlinks (dangling or not) fail with Io(AlreadyExists) because O_EXCL does not follow them.
- `create_with_key_file`: password check first (so a short password leaves no key file), then
  existence checks with `symlink_metadata` (dangling symlinks count as existing) -> Io(AlreadyExists);
  equal paths -> InvalidInput; key written, read back, compared with `ct_eq`, then `create_with_key`.
  The key file is removed on any later failure (including KDF bound errors).
- Decision: the equal-path check comes after the existence checks, so equal paths that already exist
  report AlreadyExists; equal non-existent paths report InvalidInput.
- The unwritable-directory test returns early when the process ignores file modes (root).
