# F011-storage

Added `crates/onlypassword-core/src/storage.rs`: `write_atomic`, `create_new_atomic`,
`read_bounded(path, max: u64)`, `same_file_path(a, b) -> Result<bool>`; `tempfile` dev-dependency
(Cargo.lock updated).

Decisions:
- Test hook: `pub(crate) create_new_atomic_with(path, bytes, &dyn Fn(&Path) -> Result<()>)`; an Err
  from the hook aborts before the link (simulated crash) and the temp file is removed.
- Temp name: `.<name>.<pid>.<counter>.<nanos>.tmp`, retried on AlreadyExists.
- Only symlinks are canonicalized in `write_atomic`; a dangling symlink returns Io.
- The unwritable-directory test accepts success when run as root (permissions bypassed); on error it
  asserts the target is unchanged. No temp file remains either way.
- `read_bounded` checks metadata length first, then reads with `take(max+1)` to guard growth.
