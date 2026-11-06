//! Atomic file storage (CS 6.6). Errors carry only an `io::ErrorKind`.

use crate::error::{Error, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn io(e: std::io::Error) -> Error {
    Error::Io(e.kind())
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Resolve a symlink target to the file it points to; other paths are unchanged.
fn resolve(path: &Path) -> Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => fs::canonicalize(path).map_err(io),
        _ => Ok(path.to_path_buf()),
    }
}

fn dir_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir).and_then(|d| d.sync_all()).map_err(io)
}
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

/// Write `bytes` to a fresh, uniquely named temp file next to `target`.
fn write_temp(target: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let dir = dir_of(target);
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    for _ in 0..64 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let tmp = dir.join(format!(
            ".{name}.{}.{n}.{nanos:08x}.tmp",
            std::process::id()
        ));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = match opts.open(&tmp) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(io(e)),
        };
        let r = f.write_all(bytes).and_then(|_| f.sync_all());
        drop(f);
        if let Err(e) = r {
            let _ = fs::remove_file(&tmp);
            return Err(io(e));
        }
        return Ok(tmp);
    }
    Err(Error::Io(std::io::ErrorKind::AlreadyExists))
}

/// Replace (or create) `path` atomically with `bytes`.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let target = resolve(path)?;
    let tmp = write_temp(&target, bytes)?;
    let r = fs::rename(&tmp, &target)
        .map_err(io)
        .and_then(|_| sync_dir(&dir_of(&target)));
    if r.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    r
}

/// Create a new file at `path`; fails if it already exists. Never uses rename.
pub fn create_new_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    create_new_atomic_with(path, bytes, &|_| Ok(()))
}

/// As `create_new_atomic`, with a hook run between the temp write and the link.
pub(crate) fn create_new_atomic_with(
    path: &Path,
    bytes: &[u8],
    hook: &dyn Fn(&Path) -> Result<()>,
) -> Result<()> {
    let tmp = write_temp(path, bytes)?;
    let r = hook(path).and_then(|_| fs::hard_link(&tmp, path).map_err(io));
    let removed = fs::remove_file(&tmp).map_err(io);
    r?;
    removed?;
    sync_dir(&dir_of(path))
}

/// Read a whole file, refusing files larger than `max` bytes.
pub fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let f = File::open(path).map_err(io)?;
    let len = f.metadata().map_err(io)?.len();
    if len > max {
        return Err(Error::LimitExceeded);
    }
    let mut buf = Vec::with_capacity(len.min(max) as usize);
    // Guard against growth after the metadata check.
    f.take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(io)?;
    if buf.len() as u64 > max {
        return Err(Error::LimitExceeded);
    }
    Ok(buf)
}

fn canon(p: &Path) -> Result<PathBuf> {
    match fs::canonicalize(p) {
        Ok(c) => Ok(c),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let name = p
                .file_name()
                .ok_or(Error::Io(std::io::ErrorKind::NotFound))?;
            Ok(fs::canonicalize(dir_of(p)).map_err(io)?.join(name))
        }
        Err(e) => Err(io(e)),
    }
}

/// True if both paths denote the same file (or the same not-yet-existing name).
pub fn same_file_path(a: &Path, b: &Path) -> Result<bool> {
    Ok(canon(a)? == canon(b)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    fn names(d: &Path) -> Vec<String> {
        let mut v: Vec<_> = fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn write_replaces_without_temp() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v");
        fs::write(&p, b"old").unwrap();
        write_atomic(&p, b"new").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"new");
        assert_eq!(names(d.path()), ["v"]);
    }

    #[test]
    fn rename_failure_cleans_up() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("dir");
        fs::create_dir(&p).unwrap();
        fs::write(p.join("x"), b"old").unwrap();
        assert!(matches!(write_atomic(&p, b"new"), Err(Error::Io(_))));
        assert_eq!(fs::read(p.join("x")).unwrap(), b"old");
        assert_eq!(names(d.path()), ["dir"]);
        assert_eq!(names(&p), ["x"]);
    }

    #[cfg(unix)]
    #[test]
    fn unwritable_dir_leaves_target() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v");
        fs::write(&p, b"old").unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let r = write_atomic(&p, b"new");
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        // Running as root bypasses permissions; the target must be unchanged on error.
        if r.is_err() {
            assert_eq!(fs::read(&p).unwrap(), b"old");
        } else {
            assert_eq!(fs::read(&p).unwrap(), b"new");
        }
        assert_eq!(names(d.path()), ["v"]);
    }

    #[cfg(unix)]
    #[test]
    fn modes_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a");
        write_atomic(&p, b"x").unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let q = d.path().join("b");
        create_new_atomic(&q, b"x").unwrap();
        assert_eq!(
            fs::metadata(&q).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn create_new_existing_fails_unchanged() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v");
        fs::write(&p, b"old").unwrap();
        assert_eq!(
            create_new_atomic(&p, b"new"),
            Err(Error::Io(ErrorKind::AlreadyExists))
        );
        assert_eq!(fs::read(&p).unwrap(), b"old");
        assert_eq!(names(d.path()), ["v"]);
    }

    #[test]
    fn create_new_creates() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v");
        create_new_atomic(&p, b"data").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"data");
        assert_eq!(names(d.path()), ["v"]);
    }

    #[test]
    fn hook_creating_target_wins() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v");
        let r = create_new_atomic_with(&p, b"new", &|t| fs::write(t, b"racer").map_err(io));
        assert!(matches!(r, Err(Error::Io(_))));
        assert_eq!(fs::read(&p).unwrap(), b"racer");
        assert_eq!(names(d.path()), ["v"]);
    }

    #[test]
    fn hook_abort_leaves_nothing() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v");
        let r = create_new_atomic_with(&p, b"new", &|_| Err(Error::Io(ErrorKind::Interrupted)));
        assert_eq!(r, Err(Error::Io(ErrorKind::Interrupted)));
        assert!(names(d.path()).is_empty());
    }

    #[test]
    fn read_bounded_limits() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v");
        fs::write(&p, vec![7u8; 100]).unwrap();
        assert_eq!(read_bounded(&p, 99), Err(Error::LimitExceeded));
        assert_eq!(read_bounded(&p, 100).unwrap().len(), 100);
        assert_eq!(
            read_bounded(&d.path().join("none"), 10),
            Err(Error::Io(ErrorKind::NotFound))
        );
    }

    #[test]
    fn io_error_has_kind_only() {
        let d = tempfile::tempdir().unwrap();
        let e = write_atomic(&d.path().join("no/such/v"), b"x").unwrap_err();
        assert_eq!(e, Error::Io(ErrorKind::NotFound));
        assert!(!format!("{e:?}{e}").contains("such"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_target_updated_in_place() {
        let d = tempfile::tempdir().unwrap();
        let sub = d.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let real = sub.join("real");
        fs::write(&real, b"old").unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        write_atomic(&link, b"new").unwrap();
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&real).unwrap(), b"new");
        assert_eq!(names(&sub), ["real"]);
        assert_eq!(names(d.path()), ["link", "sub"]);
    }

    #[test]
    fn same_file_path_cases() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v");
        fs::write(&p, b"x").unwrap();
        fs::create_dir(d.path().join("s")).unwrap();
        let dotted = d.path().join("s").join("..").join("v");
        assert!(same_file_path(&p, &dotted).unwrap());
        #[cfg(unix)]
        {
            let l = d.path().join("l");
            std::os::unix::fs::symlink(&p, &l).unwrap();
            assert!(same_file_path(&p, &l).unwrap());
        }
        let n1 = d.path().join("new");
        let n2 = d.path().join("s").join("..").join("new");
        assert!(same_file_path(&n1, &n2).unwrap());
        assert!(!same_file_path(&n1, &p).unwrap());
    }
}
