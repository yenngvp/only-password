use super::*;
use std::io::ErrorKind;

const P: KdfParams = KdfParams::FAST_FOR_TESTS;

fn pw(s: &str) -> SecretString {
    SecretString::new(s.to_string())
}

fn names(d: &Path) -> Vec<String> {
    let mut v: Vec<_> = std::fs::read_dir(d)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn read_bytes(b: &[u8]) -> Result<SecretKey> {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("k");
    std::fs::write(&p, b).unwrap();
    read(&p)
}

fn is_invalid<T>(r: Result<T>) -> bool {
    matches!(r, Err(Error::InvalidInput(_)))
}

#[test]
fn read_accepts_whitespace_and_dashes() {
    let k = SecretKey::generate().unwrap();
    let t = k.to_text();
    let t = t.expose();
    assert!(t.contains('-'));
    let spaced = format!("OPSK1-{}", t[6..].replace('-', " "));
    for form in [
        t.to_string(),
        format!("{t}\n"),
        format!("{t}\r\n"),
        format!(" \t {t} \t\r\n"),
        spaced,
    ] {
        assert_eq!(read_bytes(form.as_bytes()).unwrap().expose(), k.expose());
    }
}

#[test]
fn read_rejects_bad_content() {
    let k = SecretKey::generate().unwrap();
    let t = k.to_text();
    let t = t.expose().to_string();
    let wrong_prefix = t.replacen("OPSK1", "OPSK2", 1);
    let short = &t[..t.len() - 1];
    let long = format!("{t}A");
    let bad_char = format!("{}1", &t[..t.len() - 1]);
    for b in [
        wrong_prefix.as_bytes(),
        short.as_bytes(),
        long.as_bytes(),
        bad_char.as_bytes(),
        b"",
        b"   \n",
        b"\xff\xfe",
    ] {
        assert!(is_invalid(read_bytes(b)));
    }
    let mut nz = t.clone();
    nz.pop();
    nz.push('7'); // 7 = 11111, trailing bits non-zero
    assert!(is_invalid(read_bytes(nz.as_bytes())));
}

#[test]
fn read_missing_file_is_io() {
    let d = tempfile::tempdir().unwrap();
    assert_eq!(
        read(&d.path().join("none")).err(),
        Some(Error::Io(ErrorKind::NotFound))
    );
}

/// A reader that counts bytes served and fails the test if more than the limit is pulled.
struct Counting<'a>(&'a std::cell::Cell<u64>);
impl Read for Counting<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.set(self.0.get() + buf.len() as u64);
        buf.fill(b'A');
        Ok(buf.len())
    }
}

#[test]
fn oversize_reader_is_bounded() {
    let served = std::cell::Cell::new(0);
    assert!(is_invalid(read_from(Counting(&served))));
    // Only a bounded prefix (limit + 1, plus read-buffer slack) is requested from an endless source.
    assert!(served.get() <= 4097 + 8192, "served {}", served.get());
}

#[test]
fn exact_limit_and_one_over() {
    let mut ok_len = vec![b' '; 4096];
    let k = SecretKey::generate().unwrap();
    let t = k.to_text();
    ok_len[..t.expose().len()].copy_from_slice(t.expose().as_bytes());
    assert_eq!(read_bytes(&ok_len).unwrap().expose(), k.expose());
    ok_len.push(b' ');
    assert!(is_invalid(read_bytes(&ok_len)));
}

#[test]
fn write_new_round_trip_and_mode() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("k.key");
    let k = SecretKey::generate().unwrap();
    write_new(&p, &k).unwrap();
    assert_eq!(read(&p).unwrap().expose(), k.expose());
    let raw = std::fs::read_to_string(&p).unwrap();
    assert_eq!(raw, format!("{}\n", k.to_text().expose()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn write_new_existing_file_untouched() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("k.key");
    std::fs::write(&p, b"precious").unwrap();
    let k = SecretKey::generate().unwrap();
    assert_eq!(write_new(&p, &k), Err(Error::Io(ErrorKind::AlreadyExists)));
    assert_eq!(std::fs::read(&p).unwrap(), b"precious");
}

#[cfg(unix)]
#[test]
fn write_new_symlinks_fail_and_create_nothing() {
    use std::os::unix::fs::symlink;
    let d = tempfile::tempdir().unwrap();
    let k = SecretKey::generate().unwrap();
    // Dangling.
    let target = d.path().join("target");
    let link = d.path().join("dangling");
    symlink(&target, &link).unwrap();
    assert_eq!(
        write_new(&link, &k),
        Err(Error::Io(ErrorKind::AlreadyExists))
    );
    assert!(!target.exists());
    // To an existing file.
    let real = d.path().join("real");
    std::fs::write(&real, b"keep").unwrap();
    let link2 = d.path().join("live");
    symlink(&real, &link2).unwrap();
    assert_eq!(
        write_new(&link2, &k),
        Err(Error::Io(ErrorKind::AlreadyExists))
    );
    assert_eq!(std::fs::read(&real).unwrap(), b"keep");
}

#[test]
fn write_new_missing_dir_is_io() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("nodir").join("k");
    assert!(matches!(
        write_new(&p, &SecretKey::generate().unwrap()),
        Err(Error::Io(_))
    ));
    assert!(names(d.path()).is_empty());
}

#[test]
fn ct_eq_works() {
    let a = [7u8; 32];
    let mut b = a;
    assert!(ct_eq(&a, &b));
    b[31] ^= 1;
    assert!(!ct_eq(&a, &b));
}

#[test]
fn create_success_and_unlock_again() {
    let d = tempfile::tempdir().unwrap();
    let (vp, kp) = (d.path().join("v.opv"), d.path().join("k.key"));
    let v = Vault::create_with_key_file(&vp, &kp, &pw("correct horse"), P).unwrap();
    assert!(v.list().unwrap().is_empty());
    v.lock();
    let key = read(&kp).unwrap();
    Vault::unlock(&vp, &pw("correct horse"), &key).unwrap();
    assert_eq!(names(d.path()), ["k.key", "v.opv"]);
}

#[test]
fn create_precondition_failures_leave_nothing() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path();
    let (vp, kp) = (p.join("v.opv"), p.join("k.key"));
    // key path exists
    std::fs::write(&kp, b"old-key").unwrap();
    assert!(Vault::create_with_key_file(&vp, &kp, &pw("correct horse"), P).is_err());
    assert_eq!(std::fs::read(&kp).unwrap(), b"old-key");
    assert_eq!(names(p), ["k.key"]);
    std::fs::remove_file(&kp).unwrap();
    // vault path exists
    std::fs::write(&vp, b"old-vault").unwrap();
    assert!(Vault::create_with_key_file(&vp, &kp, &pw("correct horse"), P).is_err());
    assert_eq!(std::fs::read(&vp).unwrap(), b"old-vault");
    assert_eq!(names(p), ["v.opv"]);
    std::fs::remove_file(&vp).unwrap();
    // equal paths
    let same = p.join("same");
    assert!(Vault::create_with_key_file(&same, &same, &pw("correct horse"), P).is_err());
    assert!(names(p).is_empty());
    // key dir missing
    let kp2 = p.join("nodir").join("k");
    assert!(Vault::create_with_key_file(&vp, &kp2, &pw("correct horse"), P).is_err());
    assert!(names(p).is_empty());
    // short password
    assert_eq!(
        Vault::create_with_key_file(&vp, &kp, &pw("short"), P).err(),
        Some(Error::InvalidInput("password too short"))
    );
    assert!(names(p).is_empty());
}

#[cfg(unix)]
#[test]
fn unwritable_vault_dir_removes_key_file() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let vdir = d.path().join("vdir");
    let kdir = d.path().join("kdir");
    std::fs::create_dir(&vdir).unwrap();
    std::fs::create_dir(&kdir).unwrap();
    std::fs::set_permissions(&vdir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let probe = vdir.join("probe");
    if std::fs::write(&probe, b"x").is_ok() {
        // Running with privileges that ignore modes (root): the injection is impossible.
        std::fs::remove_file(&probe).unwrap();
        std::fs::set_permissions(&vdir, std::fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    let r = Vault::create_with_key_file(
        &vdir.join("v.opv"),
        &kdir.join("k.key"),
        &pw("correct horse"),
        P,
    );
    std::fs::set_permissions(&vdir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(r, Err(Error::Io(_))));
    assert!(names(&kdir).is_empty());
    assert!(names(&vdir).is_empty());
}

#[test]
fn errors_do_not_leak_key_or_paths() {
    let d = tempfile::tempdir().unwrap();
    let sentinel = "sentinel-dir-xyz";
    let dir = d.path().join(sentinel);
    std::fs::create_dir(&dir).unwrap();
    let kp = dir.join("k.key");
    let key = SecretKey::generate().unwrap();
    write_new(&kp, &key).unwrap();
    let text = key.to_text();
    let bare = text.expose().trim_start_matches("OPSK1-").to_string();
    let errs = [
        write_new(&kp, &key).unwrap_err(),
        read(&dir.join("missing")).unwrap_err(),
        read_bytes(format!("{}A", text.expose()).as_bytes()).unwrap_err(),
        Vault::create_with_key_file(&dir.join("v"), &kp, &pw("correct horse"), P).unwrap_err(),
        Vault::create_with_key_file(&dir.join("v"), &dir.join("n"), &pw("x"), P).unwrap_err(),
    ];
    for e in errs {
        for s in [format!("{e:?}"), e.to_string()] {
            assert!(!s.contains(sentinel) && !s.contains(&bare) && !s.contains("k.key"));
        }
    }
}
