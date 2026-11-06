use super::*;
use crate::crypto::kdf::KdfParams;
use crate::format::{HEADER_LEN, MAGIC, TRAILER_LEN};
use crate::Error;
use std::cell::Cell;

const P: KdfParams = KdfParams::FAST_FOR_TESTS;

fn pw(s: &str) -> SecretString {
    SecretString::new(s.to_string())
}

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn create_then_unlock_and_layout() {
    let d = dir();
    let path = d.path().join("v.opv");
    let (v, sk) = Vault::create(&path, &pw("correct horse"), P).unwrap();
    v.lock();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[..8], &MAGIC);
    assert_eq!(bytes.len(), HEADER_LEN + 4 + TRAILER_LEN);
    assert_eq!(bytes.len(), 130 + 4 + 40);
    let v = Vault::unlock(&path, &pw("correct horse"), &sk).unwrap();
    assert_eq!(v.kdf_params(), P);
}

#[test]
fn create_with_same_key_unlocks() {
    let d = dir();
    let path = d.path().join("v.opv");
    let sk = SecretKey::generate().unwrap();
    let v = Vault::create_with_key(&path, &pw("password1"), P, &sk).unwrap();
    assert_eq!(v.kdf_params(), P);
    Vault::unlock(&path, &pw("password1"), &sk).unwrap();
}

#[test]
fn existing_path_is_untouched() {
    let d = dir();
    let path = d.path().join("v.opv");
    std::fs::write(&path, b"precious").unwrap();
    let sk = SecretKey::generate().unwrap();
    assert!(Vault::create_with_key(&path, &pw("password1"), P, &sk).is_err());
    assert!(Vault::create(&path, &pw("password1"), P).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"precious");
}

#[test]
fn target_appearing_before_link_is_untouched() {
    let d = dir();
    let path = d.path().join("v.opv");
    let sk = SecretKey::generate().unwrap();
    let r = Vault::create_inner(&path, &pw("password1"), P, &sk, &|p| {
        std::fs::write(p, b"raced").map_err(|_| Error::Io(std::io::ErrorKind::Other))
    });
    assert!(r.is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"raced");
    // The hook writes, then the link must fail on its own too.
    let path2 = d.path().join("w.opv");
    let fired = Cell::new(false);
    let r = Vault::create_inner(&path2, &pw("password1"), P, &sk, &|p| {
        fired.set(true);
        std::fs::write(p, b"raced2").unwrap();
        Ok(())
    });
    assert!(fired.get());
    assert!(matches!(r, Err(Error::Io(_))));
    assert_eq!(std::fs::read(&path2).unwrap(), b"raced2");
}

#[test]
fn crash_before_link_leaves_no_vault() {
    let d = dir();
    let path = d.path().join("v.opv");
    let sk = SecretKey::generate().unwrap();
    let r = Vault::create_inner(&path, &pw("password1"), P, &sk, &|_| {
        Err(Error::Io(std::io::ErrorKind::Other))
    });
    assert!(r.is_err());
    assert!(!path.exists());
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
}

#[test]
fn invalid_input_before_touching_disk() {
    let d = dir();
    let path = d.path().join("v.opv");
    let sk = SecretKey::generate().unwrap();
    // 7 scalar values.
    assert_eq!(
        Vault::create_with_key(&path, &pw("1234567"), P, &sk).err(),
        Some(Error::InvalidInput("password too short"))
    );
    // 8 scalars, multi-byte, is accepted.
    let ok = d.path().join("ok.opv");
    Vault::create_with_key(&ok, &pw("ééééééée"), P, &sk).unwrap();
    for bad in [
        KdfParams { m_kib: 1, ..P },
        KdfParams { t: 0, ..P },
        KdfParams { p: 0, ..P },
        KdfParams {
            m_kib: u32::MAX,
            ..P
        },
    ] {
        let r = Vault::create_with_key(&path, &pw("password1"), bad, &sk);
        assert!(matches!(r, Err(Error::InvalidInput(_))));
        assert!(Vault::create(&path, &pw("password1"), bad).is_err());
    }
    assert!(!path.exists());
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
}

#[test]
fn wrong_password_and_wrong_key_are_equal_errors() {
    let d = dir();
    let path = d.path().join("v.opv");
    let (_v, sk) = Vault::create(&path, &pw("password1"), P).unwrap();
    let e1 = Vault::unlock(&path, &pw("password2"), &sk).err().unwrap();
    let other = SecretKey::generate().unwrap();
    let e2 = Vault::unlock(&path, &pw("password1"), &other)
        .err()
        .unwrap();
    assert_eq!(e1, Error::Authentication);
    assert_eq!(e1, e2);
    let missing = d.path().join("nope");
    assert!(matches!(
        Vault::unlock(&missing, &pw("password1"), &sk),
        Err(Error::Io(_))
    ));
}

#[test]
fn unlock_has_no_password_minimum() {
    let d = dir();
    let path = d.path().join("v.opv");
    let sk = SecretKey::generate().unwrap();
    // Test seam: creation without the length check.
    Vault::create_inner(&path, &pw("abc"), P, &sk, &|_| Ok(())).unwrap();
    Vault::unlock(&path, &pw("abc"), &sk).unwrap();
    assert_eq!(
        Vault::unlock(&path, &pw("abd"), &sk).err(),
        Some(Error::Authentication)
    );
    assert_eq!(
        Vault::unlock(&path, &pw(""), &sk).err(),
        Some(Error::Authentication)
    );
}

#[test]
fn secret_key_not_in_file() {
    let d = dir();
    let path = d.path().join("v.opv");
    let (_v, sk) = Vault::create(&path, &pw("password1"), P).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    assert!(!has(sk.expose()));
    let text = sk.to_text();
    assert!(!has(text.expose().as_bytes()));
    let compact: String = text.expose().chars().filter(|c| *c != '-').collect();
    assert!(!has(compact.as_bytes()));
}

#[test]
fn every_flipped_byte_fails_unlock() {
    let d = dir();
    let path = d.path().join("v.opv");
    let (_v, sk) = Vault::create(&path, &pw("password1"), P).unwrap();
    let orig = std::fs::read(&path).unwrap();
    // Sanity: the unmodified file opens.
    Vault::unlock(&path, &pw("password1"), &sk).unwrap();
    for i in 0..orig.len() {
        let mut b = orig.clone();
        b[i] ^= 0x01;
        std::fs::write(&path, &b).unwrap();
        assert!(
            Vault::unlock(&path, &pw("password1"), &sk).is_err(),
            "offset {i}"
        );
    }
}

#[test]
fn debug_is_redacted_and_keys_zeroize() {
    fn zod<T: zeroize::ZeroizeOnDrop>() {}
    zod::<VaultKey>();
    zod::<ItemWrapKey>();
    zod::<FileAuthKey>();
    let d = dir();
    let path = d.path().join("v.opv");
    let (v, _sk) = Vault::create(&path, &pw("password1"), P).unwrap();
    assert_eq!(format!("{v:?}"), "Vault { .. }");
}

#[test]
fn set_clock_replaces_clock() {
    struct Fixed;
    impl Clock for Fixed {
        fn now_ms(&self) -> u64 {
            42
        }
    }
    let d = dir();
    let path = d.path().join("v.opv");
    let (mut v, _sk) = Vault::create(&path, &pw("password1"), P).unwrap();
    assert!(SystemClock.now_ms() > 1_600_000_000_000);
    v.set_clock(Box::new(Fixed));
    assert_eq!(v.clock.now_ms(), 42);
}
