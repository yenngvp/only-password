use super::*;
use crate::crypto::kdf::KdfParams;
use crate::secret::SecretString;
use std::cell::Cell;
use std::rc::Rc;

const P: KdfParams = KdfParams::FAST_FOR_TESTS;

#[derive(Clone)]
struct TestClock(Rc<Cell<u64>>);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.get()
    }
}

fn pw(s: &str) -> SecretString {
    SecretString::new(s.to_string())
}

fn setup() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    Vault,
    SecretKey,
    Rc<Cell<u64>>,
) {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("v.opv");
    let (mut v, sk) = Vault::create(&path, &pw("correct horse"), P).unwrap();
    let t = Rc::new(Cell::new(1_000));
    v.set_clock(Box::new(TestClock(t.clone())));
    (d, path, v, sk, t)
}

fn login(title: &str, user: &str, pass: &str) -> Item {
    let mut i = Item::new_login(title);
    i.username = Some(user.to_string());
    i.password = Some(pw(pass));
    i
}

fn bytes_of(i: &Item) -> Vec<u8> {
    i.to_plaintext(0, 0).unwrap().to_vec()
}

struct Limits;
impl Limits {
    fn set(records: usize, image: usize) -> Limits {
        LIMITS.with(|l| l.set((records, image)));
        Limits
    }
}
impl Drop for Limits {
    fn drop(&mut self) {
        LIMITS.with(|l| l.set((MAX_RECORDS as usize, MAX_VAULT_FILE)));
    }
}

#[test]
fn add_three_lock_unlock_get() {
    let (_d, path, mut v, sk, _t) = setup();
    let items = [
        login("a", "u1", "p1"),
        login("b", "u2", "p2"),
        Item::new_note("c", pw("note text")),
    ];
    let ids: Vec<_> = items.iter().map(|i| v.add(i).unwrap()).collect();
    v.lock();
    let v = Vault::unlock(&path, &pw("correct horse"), &sk).unwrap();
    for (id, it) in ids.iter().zip(&items) {
        let s = v.get(id).unwrap();
        assert_eq!(s.revision, 1);
        assert_eq!(s.created_ms, 1_000);
        assert_eq!(s.updated_ms, 1_000);
        assert_eq!(bytes_of(&s.item), bytes_of(it));
    }
}

#[test]
fn update_semantics() {
    let (_d, path, mut v, sk, t) = setup();
    let id = v.add(&login("a", "u", "old")).unwrap();
    let before = v.file.records[0].clone();
    t.set(5_000);
    v.update(&id, &login("a", "u", "new")).unwrap();
    let s = v.get(&id).unwrap();
    assert_eq!(s.revision, 2);
    assert_eq!(s.created_ms, 1_000);
    assert_eq!(s.updated_ms, 5_000);
    assert_eq!(s.item.password.as_ref().unwrap().expose(), "new");
    let after = &v.file.records[0];
    assert_ne!(before.wrapped_ik, after.wrapped_ik);
    assert_ne!(before.key_nonce, after.key_nonce);
    assert_ne!(before.body_nonce, after.body_nonce);
    assert_ne!(before.body_ct, after.body_ct);
    // clock going backwards: updated_ms = max(now, created_ms)
    t.set(10);
    v.update(&id, &login("a", "u", "newer")).unwrap();
    assert_eq!(v.get(&id).unwrap().updated_ms, 1_000);
    v.lock();
    let v = Vault::unlock(&path, &pw("correct horse"), &sk).unwrap();
    assert_eq!(v.get(&id).unwrap().revision, 3);
}

#[test]
fn unknown_id_is_not_found() {
    let (_d, path, mut v, _sk, _t) = setup();
    v.add(&login("a", "u", "p")).unwrap();
    let before = std::fs::read(&path).unwrap();
    let bad = ItemId([7; 16]);
    assert_eq!(v.get(&bad).unwrap_err(), Error::NotFound);
    assert_eq!(
        v.update(&bad, &login("x", "u", "p")).unwrap_err(),
        Error::NotFound
    );
    assert_eq!(v.delete(&bad).unwrap_err(), Error::NotFound);
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn delete_survives_relock() {
    let (_d, path, mut v, sk, _t) = setup();
    let a = v.add(&login("a", "u", "p")).unwrap();
    let b = v.add(&login("b", "u", "p")).unwrap();
    v.delete(&a).unwrap();
    assert_eq!(v.get(&a).unwrap_err(), Error::NotFound);
    assert_eq!(v.list().unwrap().len(), 1);
    v.lock();
    let v = Vault::unlock(&path, &pw("correct horse"), &sk).unwrap();
    assert_eq!(v.get(&a).unwrap_err(), Error::NotFound);
    let l = v.list().unwrap();
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].id, b);
}

#[test]
fn list_sorted_by_lowercase_title_then_id() {
    let (_d, _p, mut v, _sk, _t) = setup();
    let mut same = Vec::new();
    for t in ["banana", "Apple", "apple", "Cherry"] {
        same.push((t, v.add(&login(t, "u", "secret-pw-sentinel")).unwrap()));
    }
    let l = v.list().unwrap();
    let titles: Vec<_> = l.iter().map(|s| s.title.as_str()).collect();
    assert_eq!(
        titles.iter().map(|t| t.to_lowercase()).collect::<Vec<_>>(),
        ["apple", "apple", "banana", "cherry"]
    );
    assert!(l[0].id.0 < l[1].id.0);
    assert!(!format!("{l:?}").contains("secret-pw-sentinel"));
}

#[test]
fn search_fields_and_case() {
    let (_d, _p, mut v, _sk, _t) = setup();
    let mut it = login("GitHub", "Alice", "pw-needle");
    it.urls = vec!["https://Example.COM/x".into()];
    it.notes = pw("note-needle");
    it.fields = vec![crate::CustomField {
        name: "fname".into(),
        value: pw("field-needle"),
        hidden: false,
    }];
    it.totp = Some(crate::TotpConfig {
        secret: pw("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        algorithm: crate::TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
    });
    let id = v.add(&it).unwrap();
    for q in [
        "github",
        "GITHUB",
        "hub",
        "alice",
        "ALIC",
        "example.com",
        "EXAMPLE",
    ] {
        let r = v.search(q).unwrap();
        assert_eq!(r.len(), 1, "{q}");
        assert_eq!(r[0].id, id);
    }
    for q in ["needle", "gezdgn", "fname", "zzz"] {
        assert!(v.search(q).unwrap().is_empty(), "{q}");
    }
}

#[test]
fn invalid_items_leave_file_unchanged() {
    let (_d, path, mut v, _sk, _t) = setup();
    let id = v.add(&login("a", "u", "p")).unwrap();
    let before = std::fs::read(&path).unwrap();
    let bad = Item::new_login("");
    assert!(matches!(v.add(&bad), Err(Error::InvalidInput(_))));
    assert!(matches!(v.update(&id, &bad), Err(Error::InvalidInput(_))));
    let mut note = Item::new_note("n", pw(""));
    note.username = Some("x".into());
    assert!(matches!(v.add(&note), Err(Error::InvalidInput(_))));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(v.get(&id).unwrap().revision, 1);
}

#[cfg(unix)]
#[test]
fn read_only_directory_gives_io_and_changes_nothing() {
    use std::os::unix::fs::PermissionsExt;
    let (d, path, mut v, _sk, _t) = setup();
    let id = v.add(&login("a", "u", "p")).unwrap();
    let before = std::fs::read(&path).unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::File::create(d.path().join("probe")).is_ok() {
        // running as root: permissions are not enforced
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    let r1 = v.add(&login("b", "u", "p"));
    let r2 = v.update(&id, &login("a2", "u", "p"));
    let r3 = v.delete(&id);
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(r1, Err(Error::Io(_))));
    assert!(matches!(r2, Err(Error::Io(_))));
    assert!(matches!(r3, Err(Error::Io(_))));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(v.list().unwrap().len(), 1);
    let s = v.get(&id).unwrap();
    assert_eq!((s.revision, s.item.title.as_str()), (1, "a"));
}

#[test]
fn thousand_distinct_ids() {
    let (_d, _p, mut v, _sk, _t) = setup();
    let mut ids = std::collections::HashSet::new();
    // build in memory quickly: each add rewrites the file, 1000 is acceptable
    for n in 0..1000 {
        let id = v.add(&Item::new_login(format!("t{n}"))).unwrap();
        assert!(ids.insert(id.0));
    }
    assert_eq!(v.list().unwrap().len(), 1000);
}

#[test]
fn non_ascii_order_and_search() {
    let (_d, _p, mut v, _sk, _t) = setup();
    for t in ["\u{c9}clair", "eclair", "\u{3a3}igma", "\u{130}stanbul"] {
        v.add(&Item::new_login(t)).unwrap();
    }
    let titles: Vec<String> = v.list().unwrap().into_iter().map(|s| s.title).collect();
    // lower-cased bytes: "eclair" (65..) < "i\u{307}stanbul" (69..) < "\u{e9}clair" (c3..) < "\u{3c3}igma" (cf..)
    assert_eq!(
        titles,
        ["eclair", "\u{130}stanbul", "\u{c9}clair", "\u{3a3}igma"]
    );
    let r = v.search("\u{3c3}").unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].title, "\u{3a3}igma");
}

#[test]
fn record_limit() {
    let (_d, path, mut v, _sk, _t) = setup();
    let _l = Limits::set(2, MAX_VAULT_FILE);
    let a = v.add(&Item::new_login("a")).unwrap();
    v.add(&Item::new_login("b")).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        v.add(&Item::new_login("c")).unwrap_err(),
        Error::LimitExceeded
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(v.list().unwrap().len(), 2);
    // update does not add a record
    v.update(&a, &Item::new_login("a2")).unwrap();
}

#[test]
fn image_size_limit() {
    let (_d, path, mut v, _sk, _t) = setup();
    let id = v.add(&Item::new_login("a")).unwrap();
    let before = std::fs::read(&path).unwrap();
    let _l = Limits::set(MAX_RECORDS as usize, before.len() + 100);
    assert_eq!(
        v.add(&Item::new_login("b")).unwrap_err(),
        Error::LimitExceeded
    );
    let mut big = Item::new_login("a");
    big.notes = pw(&"x".repeat(5_000));
    assert_eq!(v.update(&id, &big).unwrap_err(), Error::LimitExceeded);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let s = v.get(&id).unwrap();
    assert_eq!(s.revision, 1);
    assert_eq!(v.list().unwrap().len(), 1);
}
