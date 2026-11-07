use super::*;
use crate::crypto::kdf::KdfParams;
use crate::secret::SecretString;

const P: KdfParams = KdfParams::FAST_FOR_TESTS;
const PW: &str = "correct horse";

fn pw(s: &str) -> SecretString {
    SecretString::new(s.to_string())
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const TITLES: &[&str] = &[
    "Bank",
    "bank",
    "BANK two",
    "Mail",
    "\u{130}stanbul",
    "i\u{307}x",
    "\u{3a3}igma",
    "\u{3c3}igma",
    "mo\u{3c2}",
    "MO\u{3a3}",
    "Zeta",
    "alpha",
    "Alpha",
];
const QUERIES: &[&str] = &[
    "",
    "bank",
    "BaNk",
    "example.com",
    "EXAMPLE",
    "\u{130}",
    "i\u{307}",
    "\u{3a3}",
    "\u{3c3}",
    "\u{3c2}",
    "mo",
    "zz-none",
    "alice",
];

fn random_item(r: &mut Rng) -> Item {
    let t = TITLES[r.below(TITLES.len())];
    let mut i = Item::new_login(format!("{t}{}", r.below(3)));
    if r.below(2) == 0 {
        i.username = Some(["Alice", "bob", "\u{130}ris"][r.below(3)].to_string());
    }
    if r.below(2) == 0 {
        i.urls.push(format!("https://Example.com/p{}", r.below(5)));
    }
    i.password = Some(pw("pw-secret"));
    i
}

fn check(v: &Vault) {
    assert_eq!(v.index().entries(), v.list().unwrap().as_slice());
    assert_eq!(v.index().len(), v.list().unwrap().len());
    for q in QUERIES {
        let a: Vec<ItemSummary> = v.index().search(q).into_iter().cloned().collect();
        assert_eq!(a, v.search(q).unwrap(), "query {q:?}");
    }
}

#[test]
fn random_operation_sequence_keeps_index_equal_to_list() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("v.opv");
    let exp = d.path().join("x.opx");
    let (mut v, sk) = Vault::create(&path, &pw(PW), P).unwrap();
    assert!(v.index().is_empty());
    check(&v);
    let mut pass = PW.to_string();
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    let mut imports = 0;
    for step in 0..200 {
        let ids: Vec<ItemId> = v.list().unwrap().into_iter().map(|s| s.id).collect();
        match r.below(9) {
            0..=2 => {
                v.add(&random_item(&mut r)).unwrap();
            }
            3..=4 => {
                if let Some(id) = ids.get(r.below(ids.len().max(1))) {
                    v.update(id, &random_item(&mut r)).unwrap();
                }
            }
            5 => {
                if let Some(id) = ids.get(r.below(ids.len().max(1))) {
                    v.delete(id).unwrap();
                }
            }
            6 => {
                let _ = std::fs::remove_file(&exp);
                v.export(&exp, &pw("export pass"), &sk, P).unwrap();
                for id in &ids {
                    v.delete(id).unwrap();
                }
                check(&v);
                assert_eq!(v.import(&exp, &pw("export pass"), &sk).unwrap(), ids.len());
                imports += 1;
            }
            7 => {
                let np = format!("pw-{step}-long");
                match r.below(3) {
                    0 => v
                        .change_master_password(&pw(&pass), &sk, &pw(&np), P)
                        .unwrap(),
                    1 => v.rotate_vault_key(&pw(&pass), &sk).unwrap(),
                    _ => v
                        .change_master_password_and_rotate_key(&pw(&pass), &sk, &pw(&np), P)
                        .unwrap(),
                }
                if Vault::unlock(&path, &pw(&np), &sk).is_ok() {
                    pass = np;
                }
            }
            _ => {
                v.lock();
                v = Vault::unlock(&path, &pw(&pass), &sk).unwrap();
                assert_eq!(v.index().entries(), v.list().unwrap().as_slice());
            }
        }
        check(&v);
    }
    assert!(imports > 0);
}

fn failing_vault() -> (tempfile::TempDir, Vault, SecretKey, ItemId) {
    let d = tempfile::tempdir().unwrap();
    let (mut v, sk) = Vault::create(&d.path().join("v.opv"), &pw(PW), P).unwrap();
    let mut r = Rng(7);
    let mut id = None;
    for _ in 0..3 {
        id = Some(v.add(&random_item(&mut r)).unwrap());
    }
    (d, v, sk, id.unwrap())
}

struct Snap(Vec<ItemSummary>);
fn snap(v: &Vault) -> Snap {
    Snap(v.index().entries().to_vec())
}

#[test]
fn failed_mutations_leave_index_unchanged() {
    let (d, mut v, sk, id) = failing_vault();
    let before = snap(&v);
    let good = Item::new_login("Brand new");
    let bad = Item::new_login("");
    assert!(bad.validate().is_err());
    assert!(v.add(&bad).is_err());
    assert!(v.update(&id, &bad).is_err());
    assert_eq!(
        v.update(&ItemId([9; 16]), &good).unwrap_err(),
        Error::NotFound
    );
    assert_eq!(v.delete(&ItemId([9; 16])).unwrap_err(), Error::NotFound);
    assert_eq!(v.index().entries(), before.0.as_slice());

    // injected I/O failure on every mutating operation
    {
        FAIL_WRITE.with(|f| f.set(true));
        let exp = d.path().join("e.opx");
        let np = pw("another long pw");
        assert!(v.add(&good).is_err());
        assert!(v.update(&id, &good).is_err());
        assert!(v.delete(&id).is_err());
        assert!(v.change_master_password(&pw(PW), &sk, &np, P).is_err());
        assert!(v.rotate_vault_key(&pw(PW), &sk).is_err());
        assert!(v
            .change_master_password_and_rotate_key(&pw(PW), &sk, &np, P)
            .is_err());
        FAIL_WRITE.with(|f| f.set(false));
        v.export(&exp, &pw("export pass"), &sk, P).unwrap();
        let ids: Vec<ItemId> = v.list().unwrap().into_iter().map(|s| s.id).collect();
        for i in &ids {
            v.delete(i).unwrap();
        }
        let empty = snap(&v);
        FAIL_WRITE.with(|f| f.set(true));
        assert!(v.import(&exp, &pw("export pass"), &sk).is_err());
        FAIL_WRITE.with(|f| f.set(false));
        assert_eq!(v.index().entries(), empty.0.as_slice());
        assert!(v.index().is_empty());
        v.import(&exp, &pw("export pass"), &sk).unwrap();
    }
    assert_eq!(v.index().entries(), before.0.as_slice());
    check(&v);

    // LimitExceeded
    LIMITS.with(|l| l.set((3, MAX_VAULT_FILE)));
    assert_eq!(v.add(&good).unwrap_err(), Error::LimitExceeded);
    LIMITS.with(|l| l.set((MAX_RECORDS as usize, MAX_VAULT_FILE)));
    assert_eq!(v.index().entries(), before.0.as_slice());
    check(&v);
}

#[test]
fn unlocked_and_empty_vaults() {
    let (d, v, sk, _) = failing_vault();
    drop(v);
    let v = Vault::unlock(&d.path().join("v.opv"), &pw(PW), &sk).unwrap();
    assert_eq!(v.index().entries(), v.list().unwrap().as_slice());
    assert_eq!(v.index().len(), 3);
    let d2 = tempfile::tempdir().unwrap();
    let (e, _) = Vault::create(&d2.path().join("e.opv"), &pw(PW), P).unwrap();
    assert!(e.index().is_empty());
    assert!(e.index().entries().is_empty());
}

#[test]
fn index_reads_decrypt_nothing() {
    let (_d, v, _sk, _) = failing_vault();
    let before = v.decrypt_count();
    for q in QUERIES {
        let _ = v.index().search(q);
    }
    let _ = v.index().entries();
    assert_eq!(v.decrypt_count(), before);
    let _ = v.search("bank").unwrap();
    assert!(v.decrypt_count() > before, "counter must actually count");
}

#[test]
fn debug_is_redacted_and_summaries_hold_no_secrets() {
    let d = tempfile::tempdir().unwrap();
    let (mut v, _sk) = Vault::create(&d.path().join("v.opv"), &pw(PW), P).unwrap();
    let mut i = Item::new_login("SENTINEL-TITLE-QZX");
    i.password = Some(pw("SENTINEL-PASSWORD"));
    i.notes = pw("SENTINEL-NOTES");
    v.add(&i).unwrap();
    let dbg = format!("{:?}", v.index());
    assert_eq!(dbg, "ItemIndex { .. }");
    assert!(!dbg.contains("SENTINEL"));
    let sums = format!("{:?}", v.index().entries());
    assert!(sums.contains("SENTINEL-TITLE-QZX"));
    assert!(!sums.contains("SENTINEL-PASSWORD") && !sums.contains("SENTINEL-NOTES"));
}

#[test]
fn drop_clears_strings() {
    assert!(std::mem::needs_drop::<ItemIndex>());
    let mut idx = ItemIndex::from_summaries(vec![ItemSummary {
        id: ItemId([1; 16]),
        kind: ItemKind::Login,
        title: "secret title".into(),
        username: Some("user".into()),
        urls: vec!["https://u".into()],
        revision: 1,
        updated_ms: 1,
    }]);
    assert_eq!(
        idx.entries().first().map(|e| e.title.as_str()),
        Some("secret title")
    );
    // The routine Drop runs; afterwards no string keeps its content.
    idx.wipe_strings();
    let e = idx.entries().first().unwrap();
    assert!(e.title.is_empty());
    assert_eq!(e.username.as_deref(), Some(""));
    assert_eq!(e.urls, vec![String::new()]);
}
