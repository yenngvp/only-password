use super::*;
use crate::format::{HEADER_LEN, TRAILER_LEN};

const P: KdfParams = KdfParams::FAST_FOR_TESTS;
const P2: KdfParams = KdfParams {
    m_kib: 8_192,
    t: 2,
    p: 1,
};
const OLD: &str = "correct horse";
const NEW: &str = "battery staple";

fn pw(s: &str) -> SecretString {
    SecretString::new(s.to_string())
}

struct FailGuard;
impl FailGuard {
    fn on() -> FailGuard {
        FAIL_WRITE.with(|f| f.set(true));
        FailGuard
    }
}
impl Drop for FailGuard {
    fn drop(&mut self) {
        FAIL_WRITE.with(|f| f.set(false));
    }
}

fn setup() -> (tempfile::TempDir, PathBuf, Vault, SecretKey, Vec<ItemId>) {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("v.opv");
    let (mut v, sk) = Vault::create(&path, &pw(OLD), P).unwrap();
    let mut ids = Vec::new();
    for n in ["a", "b", "c"] {
        let mut i = Item::new_login(n);
        i.password = Some(pw(&format!("pass-{n}")));
        ids.push(v.add(&i).unwrap());
    }
    let mut i = Item::new_login("a2");
    i.username = Some("u".into());
    v.update(&ids[0], &i).unwrap(); // revision 2
    (d, path, v, sk, ids)
}

fn region(bytes: &[u8]) -> &[u8] {
    &bytes[HEADER_LEN..bytes.len() - TRAILER_LEN]
}

fn snapshot(v: &Vault, ids: &[ItemId]) -> Vec<(u64, u64, u64, Vec<u8>)> {
    ids.iter()
        .map(|id| {
            let s = v.get(id).unwrap();
            (
                s.revision,
                s.created_ms,
                s.updated_ms,
                s.item
                    .to_plaintext(s.created_ms, s.updated_ms)
                    .unwrap()
                    .to_vec(),
            )
        })
        .collect()
}

fn recs(bytes: &[u8]) -> Vec<Record> {
    VaultFile::parse(bytes).unwrap().records
}

fn assert_all_records_differ(before: &[u8], after: &[u8]) {
    let (b, a) = (recs(before), recs(after));
    assert_eq!(b.len(), a.len());
    for (x, y) in b.iter().zip(&a) {
        assert_eq!(x.item_id, y.item_id);
        assert_eq!(x.revision, y.revision);
        assert_ne!(x.key_nonce, y.key_nonce);
        assert_ne!(x.wrapped_ik, y.wrapped_ik);
        assert_ne!(x.body_nonce, y.body_nonce);
        assert_ne!(x.body_ct, y.body_ct);
    }
}

fn old_vk_opens_nothing(old_vk: &[u8; 32], bytes: &[u8]) {
    let f = VaultFile::parse(bytes).unwrap();
    let k = VaultKey::from_secret(crate::secret::SecretBytes::new(*old_vk));
    let kiw = k.item_wrap_key().unwrap();
    assert!(!f.records.is_empty());
    for r in &f.records {
        assert!(matches!(
            seal::open_record(&kiw, &f.header.vault_id, r),
            Err(Error::Authentication)
        ));
    }
}

#[test]
fn change_password_basic() {
    let (_d, path, mut v, sk, ids) = setup();
    let snap = snapshot(&v, &ids);
    let before = std::fs::read(&path).unwrap();
    v.change_master_password(&pw(OLD), &sk, &pw(NEW), P2)
        .unwrap();
    let after = std::fs::read(&path).unwrap();
    assert_eq!(region(&before), region(&after));
    let (hb, ha) = (
        VaultFile::parse(&before).unwrap(),
        VaultFile::parse(&after).unwrap(),
    );
    assert_ne!(hb.header.kdf_salt, ha.header.kdf_salt);
    assert_ne!(hb.header.vk_nonce, ha.header.vk_nonce);
    assert_eq!(hb.header.vault_id, ha.header.vault_id);
    assert_eq!(ha.header.kdf, P2);
    assert_eq!(v.kdf_params(), P2);
    assert_eq!(snapshot(&v, &ids), snap);
    // in-memory vault keeps working
    v.add(&Item::new_login("d")).unwrap();
    assert!(matches!(
        Vault::unlock(&path, &pw(OLD), &sk),
        Err(Error::Authentication)
    ));
    let u = Vault::unlock(&path, &pw(NEW), &sk).unwrap();
    assert_eq!(snapshot(&u, &ids), snap);
}

#[test]
fn change_to_same_password_still_changes_salt_and_nonce() {
    let (_d, path, mut v, sk, _ids) = setup();
    let before = VaultFile::parse(&std::fs::read(&path).unwrap()).unwrap();
    v.change_master_password(&pw(OLD), &sk, &pw(OLD), P)
        .unwrap();
    let after = VaultFile::parse(&std::fs::read(&path).unwrap()).unwrap();
    assert_ne!(before.header.kdf_salt, after.header.kdf_salt);
    assert_ne!(before.header.vk_nonce, after.header.vk_nonce);
    assert_ne!(before.header.wrapped_vk, after.header.wrapped_vk);
    Vault::unlock(&path, &pw(OLD), &sk).unwrap();
}

#[test]
fn change_password_rejections_change_nothing() {
    let (_d, path, mut v, sk, ids) = setup();
    let before = std::fs::read(&path).unwrap();
    let r = v.change_master_password(&pw("wrong password"), &sk, &pw(NEW), P);
    assert!(matches!(r, Err(Error::Authentication)));
    let other = SecretKey::generate().unwrap();
    let r = v.change_master_password(&pw(OLD), &other, &pw(NEW), P);
    assert!(matches!(r, Err(Error::Authentication)));
    let r = v.change_master_password(&pw(OLD), &sk, &pw("short"), P);
    assert!(matches!(r, Err(Error::InvalidInput(_))));
    let bad = KdfParams {
        m_kib: 1,
        t: 1,
        p: 1,
    };
    assert!(matches!(
        v.change_master_password(&pw(OLD), &sk, &pw(NEW), bad),
        Err(Error::InvalidInput(_))
    ));
    let huge = KdfParams {
        m_kib: 8_192,
        t: 17,
        p: 1,
    };
    assert!(matches!(
        v.change_master_password(&pw(OLD), &sk, &pw(NEW), huge),
        Err(Error::InvalidInput(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(v.kdf_params(), P);
    assert_eq!(v.list().unwrap().len(), ids.len());
    Vault::unlock(&path, &pw(OLD), &sk).unwrap();
}

#[test]
fn rotate_rekeys_every_record() {
    let (_d, path, mut v, sk, ids) = setup();
    let snap = snapshot(&v, &ids);
    let before = std::fs::read(&path).unwrap();
    let old_vk = *v.vk.expose();
    v.rotate_vault_key(&pw(OLD), &sk).unwrap();
    let after = std::fs::read(&path).unwrap();
    assert_eq!(snapshot(&v, &ids), snap);
    assert_all_records_differ(&before, &after);
    old_vk_opens_nothing(&old_vk, &after);
    assert_ne!(v.vk.expose(), &old_vk);
    let (hb, ha) = (
        VaultFile::parse(&before).unwrap(),
        VaultFile::parse(&after).unwrap(),
    );
    assert_eq!(hb.header.vault_id, ha.header.vault_id);
    assert_eq!(hb.header.kdf_salt, ha.header.kdf_salt);
    assert_ne!(hb.header.wrapped_vk, ha.header.wrapped_vk);
    assert_ne!(hb.header.vk_nonce, ha.header.vk_nonce);
    // same password and key still unlock; contents identical
    let u = Vault::unlock(&path, &pw(OLD), &sk).unwrap();
    assert_eq!(snapshot(&u, &ids), snap);
    assert_ne!(u.vk.expose(), &old_vk);
}

#[test]
fn splicing_old_record_into_rotated_file_fails() {
    let (_d, path, mut v, sk, ids) = setup();
    let before = std::fs::read(&path).unwrap();
    v.rotate_vault_key(&pw(OLD), &sk).unwrap();
    let mut f = VaultFile::parse(&std::fs::read(&path).unwrap()).unwrap();
    f.records[0] = recs(&before)[0].clone();
    let spliced = f.serialize().unwrap();
    std::fs::write(&path, &spliced).unwrap();
    assert!(matches!(
        Vault::unlock(&path, &pw(OLD), &sk),
        Err(Error::Authentication)
    ));
    let _ = ids;
}

#[test]
fn rotate_wrong_password_changes_nothing() {
    let (_d, path, mut v, sk, _ids) = setup();
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        v.rotate_vault_key(&pw("wrong password"), &sk),
        Err(Error::Authentication)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn combined_operation() {
    let (_d, path, mut v, sk, ids) = setup();
    let snap = snapshot(&v, &ids);
    let before = std::fs::read(&path).unwrap();
    let old_vk = *v.vk.expose();
    v.change_master_password_and_rotate_key(&pw(OLD), &sk, &pw(NEW), P2)
        .unwrap();
    let after = std::fs::read(&path).unwrap();
    assert_all_records_differ(&before, &after);
    old_vk_opens_nothing(&old_vk, &after);
    let (hb, ha) = (
        VaultFile::parse(&before).unwrap(),
        VaultFile::parse(&after).unwrap(),
    );
    assert_eq!(hb.header.vault_id, ha.header.vault_id);
    assert_ne!(hb.header.kdf_salt, ha.header.kdf_salt);
    assert_eq!(ha.header.kdf, P2);
    assert!(matches!(
        Vault::unlock(&path, &pw(OLD), &sk),
        Err(Error::Authentication)
    ));
    let u = Vault::unlock(&path, &pw(NEW), &sk).unwrap();
    assert_eq!(snapshot(&u, &ids), snap);
    assert_eq!(snapshot(&v, &ids), snap);
    // rejections
    let b2 = std::fs::read(&path).unwrap();
    assert!(matches!(
        v.change_master_password_and_rotate_key(&pw(OLD), &sk, &pw(NEW), P),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        v.change_master_password_and_rotate_key(&pw(NEW), &sk, &pw("short"), P),
        Err(Error::InvalidInput(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b2);
}

#[test]
fn write_failure_leaves_old_state_usable() {
    let (_d, path, mut v, sk, ids) = setup();
    let snap = snapshot(&v, &ids);
    let before = std::fs::read(&path).unwrap();
    {
        let _g = FailGuard::on();
        assert!(matches!(
            v.change_master_password(&pw(OLD), &sk, &pw(NEW), P2),
            Err(Error::Io(_))
        ));
        assert!(matches!(
            v.rotate_vault_key(&pw(OLD), &sk),
            Err(Error::Io(_))
        ));
        assert!(matches!(
            v.change_master_password_and_rotate_key(&pw(OLD), &sk, &pw(NEW), P2),
            Err(Error::Io(_))
        ));
    }
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(v.kdf_params(), P);
    assert_eq!(snapshot(&v, &ids), snap);
    // the in-memory vault can still mutate and the old credentials still unlock
    v.add(&Item::new_login("later")).unwrap();
    let u = Vault::unlock(&path, &pw(OLD), &sk).unwrap();
    assert_eq!(u.list().unwrap().len(), ids.len() + 1);
    // and a later successful rekey works
    v.rotate_vault_key(&pw(OLD), &sk).unwrap();
}

#[test]
fn doc_of_change_master_password_mentions_rotation() {
    let src = include_str!("../vault.rs");
    let at = src.find("pub fn change_master_password(").unwrap();
    let doc: String = src[..at]
        .lines()
        .rev()
        .take_while(|l| l.trim_start().starts_with("///") || l.trim().is_empty())
        .collect();
    assert!(doc.contains("does **not** revoke"));
    assert!(doc.contains("rotat"));
    assert!(doc.contains("change_master_password_and_rotate_key"));
}
