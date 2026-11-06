use super::export::{seal_export, MAX_PAYLOAD};
use super::*;
use crate::crypto::kdf::KdfParams;
use crate::item::{CustomField, TotpAlgorithm, TotpConfig};
use crate::secret::SecretString;
use std::path::PathBuf;

const P: KdfParams = KdfParams::FAST_FOR_TESTS;
const XPW: &str = "export passphrase";
const SECRET: &str = "JBSWY3DPEHPK3PXP";
const SENT_PASS: &str = "sentinel-login-password-91";
const SENT_NOTE: &str = "sentinel-note-body-77";
const SENT_FIELD: &str = "sentinel-field-value-42";

fn pw(s: &str) -> SecretString {
    SecretString::new(s.to_string())
}

fn rich_login() -> Item {
    let mut i = Item::new_login("Bank");
    i.username = Some("alice".into());
    i.password = Some(pw(SENT_PASS));
    i.urls = vec!["https://bank.example".into()];
    i.totp = Some(TotpConfig {
        secret: pw(SECRET),
        algorithm: TotpAlgorithm::Sha256,
        digits: 8,
        period: 60,
    });
    i.fields = vec![CustomField {
        name: "pin".into(),
        value: pw(SENT_FIELD),
        hidden: true,
    }];
    i
}

fn vault_a() -> (tempfile::TempDir, PathBuf, Vault, SecretKey, Vec<ItemId>) {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("a.opv");
    let (mut v, sk) = Vault::create(&path, &pw("correct horse"), P).unwrap();
    let mut ids = vec![
        v.add(&rich_login()).unwrap(),
        v.add(&Item::new_note("Memo", pw(SENT_NOTE))).unwrap(),
        v.add(&Item::new_login("Empty")).unwrap(),
    ];
    let mut upd = rich_login();
    upd.title = "Bank 2".into();
    v.update(&ids[0], &upd).unwrap(); // revision 2
    ids.sort_by_key(|a| a.0);
    (d, path, v, sk, ids)
}

fn vault_b(d: &tempfile::TempDir) -> (PathBuf, Vault, SecretKey) {
    let path = d.path().join("b.opv");
    let (v, sk) = Vault::create(&path, &pw("another horse"), P).unwrap();
    (path, v, sk)
}

fn snap(v: &Vault, ids: &[ItemId]) -> Vec<(u64, u64, u64, Vec<u8>)> {
    ids.iter()
        .map(|id| {
            let s = v.get(id).unwrap();
            let pt = s.item.to_plaintext(s.created_ms, s.updated_ms).unwrap();
            (s.revision, s.created_ms, s.updated_ms, pt.to_vec())
        })
        .collect()
}

fn export_file(v: &Vault, d: &tempfile::TempDir, sk: &SecretKey) -> (PathBuf, Vec<u8>) {
    let p = d.path().join("x.opx");
    v.export(&p, &pw(XPW), sk, P).unwrap();
    let b = std::fs::read(&p).unwrap();
    (p, b)
}

fn payload_json(export_schema: u32, entries: &[([u8; 16], u64, Vec<u8>)]) -> Vec<u8> {
    let items: Vec<String> = entries
        .iter()
        .map(|(id, rev, item)| {
            format!(
                r#"{{"id":"{}","revision":{},"item":{}}}"#,
                crate::base32::hex_encode(id),
                rev,
                String::from_utf8(item.clone()).unwrap()
            )
        })
        .collect();
    format!(
        r#"{{"export_schema":{},"vault_id":"{}","exported_ms":5,"items":[{}]}}"#,
        export_schema,
        "00".repeat(16),
        items.join(",")
    )
    .into_bytes()
}

fn item_json(title: &str) -> Vec<u8> {
    Item::new_login(title)
        .to_plaintext(10, 20)
        .unwrap()
        .to_vec()
}

fn write_sealed(d: &tempfile::TempDir, payload: &[u8], sk: &SecretKey, pass: &str) -> PathBuf {
    let p = d.path().join("hand.opx");
    std::fs::write(&p, seal_export(payload, &pw(pass), sk, P).unwrap()).unwrap();
    p
}

#[test]
fn roundtrip_into_other_vault_with_other_key() {
    let (d, _p, a, ska, ids) = vault_a();
    let (_bp, mut b, skb) = vault_b(&d);
    assert_ne!(ska.expose(), skb.expose());
    let (xp, _) = export_file(&a, &d, &ska);
    let bid = b.file.header.vault_id;
    assert_eq!(b.import(&xp, &pw(XPW), &ska).unwrap(), 3);
    assert_eq!(b.file.header.vault_id, bid);
    assert_eq!(a.list().unwrap(), b.list().unwrap());
    assert_eq!(snap(&a, &ids), snap(&b, &ids));
    assert!(snap(&b, &ids).iter().any(|s| s.0 == 2));
    // persisted
    let bp = b.path.clone();
    b.lock();
    let b = Vault::unlock(&bp, &pw("another horse"), &skb).unwrap();
    assert_eq!(snap(&a, &ids), snap(&b, &ids));
}

#[test]
fn wrong_password_and_wrong_key_authentication_and_b_unchanged() {
    let (d, _p, a, ska, _ids) = vault_a();
    let (bp, mut b, skb) = vault_b(&d);
    let (xp, _) = export_file(&a, &d, &ska);
    let before = std::fs::read(&bp).unwrap();
    assert_eq!(
        b.import(&xp, &pw("wrong password"), &ska),
        Err(Error::Authentication)
    );
    assert_eq!(b.import(&xp, &pw(XPW), &skb), Err(Error::Authentication));
    assert_eq!(std::fs::read(&bp).unwrap(), before);
    assert!(b.list().unwrap().is_empty());
}

#[test]
fn every_flipped_byte_is_an_error_and_b_unchanged() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("a.opv");
    let (mut a, ska) = Vault::create(&path, &pw("correct horse"), P).unwrap();
    a.add(&Item::new_note("n", pw("x"))).unwrap();
    let (bp, mut b, _skb) = vault_b(&d);
    let (xp, bytes) = export_file(&a, &d, &ska);
    let before = std::fs::read(&bp).unwrap();
    for off in 0..bytes.len() {
        let mut m = bytes.clone();
        m[off] ^= 0x01;
        std::fs::write(&xp, &m).unwrap();
        assert!(b.import(&xp, &pw(XPW), &ska).is_err(), "offset {off}");
        assert_eq!(std::fs::read(&bp).unwrap(), before, "offset {off}");
    }
    std::fs::write(&xp, &bytes).unwrap();
    assert_eq!(b.import(&xp, &pw(XPW), &ska).unwrap(), 1);
}

#[test]
fn independent_derivation_decrypts_export() {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
    use hkdf::Hkdf;
    use sha2::Sha256;
    let (d, _p, a, ska, _ids) = vault_a();
    let (_xp, f) = export_file(&a, &d, &ska);
    let salt: [u8; 16] = f[26..42].try_into().unwrap();
    let nonce: [u8; 24] = f[42..66].try_into().unwrap();
    let params = argon2::Params::new(
        u32::from_be_bytes(f[14..18].try_into().unwrap()),
        u32::from_be_bytes(f[18..22].try_into().unwrap()),
        u32::from_be_bytes(f[22..26].try_into().unwrap()),
        Some(32),
    )
    .unwrap();
    let mut pwk = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(XPW.as_bytes(), &salt, &mut pwk)
        .unwrap();
    let mut ikm = pwk.to_vec();
    ikm.extend_from_slice(ska.expose());
    let mut kx = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), &ikm)
        .expand(b"onlypassword/v1/export-key", &mut kx)
        .unwrap();
    let mut ad = b"onlypassword/v1/export".to_vec();
    ad.extend_from_slice(&f[..74]);
    let pt = XChaCha20Poly1305::new_from_slice(&kx)
        .unwrap()
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &f[74..],
                aad: &ad,
            },
        )
        .unwrap();
    let s = String::from_utf8(pt).unwrap();
    assert!(s.starts_with(r#"{"export_schema":1,"vault_id":""#));
    assert!(s.contains(r#""exported_ms":"#));
    assert!(s.contains(SENT_NOTE) && s.contains(SENT_PASS));
}

#[test]
fn header_layout() {
    let (d, _p, a, ska, _ids) = vault_a();
    let (_xp, f) = export_file(&a, &d, &ska);
    assert_eq!(&f[..8], b"OPEXPORT");
    assert_eq!(&f[8..12], &[0, 1, 0, 0]);
    assert_eq!(&f[12..14], &[1, 0x13]);
    assert_eq!(u32::from_be_bytes(f[14..18].try_into().unwrap()), P.m_kib);
    assert_eq!(u32::from_be_bytes(f[18..22].try_into().unwrap()), P.t);
    assert_eq!(u32::from_be_bytes(f[22..26].try_into().unwrap()), P.p);
    assert_eq!(
        u64::from_be_bytes(f[66..74].try_into().unwrap()),
        (f.len() - 74) as u64
    );
}

#[test]
fn error_table() {
    let (d, _p, a, ska, _ids) = vault_a();
    let (bp, mut b, _skb) = vault_b(&d);
    let (xp, f) = export_file(&a, &d, &ska);
    let before = std::fs::read(&bp).unwrap();
    let mut run = |m: &dyn Fn(&mut Vec<u8>)| {
        let mut x = f.clone();
        m(&mut x);
        std::fs::write(&xp, &x).unwrap();
        b.import(&xp, &pw(XPW), &ska)
    };
    assert_eq!(run(&|x| x[0] ^= 1), Err(Error::Corrupt("export magic")));
    assert_eq!(run(&|x| x[9] = 0), Err(Error::UnsupportedVersion));
    assert_eq!(run(&|x| x[9] = 2), Err(Error::UnsupportedVersion));
    assert_eq!(run(&|x| x[8] = 1), Err(Error::UnsupportedVersion));
    assert_eq!(run(&|x| x[11] = 1), Err(Error::Corrupt("export flags")));
    assert_eq!(run(&|x| x[10] = 1), Err(Error::Corrupt("export flags")));
    assert_eq!(run(&|x| x[12] = 2), Err(Error::UnsupportedVersion));
    assert_eq!(run(&|x| x[13] = 0x10), Err(Error::UnsupportedVersion));
    // KDF parameters below the floor / above the ceiling
    assert!(matches!(
        run(&|x| x[14..18].copy_from_slice(&1024u32.to_be_bytes())),
        Err(Error::Corrupt(_))
    ));
    assert!(matches!(
        run(&|x| x[18..22].copy_from_slice(&0u32.to_be_bytes())),
        Err(Error::Corrupt(_))
    ));
    assert!(matches!(
        run(&|x| x[22..26].copy_from_slice(&0u32.to_be_bytes())),
        Err(Error::Corrupt(_))
    ));
    assert!(matches!(
        run(&|x| x[14..18].copy_from_slice(&u32::MAX.to_be_bytes())),
        Err(Error::Corrupt(_))
    ));
    // ct_len
    assert!(matches!(run(&|x| x[73] ^= 1), Err(Error::Corrupt(_))));
    assert!(matches!(run(&|x| x.push(0)), Err(Error::Corrupt(_))));
    assert_eq!(std::fs::read(&bp).unwrap(), before);
}

#[test]
fn schema_two_after_decryption_is_unsupported() {
    let d = tempfile::tempdir().unwrap();
    let (bp, mut b, skb) = vault_b(&d);
    let id = [7u8; 16];
    let before = std::fs::read(&bp).unwrap();
    // export_schema 2
    let p = write_sealed(&d, &payload_json(2, &[(id, 1, item_json("t"))]), &skb, XPW);
    assert_eq!(b.import(&p, &pw(XPW), &skb), Err(Error::UnsupportedVersion));
    // item schema 2
    let it2 =
        String::from_utf8(item_json("t"))
            .unwrap()
            .replacen("\"schema\":1", "\"schema\":2", 1);
    let p = write_sealed(
        &d,
        &payload_json(1, &[(id, 1, it2.into_bytes())]),
        &skb,
        XPW,
    );
    assert_eq!(b.import(&p, &pw(XPW), &skb), Err(Error::UnsupportedVersion));
    assert_eq!(std::fs::read(&bp).unwrap(), before);
}

#[test]
fn invalid_payloads_are_corrupt() {
    let d = tempfile::tempdir().unwrap();
    let (bp, mut b, skb) = vault_b(&d);
    let before = std::fs::read(&bp).unwrap();
    let (i1, i2) = ([1u8; 16], [2u8; 16]);
    let cases: Vec<Vec<u8>> = vec![
        payload_json(1, &[(i2, 1, item_json("a")), (i1, 1, item_json("b"))]), // unsorted
        payload_json(1, &[(i1, 1, item_json("a")), (i1, 1, item_json("b"))]), // duplicate
        payload_json(1, &[(i1, 0, item_json("a"))]),                          // revision 0
        payload_json(
            1,
            &[(
                i1,
                1,
                String::from_utf8(item_json("t"))
                    .unwrap()
                    .replacen("\"title\":\"t\"", "\"title\":\"\"", 1)
                    .into_bytes(),
            )],
        ), // empty title
        b"not json".to_vec(),
        br#"{"export_schema":1}"#.to_vec(),
    ];
    for (n, c) in cases.iter().enumerate() {
        let p = write_sealed(&d, c, &skb, XPW);
        assert!(
            matches!(b.import(&p, &pw(XPW), &skb), Err(Error::Corrupt(_))),
            "case {n}"
        );
    }
    assert_eq!(std::fs::read(&bp).unwrap(), before);
}

#[test]
fn conflict_imports_nothing() {
    let (d, _p, a, ska, ids) = vault_a();
    let (bp, mut b, _skb) = vault_b(&d);
    let (xp, _) = export_file(&a, &d, &ska);
    // B already has one id of A: seal a record with the same id into B
    let k = b.vk.item_wrap_key().unwrap();
    let rec = seal::seal_item(
        &k,
        &b.file.header.vault_id,
        &ids[1],
        1,
        &Item::new_login("z"),
        1,
        1,
    )
    .unwrap();
    let mut recs = b.file.records.clone();
    recs.push(rec);
    b.commit(recs).unwrap();
    let before = std::fs::read(&bp).unwrap();
    let list = b.list().unwrap();
    assert_eq!(b.import(&xp, &pw(XPW), &ska), Err(Error::Conflict));
    assert_eq!(b.list().unwrap(), list);
    assert_eq!(std::fs::read(&bp).unwrap(), before);
}

#[test]
fn export_file_contains_no_secrets() {
    let (d, _p, a, ska, _ids) = vault_a();
    let (_xp, f) = export_file(&a, &d, &ska);
    let has = |n: &[u8]| f.windows(n.len()).any(|w| w == n);
    assert!(!has(ska.expose()));
    assert!(!has(ska.to_text().expose().as_bytes()));
    for s in [SENT_PASS, SENT_NOTE, SENT_FIELD, SECRET, "alice", "Bank"] {
        assert!(!has(s.as_bytes()), "{s}");
    }
}

#[test]
fn bad_lengths_are_corrupt_without_allocation() {
    let (d, _p, a, ska, _ids) = vault_a();
    let (bp, mut b, _skb) = vault_b(&d);
    let (xp, f) = export_file(&a, &d, &ska);
    let before = std::fs::read(&bp).unwrap();
    let mut x = f.clone();
    x[66..74].copy_from_slice(&u64::MAX.to_be_bytes());
    std::fs::write(&xp, &x).unwrap();
    assert!(matches!(
        b.import(&xp, &pw(XPW), &ska),
        Err(Error::Corrupt(_))
    ));
    for len in 0..f.len() {
        std::fs::write(&xp, &f[..len]).unwrap();
        assert!(b.import(&xp, &pw(XPW), &ska).is_err(), "len {len}");
    }
    assert_eq!(std::fs::read(&bp).unwrap(), before);
}

#[test]
fn export_password_rules_and_freshness() {
    let (d, _p, a, ska, _ids) = vault_a();
    let t = d.path().join("short.opx");
    assert!(matches!(
        a.export(&t, &pw("short"), &ska, P),
        Err(Error::InvalidInput(_))
    ));
    assert!(!t.exists());
    // bad params
    let bad = KdfParams {
        m_kib: 1,
        t: 1,
        p: 1,
    };
    assert!(matches!(
        a.export(&t, &pw(XPW), &ska, bad),
        Err(Error::InvalidInput(_))
    ));
    // two exports differ
    let (_x1, f1) = export_file(&a, &d, &ska);
    let (_x2, f2) = export_file(&a, &d, &ska);
    assert_ne!(f1[26..66], f2[26..66]);
    assert_ne!(f1, f2);
    // import ignores the minimum: a short password reaches decryption
    let (_bp, mut b, skb) = vault_b(&d);
    let p = write_sealed(
        &d,
        &payload_json(1, &[([3u8; 16], 1, item_json("s"))]),
        &skb,
        "abc",
    );
    assert_eq!(b.import(&p, &pw("abd"), &skb), Err(Error::Authentication));
    assert_eq!(b.import(&p, &pw("abc"), &skb).unwrap(), 1);
}

#[test]
fn failed_export_leaves_existing_target() {
    let (d, _p, a, ska, _ids) = vault_a();
    let t = d.path().join("keep.opx");
    std::fs::write(&t, b"previous contents").unwrap();
    MAX_PAYLOAD.with(|m| m.set(10));
    let r = a.export(&t, &pw(XPW), &ska, P);
    MAX_PAYLOAD.with(|m| m.set(crate::format::MAX_EXPORT_PLAINTEXT));
    assert_eq!(r, Err(Error::LimitExceeded));
    assert_eq!(std::fs::read(&t).unwrap(), b"previous contents");
    // wrong-length password failure too
    assert!(a.export(&t, &pw("x"), &ska, P).is_err());
    assert_eq!(std::fs::read(&t).unwrap(), b"previous contents");
}

#[test]
fn export_to_vault_file_is_rejected() {
    let (d, path, a, ska, ids) = vault_a();
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        a.export(&path, &pw(XPW), &ska, P),
        Err(Error::InvalidInput(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    #[cfg(unix)]
    {
        let link = d.path().join("link.opx");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(
            a.export(&link, &pw(XPW), &ska, P),
            Err(Error::InvalidInput(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }
    assert_eq!(a.list().unwrap().len(), ids.len());
}

#[test]
fn max_revision_is_readable_and_update_fails() {
    let d = tempfile::tempdir().unwrap();
    let (bp, mut b, skb) = vault_b(&d);
    let id = [9u8; 16];
    let p = write_sealed(
        &d,
        &payload_json(1, &[(id, u64::MAX, item_json("max"))]),
        &skb,
        XPW,
    );
    assert_eq!(b.import(&p, &pw(XPW), &skb).unwrap(), 1);
    let s = b.get(&ItemId(id)).unwrap();
    assert_eq!((s.revision, s.created_ms, s.updated_ms), (u64::MAX, 10, 20));
    let before = std::fs::read(&bp).unwrap();
    assert_eq!(
        b.update(&ItemId(id), &Item::new_login("x")),
        Err(Error::LimitExceeded)
    );
    assert_eq!(std::fs::read(&bp).unwrap(), before);
}

#[test]
fn item_count_limit_imports_nothing() {
    let (d, _p, a, ska, _ids) = vault_a();
    let (bp, mut b, _skb) = vault_b(&d);
    let (xp, _) = export_file(&a, &d, &ska);
    let before = std::fs::read(&bp).unwrap();
    LIMITS.with(|l| l.set((2, MAX_VAULT_FILE)));
    let r = b.import(&xp, &pw(XPW), &ska);
    LIMITS.with(|l| l.set((MAX_RECORDS as usize, MAX_VAULT_FILE)));
    assert_eq!(r, Err(Error::LimitExceeded));
    assert!(b.list().unwrap().is_empty());
    assert_eq!(std::fs::read(&bp).unwrap(), before);
}
