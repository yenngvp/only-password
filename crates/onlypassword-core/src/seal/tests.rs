use super::*;
use crate::crypto::kdf::KdfParams;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};

const VID: [u8; 16] = [0xA1; 16];
const SALT: [u8; 16] = [0xB2; 16];

fn mk(b: u8) -> MasterKey {
    MasterKey::from_secret(SecretBytes::new([b; 32]))
}
fn vk(b: u8) -> VaultKey {
    VaultKey::from_secret(SecretBytes::new([b; 32]))
}
fn header(mkey: &MasterKey, v: &VaultKey) -> Header {
    wrap_vk(mkey, v, VID, KdfParams::FAST_FOR_TESTS, SALT).unwrap()
}
fn item(title: &str) -> Item {
    Item::new_login(title)
}
fn id(b: u8) -> ItemId {
    ItemId([b; 16])
}
fn xc(key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], ct: &[u8]) -> std::result::Result<Vec<u8>, ()> {
    XChaCha20Poly1305::new_from_slice(key)
        .unwrap()
        .decrypt(nonce.into(), Payload { msg: ct, aad: ad })
        .map_err(|_| ())
}

struct Fx {
    mk: MasterKey,
    vk: VaultKey,
    header: Header,
}
fn fx() -> Fx {
    let m = mk(1);
    let v = vk(2);
    let h = header(&m, &v);
    Fx {
        mk: m,
        vk: v,
        header: h,
    }
}
fn rec(f: &Fx, n: u8, rev: u64, title: &str) -> Record {
    seal_item(
        &f.vk.item_wrap_key().unwrap(),
        &VID,
        &id(n),
        rev,
        &item(title),
        10,
        20,
    )
    .unwrap()
}
fn image(f: &Fx, recs: Vec<Record>) -> Vec<u8> {
    build_image(&f.header, recs, &f.vk).unwrap()
}

#[test]
fn roundtrip_and_freshness() {
    let f = fx();
    let kiw = f.vk.item_wrap_key().unwrap();
    let a = seal_item(&kiw, &VID, &id(5), 1, &item("t"), 10, 20).unwrap();
    let b = seal_item(&kiw, &VID, &id(5), 1, &item("t"), 10, 20).unwrap();
    assert_ne!(a.key_nonce, b.key_nonce);
    assert_ne!(a.body_nonce, b.body_nonce);
    assert_ne!(a.wrapped_ik, b.wrapped_ik);
    assert_ne!(a.body_ct, b.body_ct);
    let ov = open_vault(&image(&f, vec![a]), &f.mk).unwrap();
    let (it, c, u) = ov.open_item(&ov.file.records[0]).unwrap();
    assert_eq!((it.title.as_str(), c, u), ("t", 10, 20));
}

#[test]
fn every_single_byte_flip_is_rejected() {
    let f = fx();
    let img = image(&f, vec![rec(&f, 1, 1, "one"), rec(&f, 2, 3, "two")]);
    assert!(open_vault(&img, &f.mk).is_ok());
    for i in 0..img.len() {
        let mut bad = img.clone();
        bad[i] ^= 0x01;
        let r = open_vault(&bad, &f.mk).and_then(|ov| {
            ov.file
                .records
                .iter()
                .map(|r| ov.open_item(r).map(|_| ()))
                .collect::<Result<Vec<_>>>()
        });
        assert!(r.is_err(), "flip at offset {i} accepted");
    }
}

type Mutation = Box<dyn Fn(&mut Record)>;

#[test]
fn record_binding_to_id_revision_vault_and_versions() {
    let f = fx();
    let kiw = f.vk.item_wrap_key().unwrap();
    let good = rec(&f, 1, 1, "x");
    let mutations: Vec<Mutation> = vec![
        Box::new(|r| r.item_id = [9; 16]),
        Box::new(|r| r.revision = 2),
        Box::new(|r| r.item_schema = 2),
        Box::new(|r| r.item_schema = 0),
    ];
    for m in &mutations {
        let mut r = good.clone();
        m(&mut r);
        assert_eq!(
            open_record(&kiw, &VID, &r).unwrap_err(),
            Error::Authentication
        );
        // Trailer recomputed with the right K_fa: only the record-level check is exercised.
        let ov = open_vault(&image(&f, vec![r]), &f.mk).unwrap();
        assert_eq!(
            ov.open_item(&ov.file.records[0]).unwrap_err(),
            Error::Authentication
        );
    }
    assert_eq!(
        open_record(&kiw, &[0; 16], &good).unwrap_err(),
        Error::Authentication
    );
    assert!(open_record(&kiw, &VID, &good).is_ok());
}

#[test]
fn deletion_addition_and_rollback_fail_trailer() {
    let f = fx();
    let r1 = rec(&f, 1, 1, "a");
    let r2 = rec(&f, 2, 1, "b");
    let r2_old = r2.clone();
    let r2_new = rec(&f, 2, 2, "b2");
    let base = open_vault(&image(&f, vec![r1.clone(), r2_new.clone()]), &f.mk).unwrap();
    let trailer = base.file.trailer.clone();
    let with_old_trailer = |recs: Vec<Record>| {
        let mut vf = base.file.clone();
        vf.records = recs;
        vf.trailer = trailer.clone();
        vf.serialize().unwrap()
    };
    // deletion
    let e = open_vault(&with_old_trailer(vec![r1.clone()]), &f.mk).unwrap_err();
    assert_eq!(e, Error::Authentication);
    // addition of a record validly sealed under the same keys
    let r3 = rec(&f, 3, 1, "c");
    let e = open_vault(
        &with_old_trailer(vec![r1.clone(), r2_new.clone(), r3]),
        &f.mk,
    )
    .unwrap_err();
    assert_eq!(e, Error::Authentication);
    // rollback of one record to an older valid revision
    let e = open_vault(&with_old_trailer(vec![r1, r2_old]), &f.mk).unwrap_err();
    assert_eq!(e, Error::Authentication);
}

#[test]
fn wrong_mk_and_edited_kdf_params() {
    let f = fx();
    assert_eq!(
        unwrap_vk(&mk(9), &f.header).unwrap_err(),
        Error::Authentication
    );
    assert_eq!(unwrap_vk(&f.mk, &f.header).unwrap().expose(), f.vk.expose());
    let mut h = f.header.clone();
    h.kdf.t += 1;
    assert_eq!(unwrap_vk(&f.mk, &h).unwrap_err(), Error::Authentication);
    // via bytes: parse accepts (in range) and unwrap rejects
    let img = image(&f, vec![rec(&f, 1, 1, "a")]);
    let mut bad = img.clone();
    bad[37] ^= 1; // kdf_t low byte
    let e = open_vault(&bad, &f.mk).unwrap_err();
    assert!(matches!(e, Error::Authentication | Error::Corrupt(_)));
    // out of range m is Corrupt
    let mut bad = img;
    bad[30] = 0xFF;
    assert!(matches!(
        open_vault(&bad, &f.mk).unwrap_err(),
        Error::Corrupt(_)
    ));
}

#[test]
fn ad_layout_independent_check() {
    let f = fx();
    let img = image(&f, vec![rec(&f, 7, 4, "ad")]);
    // AD_VK from the layout: label ‖ bytes 0..82.
    let ad_vk_b = [&b"onlypassword/v1/vault-key"[..], &img[..82]].concat();
    assert_eq!(ad_vk_b.len(), 25 + 82);
    let vk_pt = xc(
        f.mk.expose(),
        img[58..82].try_into().unwrap(),
        &ad_vk_b,
        &img[82..130],
    )
    .unwrap();
    assert_eq!(vk_pt, f.vk.expose());
    // Record at 134 + 4.
    let r = &img[138..img.len() - 40];
    let suffix = [
        &img[12..28],
        &r[0..16],
        &r[16..24],
        &[0, 1][..],
        &[0, 1][..],
    ]
    .concat();
    assert_eq!(suffix.len(), 44);
    let ad_ik = [&b"onlypassword/v1/item-key"[..], &suffix].concat();
    let ad_body = [&b"onlypassword/v1/item-body"[..], &suffix].concat();
    let mut kiw = [0u8; 32];
    {
        use hkdf::Hkdf;
        Hkdf::<Sha256>::from_prk(f.vk.expose())
            .unwrap()
            .expand(b"onlypassword/v1/item-key-wrap", &mut kiw)
            .unwrap();
    }
    let ik = xc(&kiw, r[26..50].try_into().unwrap(), &ad_ik, &r[50..98]).unwrap();
    let ik: [u8; 32] = ik.try_into().unwrap();
    let pt = xc(&ik, r[98..122].try_into().unwrap(), &ad_body, &r[126..]).unwrap();
    assert!(String::from_utf8(pt).unwrap().contains("\"title\":\"ad\""));
    // AD_FILE and trailer.
    let h = Sha256::digest(&img[..img.len() - 40]);
    let ad_file_b = [&b"onlypassword/v1/file"[..], h.as_slice()].concat();
    assert_eq!(ad_file_b.len(), 52);
    let mut kfa = [0u8; 32];
    hkdf::Hkdf::<Sha256>::from_prk(f.vk.expose())
        .unwrap()
        .expand(b"onlypassword/v1/file-auth", &mut kfa)
        .unwrap();
    let t = &img[img.len() - 40..];
    assert!(xc(&kfa, t[..24].try_into().unwrap(), &ad_file_b, &t[24..])
        .unwrap()
        .is_empty());
}

#[test]
fn no_record_decrypted_when_trailer_fails() {
    // Records sealed under a different VK, header wraps ours: the trailer (K_fa of ours)
    // cannot verify. open_vault returns no OpenedVault, and open_item exists only on
    // OpenedVault, so no decryption of any record is reachable.
    let f = fx();
    let other = vk(3);
    let foreign = seal_item(
        &other.item_wrap_key().unwrap(),
        &VID,
        &id(1),
        1,
        &item("z"),
        1,
        1,
    )
    .unwrap();
    let mut vf = VaultFile {
        header: f.header.clone(),
        records: vec![foreign],
        trailer: Trailer {
            nonce: [0; 24],
            tag: [0; 16],
        },
    };
    let mut img = vf.serialize().unwrap();
    img.truncate(img.len() - 40);
    vf.trailer = compute_trailer(&other.file_auth_key().unwrap(), &img).unwrap();
    img.extend_from_slice(&vf.trailer.nonce);
    img.extend_from_slice(&vf.trailer.tag);
    assert_eq!(open_vault(&img, &f.mk).unwrap_err(), Error::Authentication);
}

#[test]
fn schema_handling() {
    let f = fx();
    let kiw = f.vk.item_wrap_key().unwrap();
    let plain = item("s").to_plaintext(1, 1).unwrap();
    let s = String::from_utf8(plain.to_vec()).unwrap();
    assert!(s.starts_with("{\"schema\":1,"));
    let json2 = s.replacen("\"schema\":1", "\"schema\":2", 1);
    // record schema 1, JSON schema 2 -> UnsupportedVersion
    let r = seal_record(&kiw, &VID, &[1; 16], 1, 1, json2.as_bytes()).unwrap();
    assert_eq!(
        open_record(&kiw, &VID, &r).unwrap_err(),
        Error::UnsupportedVersion
    );
    // record schema 2, JSON schema 1 -> Corrupt
    let r = seal_record(&kiw, &VID, &[1; 16], 1, 2, s.as_bytes()).unwrap();
    assert!(matches!(
        open_record(&kiw, &VID, &r).unwrap_err(),
        Error::Corrupt(_)
    ));
}

#[test]
fn revision_zero_rejected() {
    let f = fx();
    let kiw = f.vk.item_wrap_key().unwrap();
    assert!(seal_item(&kiw, &VID, &id(1), 0, &item("a"), 1, 1).is_err());
}
