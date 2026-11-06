//! F022: authenticated-but-invalid record bodies. The body is sealed with the internal seal API
//! (so the AEAD tags are valid) and `get` must still reject the content.

use super::*;
use crate::crypto::kdf::KdfParams;
use serde_json::Value;

fn seal_body(v: &mut Vault, id: &ItemId, body: &[u8]) {
    let rec = seal::seal_record(&v.k_iw, &v.file.header.vault_id, &id.0, 1, 1, body).unwrap();
    let mut records = v.file.records.clone();
    records.push(rec);
    records.sort_by_key(|r| r.item_id);
    v.commit(records).unwrap();
}

fn valid_json() -> Value {
    let mut i = Item::new_login("t");
    i.username = Some("u".into());
    let bytes = i.to_plaintext(5, 6).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn get_err(body: Vec<u8>) -> Error {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("v.opv");
    let (mut v, _sk) = Vault::create(
        &path,
        &SecretString::new("correct horse".into()),
        KdfParams::FAST_FOR_TESTS,
    )
    .unwrap();
    let id = ItemId([7; 16]);
    seal_body(&mut v, &id, &body);
    match v.get(&id) {
        Err(e) => e,
        Ok(_) => panic!("get must fail"),
    }
}

fn to_bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

#[test]
fn control_valid_body_is_accepted() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("v.opv");
    let (mut v, _sk) = Vault::create(
        &path,
        &SecretString::new("correct horse".into()),
        KdfParams::FAST_FOR_TESTS,
    )
    .unwrap();
    let id = ItemId([7; 16]);
    seal_body(&mut v, &id, &to_bytes(&valid_json()));
    assert_eq!(v.get(&id).unwrap().item.title, "t");
}

#[test]
fn invalid_json_is_corrupt() {
    for body in [&b"not json"[..], b"", b"{", b"[]", b"null", b"\xff\xfe"] {
        assert!(
            matches!(get_err(body.to_vec()), Error::Corrupt(_)),
            "{body:?}"
        );
    }
}

#[test]
fn unknown_field_is_corrupt() {
    let mut j = valid_json();
    j["bogus"] = Value::from(1);
    assert!(matches!(get_err(to_bytes(&j)), Error::Corrupt(_)));
    let mut j = valid_json();
    j["fields"] = serde_json::json!([{"name":"a","value":"b","hidden":false,"x":1}]);
    assert!(matches!(get_err(to_bytes(&j)), Error::Corrupt(_)));
}

#[test]
fn schema_two_is_unsupported_even_with_unknown_field() {
    let mut j = valid_json();
    j["schema"] = Value::from(2);
    assert!(matches!(get_err(to_bytes(&j)), Error::UnsupportedVersion));
    j["bogus"] = Value::from(1);
    assert!(matches!(get_err(to_bytes(&j)), Error::UnsupportedVersion));
}

#[test]
fn absent_nullable_key_is_corrupt() {
    for key in ["username", "password", "totp"] {
        let mut j = valid_json();
        j.as_object_mut().unwrap().remove(key);
        assert!(matches!(get_err(to_bytes(&j)), Error::Corrupt(_)), "{key}");
    }
}
