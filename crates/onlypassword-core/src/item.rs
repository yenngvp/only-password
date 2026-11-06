//! Item model, validation and schema-1 JSON plaintext (CS §7).

use crate::base32;
use crate::rng;
use crate::{Error, Result, SecretString};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::str::FromStr;
use zeroize::Zeroizing;

/// Maximum serialized item plaintext (CS §10).
pub const MAX_ITEM_PLAINTEXT: usize = 1_048_576;

const MAX_TITLE: usize = 1024;
const MAX_CRED: usize = 4096;
const MAX_URLS: usize = 64;
const MAX_URL: usize = 4096;
const MAX_NOTES: usize = 65_536;
const MAX_FIELDS: usize = 256;
const MAX_FIELD_NAME: usize = 256;
const MAX_FIELD_VALUE: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    Login,
    Note,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug)]
pub struct TotpConfig {
    /// Canonical base32 (CS §7).
    pub secret: SecretString,
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u32,
}

#[derive(Debug)]
pub struct CustomField {
    pub name: String,
    pub value: SecretString,
    pub hidden: bool,
}

#[derive(Debug)]
pub struct Item {
    pub kind: ItemKind,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub urls: Vec<String>,
    pub notes: SecretString,
    pub totp: Option<TotpConfig>,
    pub fields: Vec<CustomField>,
}

/// 16-byte item identifier; text form is 32 lower-case hex characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemId(pub [u8; 16]);

impl ItemId {
    pub fn generate() -> Result<ItemId> {
        Ok(ItemId(rng::random_array::<16>()?))
    }
}

impl fmt::Display for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&base32::hex_encode(&self.0))
    }
}

impl FromStr for ItemId {
    type Err = Error;
    fn from_str(s: &str) -> Result<ItemId> {
        if s.len() != 32 {
            return Err(Error::InvalidInput("bad item id"));
        }
        let v = base32::hex_decode(s)?;
        let arr: [u8; 16] = v
            .try_into()
            .map_err(|_| Error::InvalidInput("bad item id"))?;
        Ok(ItemId(arr))
    }
}

fn inv(m: &'static str) -> Error {
    Error::InvalidInput(m)
}

fn check_totp_secret(s: &str) -> Result<()> {
    let raw = base32::decode_strict(s).map_err(|_| inv("totp secret"))?;
    let raw = crate::SecretVec::new(raw);
    if !(10..=128).contains(&raw.len()) || base32::encode(raw.expose()) != s {
        return Err(inv("totp secret"));
    }
    Ok(())
}

impl Item {
    pub fn new_login(title: impl Into<String>) -> Item {
        Item {
            kind: ItemKind::Login,
            title: title.into(),
            username: None,
            password: None,
            urls: Vec::new(),
            notes: SecretString::new(String::new()),
            totp: None,
            fields: Vec::new(),
        }
    }

    pub fn new_note(title: impl Into<String>, notes: SecretString) -> Item {
        Item {
            kind: ItemKind::Note,
            title: title.into(),
            username: None,
            password: None,
            urls: Vec::new(),
            notes,
            totp: None,
            fields: Vec::new(),
        }
    }

    /// Check every limit and kind rule of CS §7.
    pub fn validate(&self) -> Result<()> {
        if self.title.is_empty() || self.title.len() > MAX_TITLE {
            return Err(inv("title length"));
        }
        if self.username.as_ref().is_some_and(|u| u.len() > MAX_CRED) {
            return Err(inv("username length"));
        }
        if self
            .password
            .as_ref()
            .is_some_and(|p| p.expose().len() > MAX_CRED)
        {
            return Err(inv("password length"));
        }
        if self.urls.len() > MAX_URLS || self.urls.iter().any(|u| u.len() > MAX_URL) {
            return Err(inv("urls"));
        }
        if self.notes.expose().len() > MAX_NOTES {
            return Err(inv("notes length"));
        }
        if self.fields.len() > MAX_FIELDS {
            return Err(inv("too many fields"));
        }
        for f in &self.fields {
            if f.name.is_empty()
                || f.name.len() > MAX_FIELD_NAME
                || f.value.expose().len() > MAX_FIELD_VALUE
            {
                return Err(inv("custom field"));
            }
        }
        if let Some(t) = &self.totp {
            if !(6..=8).contains(&t.digits) || !(1..=300).contains(&t.period) {
                return Err(inv("totp parameters"));
            }
            check_totp_secret(t.secret.expose())?;
        }
        if self.kind == ItemKind::Note
            && (self.username.is_some()
                || self.password.is_some()
                || self.totp.is_some()
                || !self.urls.is_empty())
        {
            return Err(inv("note carries login data"));
        }
        Ok(())
    }

    /// Serialize the schema-1 plaintext. Timestamps live beside the item
    /// (see `StoredItem`), so the caller supplies them.
    pub fn to_plaintext(&self, created_ms: u64, updated_ms: u64) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        if updated_ms < created_ms {
            return Err(inv("timestamps"));
        }
        let mut sum = self.title.len() + self.notes.expose().len();
        sum += self.username.as_ref().map_or(0, |s| s.len());
        sum += self.password.as_ref().map_or(0, |s| s.expose().len());
        sum += self.urls.iter().map(|u| u.len() + 3).sum::<usize>();
        sum += self
            .fields
            .iter()
            .map(|f| f.name.len() + f.value.expose().len() + 48)
            .sum::<usize>();
        sum += self
            .totp
            .as_ref()
            .map_or(0, |t| t.secret.expose().len() + 64);
        let cap = (sum + sum / 8 + 256).min(MAX_ITEM_PLAINTEXT + 4096);
        let mut out = Zeroizing::new(Vec::with_capacity(cap));

        let w = WireOut {
            schema: 1,
            kind: self.kind,
            title: &self.title,
            created_ms,
            updated_ms,
            username: self.username.as_deref(),
            password: self.password.as_ref().map(|p| p.expose()),
            urls: &self.urls,
            notes: self.notes.expose(),
            totp: self.totp.as_ref().map(|t| TotpOut {
                secret: t.secret.expose(),
                algorithm: t.algorithm,
                digits: t.digits,
                period: t.period,
            }),
            fields: self
                .fields
                .iter()
                .map(|f| FieldOut {
                    name: &f.name,
                    value: f.value.expose(),
                    hidden: f.hidden,
                })
                .collect(),
        };
        serde_json::to_writer(&mut *out, &w).map_err(|_| Error::Corrupt("serialize"))?;
        if out.len() > MAX_ITEM_PLAINTEXT {
            return Err(Error::LimitExceeded);
        }
        Ok(out)
    }

    /// Parse and validate a schema-1 plaintext; returns the item and
    /// `(created_ms, updated_ms)`.
    pub fn from_plaintext(bytes: &[u8]) -> Result<(Item, u64, u64)> {
        if bytes.len() > MAX_ITEM_PLAINTEXT {
            return Err(inv("plaintext too large"));
        }
        let probe: Probe =
            serde_json::from_slice(bytes).map_err(|_| Error::Corrupt("schema probe"))?;
        if probe.schema != 1 {
            return Err(Error::UnsupportedVersion);
        }
        let w: WireIn = serde_json::from_slice(bytes).map_err(|_| Error::Corrupt("item json"))?;
        if w.updated_ms < w.created_ms {
            return Err(Error::Corrupt("timestamps"));
        }
        let (c, u) = (w.created_ms, w.updated_ms);
        let item = Item {
            kind: w.kind,
            title: w.title,
            username: w.username,
            password: w.password.map(|s| s.0),
            urls: w.urls,
            notes: w.notes.0,
            totp: w.totp.map(|t| TotpConfig {
                secret: t.secret.0,
                algorithm: t.algorithm,
                digits: t.digits,
                period: t.period,
            }),
            fields: w
                .fields
                .into_iter()
                .map(|f| CustomField {
                    name: f.name,
                    value: f.value.0,
                    hidden: f.hidden,
                })
                .collect(),
        };
        item.validate().map_err(|_| Error::Corrupt("item rules"))?;
        Ok((item, c, u))
    }
}

// ---- wire types ----

#[derive(Serialize)]
struct WireOut<'a> {
    schema: u32,
    kind: ItemKind,
    title: &'a str,
    created_ms: u64,
    updated_ms: u64,
    username: Option<&'a str>,
    password: Option<&'a str>,
    urls: &'a [String],
    notes: &'a str,
    totp: Option<TotpOut<'a>>,
    fields: Vec<FieldOut<'a>>,
}

#[derive(Serialize)]
struct TotpOut<'a> {
    secret: &'a str,
    algorithm: TotpAlgorithm,
    digits: u8,
    period: u32,
}

#[derive(Serialize)]
struct FieldOut<'a> {
    name: &'a str,
    value: &'a str,
    hidden: bool,
}

impl Serialize for ItemKind {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            ItemKind::Login => "login",
            ItemKind::Note => "note",
        })
    }
}

impl Serialize for TotpAlgorithm {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        })
    }
}

#[derive(Deserialize)]
enum KindIn {
    #[serde(rename = "login")]
    Login,
    #[serde(rename = "note")]
    Note,
}

#[derive(Deserialize)]
enum AlgIn {
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA512")]
    Sha512,
}

impl<'de> Deserialize<'de> for ItemKind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Ok(match KindIn::deserialize(d)? {
            KindIn::Login => ItemKind::Login,
            KindIn::Note => ItemKind::Note,
        })
    }
}

impl<'de> Deserialize<'de> for TotpAlgorithm {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Ok(match AlgIn::deserialize(d)? {
            AlgIn::Sha1 => TotpAlgorithm::Sha1,
            AlgIn::Sha256 => TotpAlgorithm::Sha256,
            AlgIn::Sha512 => TotpAlgorithm::Sha512,
        })
    }
}

/// Secret string read straight into a `SecretString` (no extra copy).
struct Sec(SecretString);

impl<'de> Deserialize<'de> for Sec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(d).map(|s| Sec(SecretString::new(s)))
    }
}

/// Nullable but required: an absent key is an error (no implicit `Option` default).
fn required<'de, D, T>(d: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

#[derive(Deserialize)]
struct Probe {
    schema: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct WireIn {
    schema: u32,
    kind: ItemKind,
    title: String,
    created_ms: u64,
    updated_ms: u64,
    #[serde(deserialize_with = "required")]
    username: Option<String>,
    #[serde(deserialize_with = "required")]
    password: Option<Sec>,
    urls: Vec<String>,
    notes: Sec,
    #[serde(deserialize_with = "required")]
    totp: Option<TotpIn>,
    fields: Vec<FieldIn>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TotpIn {
    secret: Sec,
    algorithm: TotpAlgorithm,
    digits: u8,
    period: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldIn {
    name: String,
    value: Sec,
    hidden: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const S: &str = "hunter2-sentinel";
    const SECRET: &str = "JBSWY3DPEHPK3PXP"; // 10 bytes

    fn full() -> Item {
        let mut i = Item::new_login("Example");
        i.username = Some("alice".into());
        i.password = Some(SecretString::new(S.into()));
        i.urls = vec!["https://example.com".into(), "https://b.example".into()];
        i.notes = SecretString::new("some \"notes\"\n".into());
        i.totp = Some(TotpConfig {
            secret: SecretString::new(SECRET.into()),
            algorithm: TotpAlgorithm::Sha256,
            digits: 8,
            period: 60,
        });
        i.fields = vec![
            CustomField {
                name: "pin".into(),
                value: SecretString::new("1234".into()),
                hidden: true,
            },
            CustomField {
                name: "q".into(),
                value: SecretString::new(String::new()),
                hidden: false,
            },
        ];
        i
    }

    const FULL_JSON: &str = concat!(
        r#"{"schema":1,"kind":"login","title":"Example","created_ms":1000,"updated_ms":2000,"#,
        r#""username":"alice","password":"hunter2-sentinel","#,
        r#""urls":["https://example.com","https://b.example"],"notes":"some \"notes\"\n","#,
        r#""totp":{"secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA256","digits":8,"period":60},"#,
        r#""fields":[{"name":"pin","value":"1234","hidden":true},{"name":"q","value":"","hidden":false}]}"#
    );

    const NOTE_JSON: &str = r#"{"schema":1,"kind":"note","title":"n","created_ms":1,"updated_ms":1,"username":null,"password":null,"urls":[],"notes":"hi","totp":null,"fields":[]}"#;

    fn same(a: &Item, b: &Item) {
        assert_eq!(a.kind, b.kind);
        assert_eq!(a.title, b.title);
        assert_eq!(a.username, b.username);
        assert_eq!(
            a.password.as_ref().map(|p| p.expose().to_owned()),
            b.password.as_ref().map(|p| p.expose().to_owned())
        );
        assert_eq!(a.urls, b.urls);
        assert_eq!(a.notes.expose(), b.notes.expose());
        match (&a.totp, &b.totp) {
            (None, None) => {}
            (Some(x), Some(y)) => {
                assert_eq!(x.secret.expose(), y.secret.expose());
                assert_eq!(x.algorithm, y.algorithm);
                assert_eq!((x.digits, x.period), (y.digits, y.period));
            }
            _ => panic!("totp differs"),
        }
        assert_eq!(a.fields.len(), b.fields.len());
        for (x, y) in a.fields.iter().zip(&b.fields) {
            assert_eq!(
                (&x.name, x.value.expose(), x.hidden),
                (&y.name, y.value.expose(), y.hidden)
            );
        }
    }

    #[test]
    fn exact_bytes_and_determinism() {
        let a = full().to_plaintext(1000, 2000).unwrap();
        assert_eq!(std::str::from_utf8(&a).unwrap(), FULL_JSON);
        assert_eq!(*a, *full().to_plaintext(1000, 2000).unwrap());
        let n = Item::new_note("n", SecretString::new("hi".into()));
        assert_eq!(
            std::str::from_utf8(&n.to_plaintext(1, 1).unwrap()).unwrap(),
            NOTE_JSON
        );
    }

    #[test]
    fn roundtrips() {
        let (i, c, u) = Item::from_plaintext(FULL_JSON.as_bytes()).unwrap();
        same(&i, &full());
        assert_eq!((c, u), (1000, 2000));
        let bytes = i.to_plaintext(c, u).unwrap();
        assert_eq!(&*bytes, FULL_JSON.as_bytes());
        let (n, _, _) = Item::from_plaintext(NOTE_JSON.as_bytes()).unwrap();
        same(&n, &Item::new_note("n", SecretString::new("hi".into())));
    }

    #[test]
    fn json_keys_and_types() {
        let v: Value = serde_json::from_slice(&full().to_plaintext(1000, 2000).unwrap()).unwrap();
        let o = v.as_object().unwrap();
        let mut keys: Vec<_> = o.keys().cloned().collect();
        keys.sort();
        let mut want = vec![
            "schema",
            "kind",
            "title",
            "created_ms",
            "updated_ms",
            "username",
            "password",
            "urls",
            "notes",
            "totp",
            "fields",
        ];
        want.sort();
        assert_eq!(keys, want);
        assert!(o["schema"].is_u64() && o["created_ms"].is_u64() && o["urls"].is_array());
        let t = o["totp"].as_object().unwrap();
        assert!(t["secret"].is_string() && t["digits"].is_u64() && t["period"].is_u64());
        assert_eq!(t["algorithm"], "SHA256");
        assert!(o["fields"][0]["hidden"].is_boolean());
    }

    fn mutate(f: impl Fn(&mut serde_json::Map<String, Value>)) -> String {
        let mut v: Value = serde_json::from_str(FULL_JSON).unwrap();
        f(v.as_object_mut().unwrap());
        serde_json::to_string(&v).unwrap()
    }

    fn corrupt(s: &str) {
        assert!(
            matches!(Item::from_plaintext(s.as_bytes()), Err(Error::Corrupt(_))),
            "{s}"
        );
    }

    #[test]
    fn unknown_duplicate_missing_wrongtype() {
        corrupt(&mutate(|o| {
            o.insert("extra".into(), Value::Null);
        }));
        corrupt(&FULL_JSON.replacen("{\"schema\":1,", "{\"schema\":1,\"title\":\"x\",", 1));
        corrupt(&FULL_JSON.replace("\"digits\":8,", "\"digits\":8,\"digits\":8,"));
        corrupt(&FULL_JSON.replace("\"hidden\":true", "\"hidden\":true,\"hidden\":true"));
        corrupt(&FULL_JSON.replace("\"period\":60", "\"period\":60,\"x\":1"));
        corrupt(&FULL_JSON.replace("\"hidden\":true", "\"hidden\":true,\"x\":1"));
        let keys = [
            "kind",
            "title",
            "created_ms",
            "updated_ms",
            "username",
            "password",
            "urls",
            "notes",
            "totp",
            "fields",
        ];
        for k in keys {
            corrupt(&mutate(|o| {
                o.remove(k);
            }));
        }
        // nullable keys absent while the others are present, in a note too
        for k in ["username", "password", "totp"] {
            let mut v: Value = serde_json::from_str(NOTE_JSON).unwrap();
            v.as_object_mut().unwrap().remove(k);
            corrupt(&v.to_string());
        }
        for k in ["secret", "algorithm", "digits", "period"] {
            corrupt(&mutate(|o| {
                o["totp"].as_object_mut().unwrap().remove(k);
            }));
        }
        for k in ["name", "value", "hidden"] {
            corrupt(&mutate(|o| {
                o["fields"][0].as_object_mut().unwrap().remove(k);
            }));
        }
        corrupt(&mutate(|o| {
            o.insert("title".into(), Value::from(5));
        }));
        corrupt(&mutate(|o| {
            o.insert("urls".into(), Value::from("x"));
        }));
        corrupt(&mutate(|o| {
            o.insert("kind".into(), Value::from("Login"));
        }));
        corrupt(&mutate(|o| {
            o["totp"]["algorithm"] = Value::from("MD5");
        }));
        corrupt(&mutate(|o| {
            o.insert("created_ms".into(), Value::from(5000));
        })); // updated < created
        for junk in ["", "[]", "null", "{", "1", &format!("{FULL_JSON} x")] {
            assert!(Item::from_plaintext(junk.as_bytes()).is_err());
        }
        assert!(Item::from_plaintext(&[0xff, 0xfe, b'{']).is_err());
    }

    #[test]
    fn rule_violations_are_corrupt() {
        let big = |n| "a".repeat(n);
        corrupt(&mutate(|o| {
            o.insert("title".into(), Value::from(""));
        }));
        corrupt(&mutate(|o| {
            o.insert("title".into(), Value::from(big(1025)));
        }));
        corrupt(&mutate(|o| {
            o.insert("urls".into(), Value::from(vec!["u"; 65]));
        }));
        corrupt(&mutate(|o| {
            o.insert(
                "fields".into(),
                Value::from(vec![
                    serde_json::json!({"name":"a","value":"","hidden":false});
                    257
                ]),
            );
        }));
        for d in [5, 9] {
            corrupt(&mutate(|o| {
                o["totp"]["digits"] = Value::from(d);
            }));
        }
        for p in [0, 301] {
            corrupt(&mutate(|o| {
                o["totp"]["period"] = Value::from(p);
            }));
        }
        corrupt(&mutate(|o| {
            o["totp"]["secret"] = Value::from("jbswy3dpehpk3pxp");
        }));
        // note with a password
        let n = NOTE_JSON.replace("\"password\":null", "\"password\":\"x\"");
        corrupt(&n);
        corrupt(&NOTE_JSON.replace("\"urls\":[]", "\"urls\":[\"u\"]"));
    }

    #[test]
    fn size_limit_is_invalid_input() {
        let mut v = vec![b' '; MAX_ITEM_PLAINTEXT + 1];
        v[0] = b'{';
        assert!(matches!(
            Item::from_plaintext(&v),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn schema_handling() {
        for s in ["0", "2", "-1", "99999999999"] {
            let j = FULL_JSON.replacen("\"schema\":1", &format!("\"schema\":{s}"), 1);
            assert_eq!(
                Item::from_plaintext(j.as_bytes()).unwrap_err(),
                Error::UnsupportedVersion,
                "{s}"
            );
            let j2 = j.replacen("{", "{\"unknown\":1,", 1);
            assert_eq!(
                Item::from_plaintext(j2.as_bytes()).unwrap_err(),
                Error::UnsupportedVersion
            );
        }
        corrupt(&mutate(|o| {
            o.remove("schema");
        }));
        corrupt(&FULL_JSON.replacen("\"schema\":1,", "\"schema\":1,\"schema\":1,", 1));
        corrupt(&FULL_JSON.replacen("\"schema\":1", "\"schema\":\"1\"", 1));
        corrupt(&FULL_JSON.replacen("\"schema\":1", "\"schema\":1.5", 1));
        corrupt(&FULL_JSON.replacen("\"schema\":1", "\"schema\":1.0", 1));
    }

    fn invalid(i: &Item) {
        assert!(matches!(i.validate(), Err(Error::InvalidInput(_))));
    }

    #[test]
    fn validate_rejects() {
        full().validate().unwrap();
        let mut i = full();
        i.title = String::new();
        invalid(&i);
        i.title = "a".repeat(1025);
        invalid(&i);
        i.title = "a".repeat(1024);
        i.validate().unwrap();
        let mut i = full();
        i.urls = vec!["u".into(); 65];
        invalid(&i);
        let mut i = full();
        i.urls = vec!["u".repeat(4097)];
        invalid(&i);
        let mut i = full();
        i.fields = (0..257)
            .map(|_| CustomField {
                name: "a".into(),
                value: SecretString::new(String::new()),
                hidden: false,
            })
            .collect();
        invalid(&i);
        let mut i = full();
        i.username = Some("a".repeat(4097));
        invalid(&i);
        let mut i = full();
        i.password = Some(SecretString::new("a".repeat(4097)));
        invalid(&i);
        let mut i = full();
        i.notes = SecretString::new("a".repeat(65537));
        invalid(&i);
        let mut i = full();
        i.fields[0].name = String::new();
        invalid(&i);
        let mut i = full();
        i.fields[0].value = SecretString::new("a".repeat(65537));
        invalid(&i);
        for (d, p) in [(5, 60), (9, 60), (6, 0), (6, 301)] {
            let mut i = full();
            let t = i.totp.as_mut().unwrap();
            t.digits = d;
            t.period = p;
            invalid(&i);
        }
        // note rules
        let mut n = Item::new_note("n", SecretString::new(String::new()));
        n.validate().unwrap();
        n.password = Some(SecretString::new("x".into()));
        invalid(&n);
        let mut n = Item::new_note("n", SecretString::new(String::new()));
        n.username = Some("x".into());
        invalid(&n);
        let mut n = Item::new_note("n", SecretString::new(String::new()));
        n.urls.push("u".into());
        invalid(&n);
        let mut n = Item::new_note("n", SecretString::new(String::new()));
        n.totp = full().totp;
        invalid(&n);
    }

    #[test]
    fn validate_totp_secret() {
        // 9 bytes = 72 bits -> 15 chars (last has 3 spare bits ... use exact encodings)
        let ok16 = "JBSWY3DPEHPK3PXP";
        let b9 = base32::encode(&[7u8; 9]);
        let b10 = base32::encode(&[7u8; 10]);
        let b128 = base32::encode(&[7u8; 128]);
        let b129 = base32::encode(&[7u8; 129]);
        let cases: Vec<(String, bool)> = vec![
            (ok16.into(), true),
            (b10, true),
            (b128, true),
            (b9, false),
            (b129, false),
            (ok16.to_lowercase(), false),
            (format!("{ok16}===="), false),
            (format!("{} {}", &ok16[..8], &ok16[8..]), false),
            (format!("{}-{}", &ok16[..8], &ok16[8..]), false),
            (String::new(), false),
        ];
        for (s, good) in cases {
            let mut i = full();
            i.totp.as_mut().unwrap().secret = SecretString::new(s.clone());
            assert_eq!(i.validate().is_ok(), good, "{s}");
        }
        // 11 bytes -> 18 chars, last char carries 3 spare bits; set one
        let mut enc = base32::encode(&[0u8; 11]).into_bytes();
        assert_eq!(enc.len(), 18);
        enc[17] = b'B'; // value 1 -> non-zero trailing bits
        let mut i = full();
        i.totp.as_mut().unwrap().secret = SecretString::new(String::from_utf8(enc).unwrap());
        invalid(&i);
    }

    #[test]
    fn to_plaintext_rejects_bad_input() {
        assert!(full().to_plaintext(5, 4).is_err());
        let mut i = full();
        i.title.clear();
        assert!(matches!(i.to_plaintext(1, 1), Err(Error::InvalidInput(_))));
        // validate passes but plaintext exceeds 1 MiB
        let mut i = full();
        i.fields = (0..32)
            .map(|_| CustomField {
                name: "a".into(),
                value: SecretString::new("b".repeat(65536)),
                hidden: false,
            })
            .collect();
        assert_eq!(i.to_plaintext(1, 1).unwrap_err(), Error::LimitExceeded);
    }

    #[test]
    fn item_id() {
        let id = ItemId([0xab; 16]);
        assert_eq!(id.to_string(), "ab".repeat(16));
        assert_eq!(id.to_string().parse::<ItemId>().unwrap(), id);
        for bad in [
            "AB".repeat(16),
            "ab".repeat(15),
            "ab".repeat(17),
            "zz".repeat(16),
            String::new(),
        ] {
            assert!(bad.parse::<ItemId>().is_err(), "{bad}");
        }
        let g = ItemId::generate().unwrap();
        assert_eq!(g.to_string().len(), 32);
        assert_ne!(g, ItemId::generate().unwrap());
    }

    #[test]
    fn debug_redacts() {
        let mut i = full();
        i.fields[0].value = SecretString::new(S.into());
        i.totp.as_mut().unwrap().secret = SecretString::new(SECRET.into());
        i.notes = SecretString::new("note-sentinel".into());
        let d = format!("{i:?}");
        assert!(!d.contains(S) && !d.contains(SECRET) && !d.contains("note-sentinel"));
        assert!(d.contains("Example"));
    }

    #[test]
    fn errors_do_not_leak() {
        let j = FULL_JSON.replace("\"digits\":8", "\"digits\":9");
        let e = Item::from_plaintext(j.as_bytes()).unwrap_err();
        assert!(!format!("{e:?}{e}").contains(S));
    }
}
