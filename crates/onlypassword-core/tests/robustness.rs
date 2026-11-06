//! F022: hostile-input robustness through the public API. Seeded xorshift, no extra dependency.
//! Nothing here catches panics: a panic fails the test.

use onlypassword_core::base32::parse_totp_secret;
use onlypassword_core::crypto::kdf::KdfParams;
use onlypassword_core::crypto::keys::SecretKey;
use onlypassword_core::{
    generate_passphrase, generate_password, hotp, totp, totp_for_item, CustomField, Error, Item,
    ItemId, ItemKind, PassphraseOptions, PasswordOptions, SecretString, TotpAlgorithm, TotpConfig,
    Vault,
};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const P: KdfParams = KdfParams::FAST_FOR_TESTS;
const LIMIT: Duration = Duration::from_secs(5);
const VAULT_PW: &str = "correct horse battery";
const EXPORT_PW: &str = "export password 1";
const VAULT_MAGIC: &[u8; 8] = b"OPVAULT\0";
const EXPORT_MAGIC: &[u8; 8] = b"OPEXPORT";

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

fn pw(s: &str) -> SecretString {
    SecretString::new(s.to_string())
}

/// Everything observable about an item, as plaintext JSON plus id and revision.
type Print = Vec<(String, u64, Vec<u8>)>;

fn fingerprint(v: &Vault) -> Print {
    let mut out = Vec::new();
    for s in v.list().expect("list") {
        let st = v.get(&s.id).expect("get");
        let json = st
            .item
            .to_plaintext(st.created_ms, st.updated_ms)
            .expect("plaintext");
        out.push((st.id.to_string(), st.revision, json.to_vec()));
    }
    out
}

struct Fixture {
    _dir: tempfile::TempDir,
    dir: PathBuf,
    key: SecretKey,
    vault_bytes: Vec<u8>,
    export_bytes: Vec<u8>,
    empty_vault_bytes: Vec<u8>,
    want: Print,
}

fn login() -> Item {
    let mut i = Item::new_login("Example");
    i.username = Some("alice".into());
    i.password = Some(pw("p@ss-sentinel"));
    i.urls = vec!["https://example.com".into()];
    i.notes = pw("note");
    i.totp = Some(TotpConfig {
        secret: pw("JBSWY3DPEHPK3PXP"),
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
    });
    i.fields = vec![CustomField {
        name: "pin".into(),
        value: pw("1234"),
        hidden: true,
    }];
    i
}

fn fixture() -> Fixture {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().to_path_buf();
    let vp = dir.join("src.opv");
    let (mut v, key) = Vault::create(&vp, &pw(VAULT_PW), P).unwrap();
    v.add(&login()).unwrap();
    v.add(&Item::new_note("n", pw("body"))).unwrap();
    let want = fingerprint(&v);
    assert_eq!(want.len(), 2);
    let xp = dir.join("src.opx");
    v.export(&xp, &pw(EXPORT_PW), &key, P).unwrap();
    let ep = dir.join("empty.opv");
    Vault::create_with_key(&ep, &pw(VAULT_PW), P, &key).unwrap();
    Fixture {
        vault_bytes: std::fs::read(&vp).unwrap(),
        export_bytes: std::fs::read(&xp).unwrap(),
        empty_vault_bytes: std::fs::read(&ep).unwrap(),
        _dir: d,
        dir,
        key,
        want,
    }
}

impl Fixture {
    fn unlock(&self, bytes: &[u8]) -> Result<Vault, Error> {
        let p = self.dir.join("probe.opv");
        std::fs::write(&p, bytes).unwrap();
        let t = Instant::now();
        let r = Vault::unlock(&p, &pw(VAULT_PW), &self.key);
        assert!(t.elapsed() < LIMIT, "unlock took {:?}", t.elapsed());
        r
    }

    /// Unlock hostile bytes: Err, or the original plaintext and nothing else.
    fn check_unlock(&self, bytes: &[u8], what: &str) {
        if let Ok(v) = self.unlock(bytes) {
            assert_eq!(fingerprint(&v), self.want, "wrong plaintext after {what}");
        }
    }

    /// Import hostile bytes into a fresh empty vault: Err (vault unchanged) or exactly the
    /// original items.
    fn check_import(&self, bytes: &[u8], what: &str) {
        let target = self.dir.join("target.opv");
        std::fs::write(&target, &self.empty_vault_bytes).unwrap();
        let mut v = Vault::unlock(&target, &pw(VAULT_PW), &self.key).unwrap();
        let xp = self.dir.join("probe.opx");
        std::fs::write(&xp, bytes).unwrap();
        let t = Instant::now();
        let r = v.import(&xp, &pw(EXPORT_PW), &self.key);
        assert!(t.elapsed() < LIMIT, "import took {:?}", t.elapsed());
        match r {
            Ok(n) => {
                assert_eq!(n, self.want.len(), "{what}");
                let mut got = fingerprint(&v);
                let mut want = self.want.clone();
                got.sort();
                want.sort();
                assert_eq!(got, want, "wrong plaintext after {what}");
            }
            Err(_) => {
                assert_eq!(
                    std::fs::read(&target).unwrap(),
                    self.empty_vault_bytes,
                    "failed import changed the vault ({what})"
                );
                assert!(v.list().unwrap().is_empty(), "{what}");
            }
        }
    }
}

fn mutate(rng: &mut Rng, base: &[u8]) -> (Vec<u8>, &'static str) {
    let mut b = base.to_vec();
    let at = rng.below(b.len());
    match rng.below(6) {
        0 => {
            b[at] ^= 1 << rng.below(8);
            (b, "flip")
        }
        1 => {
            b.insert(at, rng.byte());
            (b, "insert")
        }
        2 => {
            b.remove(at);
            (b, "delete")
        }
        3 => {
            let n = (b.len() - at).min(4);
            for x in &mut b[at..at + n] {
                *x = 0;
            }
            (b, "u32 zero")
        }
        4 => {
            let n = (b.len() - at).min(4);
            for x in &mut b[at..at + n] {
                *x = 0xFF;
            }
            (b, "u32::MAX")
        }
        _ => {
            let n = (b.len() - at).min(8);
            for x in &mut b[at..at + n] {
                *x = 0xFF;
            }
            (b, "u64::MAX")
        }
    }
}

#[test]
fn control_fixtures_are_valid() {
    let f = fixture();
    assert_eq!(fingerprint(&f.unlock(&f.vault_bytes).unwrap()), f.want);
    f.check_import(&f.export_bytes, "control");
    let target = f.dir.join("t.opv");
    std::fs::write(&target, &f.empty_vault_bytes).unwrap();
    let mut v = Vault::unlock(&target, &pw(VAULT_PW), &f.key).unwrap();
    assert_eq!(
        v.import(&f.dir.join("src.opx"), &pw(EXPORT_PW), &f.key)
            .unwrap(),
        2
    );
}

#[test]
fn vault_every_truncation_is_rejected() {
    let f = fixture();
    for n in 0..f.vault_bytes.len() {
        assert!(f.unlock(&f.vault_bytes[..n]).is_err(), "truncated to {n}");
    }
}

#[test]
fn export_every_truncation_is_rejected() {
    let f = fixture();
    for n in 0..f.export_bytes.len() {
        f.check_import(&f.export_bytes[..n], &format!("truncation {n}"));
        let target = f.dir.join("t2.opv");
        std::fs::write(&target, &f.empty_vault_bytes).unwrap();
        let mut v = Vault::unlock(&target, &pw(VAULT_PW), &f.key).unwrap();
        let xp = f.dir.join("t2.opx");
        std::fs::write(&xp, &f.export_bytes[..n]).unwrap();
        assert!(v.import(&xp, &pw(EXPORT_PW), &f.key).is_err(), "{n}");
    }
}

#[test]
fn vault_every_single_byte_flip() {
    let f = fixture();
    for i in 0..f.vault_bytes.len() {
        for bit in [0u8, 7] {
            let mut b = f.vault_bytes.clone();
            b[i] ^= 1 << bit;
            f.check_unlock(&b, &format!("flip byte {i} bit {bit}"));
        }
    }
}

#[test]
fn export_every_single_byte_flip() {
    let f = fixture();
    for i in 0..f.export_bytes.len() {
        for bit in [0u8, 7] {
            let mut b = f.export_bytes.clone();
            b[i] ^= 1 << bit;
            f.check_import(&b, &format!("flip byte {i} bit {bit}"));
        }
    }
}

#[test]
fn vault_seeded_random_mutations() {
    let f = fixture();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for k in 0..2000 {
        let (b, what) = mutate(&mut rng, &f.vault_bytes);
        f.check_unlock(&b, &format!("{what} #{k}"));
    }
}

#[test]
fn export_seeded_random_mutations() {
    let f = fixture();
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for k in 0..2000 {
        let (b, what) = mutate(&mut rng, &f.export_bytes);
        f.check_import(&b, &format!("{what} #{k}"));
    }
}

#[test]
fn random_garbage_and_magic_prefixed_buffers() {
    let f = fixture();
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    let prefixes: [&[u8]; 4] = [
        VAULT_MAGIC,
        EXPORT_MAGIC,
        // Valid header prefix of each format, random tail.
        &f.vault_bytes[..30],
        &f.export_bytes[..30],
    ];
    for k in 0..2000 {
        let n = rng.below(4097);
        let b = rng.bytes(n);
        assert!(f.unlock(&b).is_err(), "garbage {k}");
        let xp = f.dir.join("g.opx");
        std::fs::write(&xp, &b).unwrap();
        let target = f.dir.join("g.opv");
        std::fs::write(&target, &f.empty_vault_bytes).unwrap();
        let mut v = Vault::unlock(&target, &pw(VAULT_PW), &f.key).unwrap();
        assert!(
            v.import(&xp, &pw(EXPORT_PW), &f.key).is_err(),
            "garbage {k}"
        );
    }
    for (pi, prefix) in prefixes.iter().enumerate() {
        for k in 0..100 {
            let mut b = prefix.to_vec();
            let n = rng.below(4097 - b.len());
            b.extend(rng.bytes(n));
            assert!(f.unlock(&b).is_err(), "prefix {pi} #{k}");
            f.check_import(&b, &format!("prefix {pi} #{k}"));
        }
    }
}

#[test]
fn huge_declared_lengths_are_rejected_on_tiny_input() {
    let f = fixture();
    // Empty vault: header (130) | record_count u32 | trailer (40).
    let e = &f.empty_vault_bytes;
    assert_eq!(e.len(), 130 + 4 + 40);
    for count in [1u32, 2, 100_000, 100_001, u32::MAX] {
        let mut b = e.clone();
        b[130..134].copy_from_slice(&count.to_be_bytes());
        assert!(b.len() < 1024);
        assert!(f.unlock(&b).is_err(), "record_count {count}");
    }
    // One small record: huge or zero record_len, huge count.
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("one.opv");
    let mut v = Vault::create_with_key(&p, &pw(VAULT_PW), P, &f.key).unwrap();
    v.add(&Item::new_note("n", pw("b"))).unwrap();
    let one = std::fs::read(&p).unwrap();
    assert!(one.len() < 1024, "{}", one.len());
    for len in [0u32, 1, 125, 141, 65_536, 1 << 30, u32::MAX] {
        let mut b = one.clone();
        b[134..138].copy_from_slice(&len.to_be_bytes());
        assert!(f.unlock(&b).is_err(), "record_len {len}");
    }
    for count in [0u32, 2, 100_000, u32::MAX] {
        let mut b = one.clone();
        b[130..134].copy_from_slice(&count.to_be_bytes());
        assert!(f.unlock(&b).is_err(), "count {count}");
    }
    // Export: ct_len (u64 at 66..74) and KDF memory (u32 at 12..16).
    let small = d.path().join("small.opx");
    v.export(&small, &pw(EXPORT_PW), &f.key, P).unwrap();
    let x = std::fs::read(&small).unwrap();
    assert!(x.len() < 1024, "{}", x.len());
    for ct in [0u64, 1, x.len() as u64, u64::MAX, 1 << 40, 1 << 31] {
        let mut b = x.clone();
        b[66..74].copy_from_slice(&ct.to_be_bytes());
        f.check_import_bytes_err(&b, &format!("ct_len {ct}"));
    }
    for m in [0u32, 1, u32::MAX, 1 << 30] {
        let mut b = x.clone();
        b[12..16].copy_from_slice(&m.to_be_bytes());
        f.check_import_bytes_err(&b, &format!("m_kib {m}"));
    }
    for t in [0u32, u32::MAX] {
        let mut b = x.clone();
        b[16..20].copy_from_slice(&t.to_be_bytes());
        f.check_import_bytes_err(&b, &format!("t {t}"));
        let mut b = x.clone();
        b[20..24].copy_from_slice(&t.to_be_bytes());
        f.check_import_bytes_err(&b, &format!("p {t}"));
    }
}

impl Fixture {
    fn check_import_bytes_err(&self, bytes: &[u8], what: &str) {
        let target = self.dir.join("big.opv");
        std::fs::write(&target, &self.empty_vault_bytes).unwrap();
        let mut v = Vault::unlock(&target, &pw(VAULT_PW), &self.key).unwrap();
        let xp = self.dir.join("big.opx");
        std::fs::write(&xp, bytes).unwrap();
        let t = Instant::now();
        let r = v.import(&xp, &pw(EXPORT_PW), &self.key);
        assert!(t.elapsed() < LIMIT, "{what}");
        assert!(r.is_err(), "{what}");
    }
}

fn random_string(rng: &mut Rng, max_chars: usize) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz234567-= 189\n";
    let n = rng.below(max_chars + 1);
    let mode = rng.below(4);
    (0..n)
        .map(|_| match mode {
            0 => ALPHA[rng.below(ALPHA.len())] as char,
            1 => char::from_u32(rng.next() as u32 % 0x11_0000).unwrap_or('\u{FFFD}'),
            2 => ['é', 'İ', 'ß', '\u{0}', '\u{FEFF}', '日', '😀', 'ﬃ'][rng.below(8)],
            _ => rng.byte() as char,
        })
        .collect()
}

#[test]
fn text_parsers_survive_random_strings() {
    let mut rng = Rng(0xA5A5_5A5A_DEAD_BEEF);
    let valid_key = SecretKey::generate().unwrap().to_text();
    for k in 0..5000 {
        let mut s = random_string(&mut rng, 80);
        match k % 5 {
            0 => s.insert_str(0, "OPSK1-"),
            1 => s.insert_str(0, "opsk1-"),
            2 => {
                // A valid key with one random character replaced by a (possibly multi-byte) one.
                let mut chars: Vec<char> = valid_key.expose().chars().collect();
                let at = rng.below(chars.len());
                chars[at] = ['é', 'İ', '日', '😀', '\0', 'A', '1'][rng.below(7)];
                s = chars.into_iter().collect();
            }
            _ => {}
        }
        let _ = SecretKey::from_text(&s);
        let _ = SecretKey::from_key_file_text(&s);
        let _ = parse_totp_secret(&s);
        let _ = s.parse::<ItemId>();
        // Cut on every char boundary of a short prefix of the valid key text.
    }
    for end in 0..=valid_key.expose().len() {
        if let Some(p) = valid_key.expose().get(..end) {
            let r = SecretKey::from_text(p);
            assert_eq!(r.is_ok(), end == valid_key.expose().len(), "{end}");
        }
    }
}

#[test]
fn text_parsers_survive_one_mebibyte_inputs() {
    let big = [
        "A".repeat(1 << 20),
        "日".repeat((1 << 20) / 3),
        "OPSK1-".to_string() + &"AAAA-".repeat(1 << 18),
        "😀".repeat((1 << 20) / 4),
        " ".repeat(1 << 20),
        "2".repeat(1 << 20),
    ];
    for s in &big {
        assert!(SecretKey::from_text(s).is_err());
        assert!(SecretKey::from_key_file_text(s).is_err());
        assert!(parse_totp_secret(s).is_err());
        assert!(s.parse::<ItemId>().is_err());
    }
}

#[test]
fn item_id_accepts_only_32_hex() {
    let id = ItemId([0xAB; 16]);
    assert_eq!(id.to_string().parse::<ItemId>().unwrap(), id);
    for bad in [
        "",
        "ab",
        &"g".repeat(32),
        &"a".repeat(31),
        &"a".repeat(33),
        &"é".repeat(16),
    ] {
        assert!(bad.parse::<ItemId>().is_err(), "{bad:?}");
    }
}

#[test]
fn hostile_generator_and_totp_options() {
    for length in [0usize, 1, 3, 1 << 20, usize::MAX / 2, usize::MAX] {
        let o = PasswordOptions {
            length,
            ..PasswordOptions::default()
        };
        if length > 4096 {
            assert!(generate_password(&o).is_err(), "length {length}");
        } else {
            let _ = generate_password(&o);
        }
    }
    let none = PasswordOptions {
        lower: false,
        upper: false,
        digits: false,
        symbols: false,
        ..PasswordOptions::default()
    };
    assert!(generate_password(&none).is_err());
    for words in [0usize, 1, 3, 25, 1 << 20, usize::MAX] {
        for sep in [
            "",
            "-",
            &"x".repeat(9),
            &"é".repeat(5),
            &"x".repeat(1 << 20),
        ] {
            let o = PassphraseOptions {
                words,
                separator: sep.to_string(),
                ..PassphraseOptions::default()
            };
            let r = generate_passphrase(&o);
            if !(4..=24).contains(&words) || sep.len() > 8 || !sep.is_ascii() {
                assert!(r.is_err(), "words {words} sep len {}", sep.len());
            }
        }
    }
    let secret = vec![7u8; 20];
    for digits in [0u8, 1, 5, 9, 255] {
        let r = hotp(&secret, u64::MAX, TotpAlgorithm::Sha1, digits);
        assert_eq!(r.is_ok(), (6..=8).contains(&digits), "digits {digits}");
    }
    assert!(hotp(&[], 0, TotpAlgorithm::Sha256, 6).is_err());
    assert!(hotp(&vec![1u8; 1 << 20], 0, TotpAlgorithm::Sha512, 6).is_err());
    for period in [0u32, 1, 301, u32::MAX] {
        let r = totp(&secret, u64::MAX, period, TotpAlgorithm::Sha512, 8);
        assert_eq!(r.is_ok(), (1..=300).contains(&period), "period {period}");
    }
    let mut rng = Rng(77);
    for _ in 0..500 {
        let cfg = TotpConfig {
            secret: SecretString::new(random_string(&mut rng, 40)),
            algorithm: TotpAlgorithm::Sha256,
            digits: rng.byte(),
            period: rng.next() as u32,
        };
        let _ = totp_for_item(&cfg, rng.next());
    }
}

#[test]
fn item_json_extremes_through_the_public_api() {
    // Hostile-but-structurally-valid items are rejected on add, never stored.
    let d = tempfile::tempdir().unwrap();
    let (mut v, _k) = Vault::create(&d.path().join("v.opv"), &pw(VAULT_PW), P).unwrap();
    let mut i = Item::new_login("x");
    i.title = "t".repeat(1 << 20);
    assert!(v.add(&i).is_err());
    let mut i = Item::new_login("x");
    i.totp = Some(TotpConfig {
        secret: pw("not base32 !!"),
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
    });
    assert!(v.add(&i).is_err());
    let mut i = Item::new_note("n", pw("b"));
    i.kind = ItemKind::Note;
    i.username = Some("nope".into());
    assert!(v.add(&i).is_err());
    assert!(v.list().unwrap().is_empty());
    assert!(matches!(v.get(&ItemId([1; 16])), Err(Error::NotFound)));
}
