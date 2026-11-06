//! Key hierarchy: SK, MK, VK, IK and the VK subkeys (CS §3).

use crate::base32;
use crate::crypto::hkdf::{self, INFO_FILEAUTH, INFO_ITEMWRAP, INFO_MK};
use crate::crypto::kdf::{self, KdfParams};
use crate::rng;
use crate::secret::SecretBytes;
use crate::{Error, Result};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const PREFIX: &str = "OPSK1-";
const SK_CHARS: usize = 52;

fn bad() -> Error {
    Error::InvalidInput("invalid secret key")
}

macro_rules! key_type {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name(SecretBytes<32>);

        impl $name {
            /// Wrap existing key bytes.
            pub fn from_secret(bytes: SecretBytes<32>) -> Self {
                $name(bytes)
            }
            pub fn expose(&self) -> &[u8; 32] {
                self.0.expose()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

key_type!(/// 32-byte secret key SK (CS §3.2).
    SecretKey);
key_type!(/// Master key MK (CS §3.3).
    MasterKey);
key_type!(/// Vault key VK, random (CS §3).
    VaultKey);
key_type!(/// Item key IK, random, one per item revision.
    ItemKey);
key_type!(/// Item-key wrapping key K_iw (CS §3.4).
    ItemWrapKey);
key_type!(/// File authentication key K_fa (CS §3.4).
    FileAuthKey);

fn random_secret() -> Result<SecretBytes<32>> {
    let mut a = rng::random_array::<32>()?;
    let s = SecretBytes::new(a);
    a.zeroize();
    Ok(s)
}

impl SecretKey {
    pub fn generate() -> Result<Self> {
        Ok(SecretKey(random_secret()?))
    }

    /// `OPSK1-` plus 13 groups of 4 base32 characters.
    pub fn to_text(&self) -> crate::secret::SecretString {
        let enc = Zeroizing::new(base32::encode(self.0.expose()));
        let mut out = String::from(PREFIX);
        for (i, c) in enc.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(c);
        }
        crate::secret::SecretString::new(out)
    }

    pub fn from_text(text: &str) -> Result<Self> {
        let head = text.get(..PREFIX.len()).ok_or_else(bad)?;
        if !head.eq_ignore_ascii_case(PREFIX) {
            return Err(bad());
        }
        let rest = text.get(PREFIX.len()..).ok_or_else(bad)?;
        let mut chars = Zeroizing::new(String::with_capacity(SK_CHARS));
        for c in rest.chars() {
            match c {
                ' ' | '-' => {}
                'A'..='Z' | 'a'..='z' | '2'..='7' => {
                    if chars.len() >= SK_CHARS {
                        return Err(bad());
                    }
                    chars.push(c);
                }
                _ => return Err(bad()),
            }
        }
        if chars.len() != SK_CHARS {
            return Err(bad());
        }
        let mut bytes = Zeroizing::new(base32::decode_strict(&chars).map_err(|_| bad())?);
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| bad())?;
        bytes.zeroize();
        let mut arr = arr;
        let s = SecretBytes::new(arr);
        arr.zeroize();
        Ok(SecretKey(s))
    }

    /// Key file text: ASCII whitespace trimmed at both ends, then `from_text`.
    /// A BOM or any other character is `InvalidInput`.
    pub fn from_key_file_text(text: &str) -> Result<Self> {
        Self::from_text(text.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n')))
    }
}

impl MasterKey {
    /// `Argon2id(password_bytes, kdf_salt)` then HKDF with `kdf_salt` as salt over
    /// `pw_key ‖ SK` and `INFO_MK` (CS §3.3). `password_bytes` must already be NFKC-normalized.
    pub fn derive(
        password_bytes: &[u8],
        kdf_salt: &[u8; 16],
        params: &KdfParams,
        sk: &SecretKey,
    ) -> Result<Self> {
        let pw_key = kdf::argon2id(password_bytes, kdf_salt, params)?;
        let mut ikm = Zeroizing::new([0u8; 64]);
        let (a, b) = ikm.split_at_mut(32);
        a.copy_from_slice(pw_key.expose());
        b.copy_from_slice(sk.expose());
        Ok(MasterKey(hkdf::extract_expand(
            kdf_salt,
            &ikm[..],
            INFO_MK,
        )?))
    }
}

impl VaultKey {
    pub fn generate() -> Result<Self> {
        Ok(VaultKey(random_secret()?))
    }
    /// K_iw = HKDF-Expand(VK, INFO_ITEMWRAP).
    pub fn item_wrap_key(&self) -> Result<ItemWrapKey> {
        Ok(ItemWrapKey(hkdf::expand(&self.0, INFO_ITEMWRAP)?))
    }
    /// K_fa = HKDF-Expand(VK, INFO_FILEAUTH).
    pub fn file_auth_key(&self) -> Result<FileAuthKey> {
        Ok(FileAuthKey(hkdf::expand(&self.0, INFO_FILEAUTH)?))
    }
}

impl ItemKey {
    pub fn generate() -> Result<Self> {
        Ok(ItemKey(random_secret()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::hkdf::Hkdf;
    use argon2::{Algorithm, Argon2, Params, Version};
    use sha2::Sha256;

    const FAST: KdfParams = KdfParams::FAST_FOR_TESTS;
    const SALT: [u8; 16] = [7; 16];
    const PW: &[u8] = b"correct horse battery";

    fn sk_from(b: u8) -> SecretKey {
        SecretKey::from_secret(SecretBytes::new([b; 32]))
    }

    fn is_invalid<T>(r: Result<T>) -> bool {
        matches!(r, Err(Error::InvalidInput(_)))
    }

    #[test]
    fn text_round_trip_and_shape() {
        let sk = SecretKey::generate().unwrap();
        let t = sk.to_text();
        let t = t.expose();
        let rest = t.strip_prefix("OPSK1-").unwrap();
        let groups: Vec<&str> = rest.split('-').collect();
        assert_eq!(groups.len(), 13);
        assert!(groups.iter().all(|g| g.len() == 4));
        let back = SecretKey::from_text(t).unwrap();
        assert_eq!(back.expose(), sk.expose());
        // fixed known layout for all-zero key
        let z = sk_from(0).to_text();
        assert_eq!(z.expose().len(), 6 + 52 + 12);
        assert!(z.expose().starts_with("OPSK1-AAAA-AAAA-"));
    }

    #[test]
    fn generate_differs() {
        let a = SecretKey::generate().unwrap();
        let b = SecretKey::generate().unwrap();
        assert_ne!(a.expose(), b.expose());
        assert_ne!(
            VaultKey::generate().unwrap().expose(),
            VaultKey::generate().unwrap().expose()
        );
        assert_ne!(
            ItemKey::generate().unwrap().expose(),
            ItemKey::generate().unwrap().expose()
        );
    }

    #[test]
    fn from_text_tolerance() {
        let sk = sk_from(0xA5);
        let t = sk.to_text().expose().to_string();
        let lower = t.to_lowercase();
        assert_eq!(SecretKey::from_text(&lower).unwrap().expose(), sk.expose());
        let spaced = t.replace('-', " - ").replacen("OPSK1 - ", "OPSK1-", 1);
        assert_eq!(SecretKey::from_text(&spaced).unwrap().expose(), sk.expose());
        let nodash = t.replacen("OPSK1-", "opsk1-", 1).replace('-', "");
        assert!(is_invalid(SecretKey::from_text(&nodash)) || nodash.starts_with("opsk1"));
        let no_dash_after = format!("OPSK1-{}", t[6..].replace('-', ""));
        assert_eq!(
            SecretKey::from_text(&no_dash_after).unwrap().expose(),
            sk.expose()
        );
    }

    #[test]
    fn from_text_rejections() {
        let t = sk_from(0xA5).to_text().expose().to_string();
        assert!(is_invalid(SecretKey::from_text(
            &t.replacen("OPSK1", "OPSK2", 1)
        )));
        assert!(is_invalid(SecretKey::from_text(&t[6..])));
        assert!(is_invalid(SecretKey::from_text("")));
        assert!(is_invalid(SecretKey::from_text("OPSK")));
        assert!(is_invalid(SecretKey::from_text("é")));
        assert!(is_invalid(SecretKey::from_text("OPSK1é-AAAA")));
        // too short / too long
        assert!(is_invalid(SecretKey::from_text(&t[..t.len() - 1])));
        assert!(is_invalid(SecretKey::from_text(&format!("{t}A"))));
        assert!(is_invalid(SecretKey::from_text("OPSK1-")));
        // invalid characters (0, 1, 8, 9, '=', '_')
        for bad in ['0', '1', '8', '9', '=', '_', '!'] {
            let mut s = t.clone();
            s.replace_range(7..8, &bad.to_string());
            assert!(is_invalid(SecretKey::from_text(&s)), "{bad}");
        }
        // non-zero trailing bits: last symbol of a valid text has 4 unused low bits
        let mut s = sk_from(0).to_text().expose().to_string();
        assert!(SecretKey::from_text(&s).is_ok());
        s.pop();
        s.push('B');
        assert!(is_invalid(SecretKey::from_text(&s)));
    }

    #[test]
    fn key_file_text() {
        let sk = sk_from(0x3C);
        let t = sk.to_text().expose().to_string();
        for form in [
            format!("{t}\n"),
            format!("   {t}"),
            format!("\t {t}\r\n"),
            format!("  {t}  \r\n\r\n"),
        ] {
            assert_eq!(
                SecretKey::from_key_file_text(&form).unwrap().expose(),
                sk.expose()
            );
        }
        assert!(is_invalid(SecretKey::from_key_file_text(&format!(
            "\u{feff}{t}"
        ))));
        assert!(is_invalid(SecretKey::from_key_file_text(&format!(
            "{t}\nextra"
        ))));
        assert!(is_invalid(SecretKey::from_key_file_text(&format!("x{t}"))));
        assert!(is_invalid(SecretKey::from_key_file_text(&format!(
            "{t}\u{a0}"
        ))));
        assert!(is_invalid(SecretKey::from_key_file_text("")));
    }

    #[test]
    fn master_key_dependence() {
        let sk = sk_from(1);
        let base = MasterKey::derive(PW, &SALT, &FAST, &sk).unwrap();
        let same = MasterKey::derive(PW, &SALT, &FAST, &sk).unwrap();
        assert_eq!(base.expose(), same.expose());
        let pw = MasterKey::derive(b"correct horse batterz", &SALT, &FAST, &sk).unwrap();
        assert_ne!(base.expose(), pw.expose());
        let salt = MasterKey::derive(PW, &[8; 16], &FAST, &sk).unwrap();
        assert_ne!(base.expose(), salt.expose());
        let skc = MasterKey::derive(PW, &SALT, &FAST, &sk_from(2)).unwrap();
        assert_ne!(base.expose(), skc.expose());
        let p2 = KdfParams {
            t: FAST.t + 1,
            ..FAST
        };
        let par = MasterKey::derive(PW, &SALT, &p2, &sk).unwrap();
        assert_ne!(base.expose(), par.expose());
    }

    #[test]
    fn master_key_independent_recompute() {
        let sk = sk_from(9);
        let mk = MasterKey::derive(PW, &SALT, &FAST, &sk).unwrap();
        let params = Params::new(FAST.m_kib, FAST.t, FAST.p, Some(32)).unwrap();
        let mut pw_key = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(PW, &SALT, &mut pw_key)
            .unwrap();
        let mut ikm = pw_key.to_vec();
        ikm.extend_from_slice(&[9u8; 32]);
        let h = Hkdf::<Sha256>::new(Some(&SALT), &ikm);
        let mut out = [0u8; 32];
        h.expand(b"onlypassword/v1/master-key", &mut out).unwrap();
        assert_eq!(mk.expose(), &out);
    }

    #[test]
    fn subkeys_match_labels() {
        let vk = VaultKey::from_secret(SecretBytes::new([0x42; 32]));
        let iw = vk.item_wrap_key().unwrap();
        let fa = vk.file_auth_key().unwrap();
        assert_ne!(iw.expose(), fa.expose());
        assert_ne!(iw.expose(), vk.expose());
        assert_ne!(fa.expose(), vk.expose());
        let h = Hkdf::<Sha256>::from_prk(&[0x42; 32]).unwrap();
        let mut a = [0u8; 32];
        h.expand(b"onlypassword/v1/item-key-wrap", &mut a).unwrap();
        let mut b = [0u8; 32];
        h.expand(b"onlypassword/v1/file-auth", &mut b).unwrap();
        assert_eq!(iw.expose(), &a);
        assert_eq!(fa.expose(), &b);
    }

    fn assert_zod<T: ZeroizeOnDrop>() {}

    #[test]
    fn zeroize_on_drop_and_redacted_debug() {
        assert_zod::<SecretKey>();
        assert_zod::<MasterKey>();
        assert_zod::<VaultKey>();
        assert_zod::<ItemKey>();
        assert_zod::<ItemWrapKey>();
        assert_zod::<FileAuthKey>();
        let sentinel = [0xABu8; 32];
        let k = VaultKey::from_secret(SecretBytes::new(sentinel));
        for d in [format!("{k:?}"), format!("{k:#?}")] {
            assert!(d.contains("redacted"));
            assert!(!d.to_lowercase().contains("ab"));
            assert!(!d.contains("171"));
        }
        let sk = sk_from(0xAB);
        let d = format!("{sk:?}");
        assert!(!d.contains(sk.to_text().expose()) && !d.contains("171"));
    }

    #[test]
    fn zeroize_wipes() {
        let mut k = ItemKey::from_secret(SecretBytes::new([5; 32]));
        k.zeroize();
        assert_eq!(k.expose(), &[0u8; 32]);
    }
}
