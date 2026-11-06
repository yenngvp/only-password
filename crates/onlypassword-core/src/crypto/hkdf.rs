//! HKDF-SHA-256 (RFC 5869) with fixed 32-byte output (CS §3).

use crate::secret::SecretBytes;
use crate::{Error, Result};
use hkdf::Hkdf;
use sha2::Sha256;

pub const OUT_LEN: usize = 32;
pub const INFO_MK: &[u8] = b"onlypassword/v1/master-key";
pub const INFO_ITEMWRAP: &[u8] = b"onlypassword/v1/item-key-wrap";
pub const INFO_FILEAUTH: &[u8] = b"onlypassword/v1/file-auth";
pub const INFO_EXPORT: &[u8] = b"onlypassword/v1/export-key";

fn expand_into(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let h = Hkdf::<Sha256>::from_prk(prk).map_err(|_| Error::InvalidInput("hkdf prk"))?;
    h.expand(info, out)
        .map_err(|_| Error::InvalidInput("hkdf length"))
}

/// Extract then expand to 32 bytes.
pub fn extract_expand(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<SecretBytes<OUT_LEN>> {
    let (mut prk, h) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    zeroize::Zeroize::zeroize(&mut prk[..]);
    let mut out = [0u8; OUT_LEN];
    h.expand(info, &mut out)
        .map_err(|_| Error::InvalidInput("hkdf length"))?;
    let s = SecretBytes::new(out);
    zeroize::Zeroize::zeroize(&mut out);
    Ok(s)
}

/// Expand a 32-byte PRK to 32 bytes.
pub fn expand(prk: &SecretBytes<32>, info: &[u8]) -> Result<SecretBytes<OUT_LEN>> {
    let mut out = [0u8; OUT_LEN];
    expand_into(prk.expose(), info, &mut out)?;
    let s = SecretBytes::new(out);
    zeroize::Zeroize::zeroize(&mut out);
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{field, load_vectors};

    #[test]
    fn rfc5869_kat() {
        let vs = load_vectors("hkdf-sha256.json");
        let mut seen = 0;
        for v in &vs {
            let id = v["id"].as_str().unwrap();
            if !["A.1", "A.2", "A.3"].contains(&id) {
                continue;
            }
            seen += 1;
            let (ikm, salt, info) = (field(v, "ikm"), field(v, "salt"), field(v, "info"));
            let (prk, okm) = (field(v, "prk"), field(v, "okm"));
            let l = v["l"].as_u64().unwrap() as usize;
            assert_eq!(okm.len(), l);
            // full-length expand from the published PRK
            let mut out = vec![0u8; l];
            expand_into(&prk, &info, &mut out).unwrap();
            assert_eq!(out, okm);
            // public API: first 32 bytes of OKM (T(1))
            let p: [u8; 32] = prk.as_slice().try_into().unwrap();
            let got = expand(&SecretBytes::new(p), &info).unwrap();
            assert_eq!(&got.expose()[..], &okm[..32]);
            let got = extract_expand(&salt, &ikm, &info).unwrap();
            assert_eq!(&got.expose()[..], &okm[..32]);
        }
        assert_eq!(seen, 3);
    }

    #[test]
    fn labels_are_exact() {
        assert_eq!(INFO_MK, b"onlypassword/v1/master-key");
        assert_eq!(INFO_ITEMWRAP, b"onlypassword/v1/item-key-wrap");
        assert_eq!(INFO_FILEAUTH, b"onlypassword/v1/file-auth");
        assert_eq!(INFO_EXPORT, b"onlypassword/v1/export-key");
    }

    #[test]
    fn different_info_gives_different_keys() {
        let a = extract_expand(b"s", b"k", INFO_MK).unwrap();
        let b = extract_expand(b"s", b"k", INFO_EXPORT).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn bad_prk_length_is_error() {
        let mut out = [0u8; 32];
        assert!(expand_into(&[0u8; 5], b"", &mut out).is_err());
    }
}
