//! XChaCha20-Poly1305 (CS §4). Every `seal` draws a fresh random 24-byte nonce; the
//! public API has no way to choose one.

use crate::rng::random_array;
use crate::secret::{SecretBytes, SecretVec};
use crate::{Error, Result};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

/// 32-byte AEAD key (zeroized on drop, redacted `Debug`).
#[derive(Debug)]
pub struct AeadKey(SecretBytes<KEY_LEN>);

impl AeadKey {
    pub fn new(bytes: [u8; KEY_LEN]) -> Self {
        AeadKey(SecretBytes::new(bytes))
    }
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        self.0.expose()
    }
}

/// Result of `seal`: the nonce and `ciphertext ‖ tag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext_and_tag: Vec<u8>,
}

fn cipher(key: &AeadKey) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| Error::InvalidInput("aead key"))
}

fn seal_with_nonce(
    key: &AeadKey,
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    cipher(key)?
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .map_err(|_| Error::InvalidInput("aead encrypt"))
}

/// Encrypt with a fresh random nonce.
pub fn seal(key: &AeadKey, ad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let nonce = random_array::<NONCE_LEN>()?;
    let ciphertext_and_tag = seal_with_nonce(key, &nonce, ad, plaintext)?;
    Ok(Sealed {
        nonce,
        ciphertext_and_tag,
    })
}

/// Test-only deterministic path (known-answer tests).
#[cfg(test)]
pub(crate) fn seal_with_nonce_for_tests(
    key: &AeadKey,
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    seal_with_nonce(key, nonce, ad, plaintext)
}

/// Decrypt `ciphertext ‖ tag`. Any failure yields `Error::Authentication` and no plaintext.
pub fn open(
    key: &AeadKey,
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<SecretVec> {
    cipher(key)
        .map_err(|_| Error::Authentication)?
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext_and_tag,
                aad: ad,
            },
        )
        .map(SecretVec::new)
        .map_err(|_| Error::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{field, hex_decode, load_vectors};
    use chacha20poly1305::ChaCha20Poly1305;

    fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
        v.try_into().unwrap()
    }

    #[test]
    fn xchacha_kat() {
        let vs = load_vectors("xchacha20poly1305.json");
        for v in &vs {
            let key = AeadKey::new(arr(&field(v, "key")));
            let nonce: [u8; 24] = arr(&field(v, "nonce"));
            let (aad, pt) = (field(v, "aad"), field(v, "plaintext"));
            let mut expect = field(v, "ciphertext");
            expect.extend(field(v, "tag"));
            assert_eq!(
                seal_with_nonce_for_tests(&key, &nonce, &aad, &pt).unwrap(),
                expect
            );
            let out = open(&key, &nonce, &aad, &expect).unwrap();
            assert_eq!(out.expose(), &pt[..]);
        }
    }

    #[test]
    fn chacha_rfc8439_kat() {
        for v in &load_vectors("chacha20poly1305.json") {
            let c = ChaCha20Poly1305::new_from_slice(&field(v, "key")).unwrap();
            let n: [u8; 12] = arr(&field(v, "nonce"));
            let mut expect = field(v, "ciphertext");
            expect.extend(field(v, "tag"));
            let got = c
                .encrypt(
                    &n.into(),
                    Payload {
                        msg: &field(v, "plaintext"),
                        aad: &field(v, "aad"),
                    },
                )
                .unwrap();
            assert_eq!(got, expect);
        }
    }

    fn sample() -> (AeadKey, Vec<u8>, Vec<u8>, Sealed) {
        let key = AeadKey::new([7u8; 32]);
        let ad = b"label|fixed".to_vec();
        let pt = b"attack at dawn, bring snacks".to_vec();
        let s = seal(&key, &ad, &pt).unwrap();
        (key, ad, pt, s)
    }

    #[test]
    fn roundtrip() {
        let (key, ad, pt, s) = sample();
        assert_eq!(s.ciphertext_and_tag.len(), pt.len() + TAG_LEN);
        assert_eq!(
            open(&key, &s.nonce, &ad, &s.ciphertext_and_tag)
                .unwrap()
                .expose(),
            &pt[..]
        );
        let e = seal(&key, b"", b"").unwrap();
        assert_eq!(e.ciphertext_and_tag.len(), TAG_LEN);
        assert!(open(&key, &e.nonce, b"", &e.ciphertext_and_tag)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn every_bit_flip_fails() {
        let (key, ad, _, s) = sample();
        for i in 0..s.ciphertext_and_tag.len() * 8 {
            let mut c = s.ciphertext_and_tag.clone();
            c[i / 8] ^= 1 << (i % 8);
            assert_eq!(
                open(&key, &s.nonce, &ad, &c).unwrap_err(),
                Error::Authentication
            );
        }
        for i in 0..24 * 8 {
            let mut n = s.nonce;
            n[i / 8] ^= 1 << (i % 8);
            assert_eq!(
                open(&key, &n, &ad, &s.ciphertext_and_tag).unwrap_err(),
                Error::Authentication
            );
        }
        for i in 0..ad.len() * 8 {
            let mut a = ad.clone();
            a[i / 8] ^= 1 << (i % 8);
            assert_eq!(
                open(&key, &s.nonce, &a, &s.ciphertext_and_tag).unwrap_err(),
                Error::Authentication
            );
        }
    }

    #[test]
    fn wrong_key_truncation_and_short_input_fail() {
        let (_, ad, _, s) = sample();
        let wrong = AeadKey::new([8u8; 32]);
        assert_eq!(
            open(&wrong, &s.nonce, &ad, &s.ciphertext_and_tag).unwrap_err(),
            Error::Authentication
        );
        let key = AeadKey::new([7u8; 32]);
        for len in 0..s.ciphertext_and_tag.len() {
            assert_eq!(
                open(&key, &s.nonce, &ad, &s.ciphertext_and_tag[..len]).unwrap_err(),
                Error::Authentication
            );
        }
        let mut longer = s.ciphertext_and_tag.clone();
        longer.push(0);
        assert_eq!(
            open(&key, &s.nonce, &ad, &longer).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn nonces_differ_between_calls() {
        let key = AeadKey::new([1u8; 32]);
        let a = seal(&key, b"ad", b"same").unwrap();
        let b = seal(&key, b"ad", b"same").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext_and_tag, b.ciphertext_and_tag);
    }

    #[test]
    fn key_debug_is_redacted() {
        let d = format!("{:?}", AeadKey::new([0x41; 32]));
        assert!(d.contains("redacted") && !d.contains("65") && !d.contains("41"));
        let _ = hex_decode("00");
    }
}
