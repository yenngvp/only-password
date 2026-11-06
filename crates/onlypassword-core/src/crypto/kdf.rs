//! Argon2id key derivation, KDF parameters and password normalization (CS §3.1, §3.3, §10).

use crate::secret::{SecretBytes, SecretVec};
use crate::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use unicode_normalization::UnicodeNormalization;

/// Minimum password length in Unicode scalar values, counted after NFKC (CS §3.1).
pub const MIN_PASSWORD_SCALARS: usize = 8;

const M_MAX: u32 = 262_144;
const T_MAX: u32 = 16;
const P_MAX: u32 = 16;

/// Argon2id cost parameters (CS §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 65_536,
        t: 3,
        p: 4,
    };
    /// The real floor.
    pub const MIN: KdfParams = KdfParams {
        m_kib: 19_456,
        t: 2,
        p: 1,
    };
    #[cfg(any(test, feature = "insecure-fast-kdf"))]
    pub const FAST_FOR_TESTS: KdfParams = KdfParams {
        m_kib: 8_192,
        t: 1,
        p: 1,
    };

    fn check(&self, floor: KdfParams) -> Result<()> {
        if self.m_kib < floor.m_kib
            || self.m_kib > M_MAX
            || self.t < floor.t
            || self.t > T_MAX
            || self.p < floor.p
            || self.p > P_MAX
        {
            return Err(Error::InvalidInput("kdf parameters out of range"));
        }
        Ok(())
    }

    /// Floor is lowered to `FAST_FOR_TESTS` only under `cfg(test)` / `insecure-fast-kdf`.
    pub fn validate(&self) -> Result<()> {
        #[cfg(any(test, feature = "insecure-fast-kdf"))]
        let floor = Self::FAST_FOR_TESTS;
        #[cfg(not(any(test, feature = "insecure-fast-kdf")))]
        let floor = Self::MIN;
        self.check(floor)
    }

    /// Always the real floor and ceiling.
    pub fn validate_strict(&self) -> Result<()> {
        self.check(Self::MIN)
    }
}

/// `UTF-8(NFKC(password))` (CS §3.1). No length check; used by unlock and import too.
pub fn normalize_password(password: &str) -> SecretVec {
    let s: String = password.nfkc().collect();
    SecretVec::new(s.into_bytes())
}

/// Creation-path check: at least 8 scalar values after NFKC (CS §3.1).
pub fn check_new_password(password: &str) -> Result<()> {
    if password.nfkc().take(MIN_PASSWORD_SCALARS).count() < MIN_PASSWORD_SCALARS {
        return Err(Error::InvalidInput("password too short"));
    }
    Ok(())
}

fn derive(
    password: &[u8],
    salt: &[u8; 16],
    params: &KdfParams,
    build: impl FnOnce(Params) -> Result<Argon2<'static>>,
) -> Result<SecretBytes<32>> {
    let p = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|_| Error::InvalidInput("kdf parameters out of range"))?;
    let ctx = build(p)?;
    let mut out = [0u8; 32];
    let r = ctx.hash_password_into(password, salt, &mut out);
    let s = SecretBytes::new(out);
    zeroize::Zeroize::zeroize(&mut out);
    r.map_err(|_| Error::InvalidInput("kdf failure"))?;
    Ok(s)
}

/// Argon2id v0x13, no secret, no associated data, 32-byte output (CS §3.3 step 1).
/// Parameters are validated before any memory is allocated.
pub fn argon2id(password: &[u8], salt: &[u8; 16], params: &KdfParams) -> Result<SecretBytes<32>> {
    params.validate()?;
    derive(password, salt, params, |p| {
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, p))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{field, load_vectors};
    use argon2::AssociatedData;

    #[test]
    fn rfc9106_kat() {
        for v in load_vectors("argon2id.json") {
            let secret = field(&v, "secret");
            let ad = field(&v, "associated_data");
            let num = |k: &str| v[k].as_u64().unwrap() as u32;
            assert_eq!(num("version"), 19);
            let params = argon2::ParamsBuilder::new()
                .m_cost(num("memory_kib"))
                .t_cost(num("iterations"))
                .p_cost(num("parallelism"))
                .data(AssociatedData::new(&ad).unwrap())
                .output_len(num("tag_length") as usize)
                .build()
                .unwrap();
            let ctx = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params)
                .unwrap();
            let mut out = vec![0u8; num("tag_length") as usize];
            ctx.hash_password_into(&field(&v, "password"), &field(&v, "salt"), &mut out)
                .unwrap();
            assert_eq!(out, field(&v, "tag"));
        }
    }

    #[test]
    fn constants() {
        assert_eq!(
            KdfParams::DEFAULT,
            KdfParams {
                m_kib: 65_536,
                t: 3,
                p: 4
            }
        );
        assert_eq!(
            KdfParams::MIN,
            KdfParams {
                m_kib: 19_456,
                t: 2,
                p: 1
            }
        );
        assert_eq!(
            KdfParams::FAST_FOR_TESTS,
            KdfParams {
                m_kib: 8_192,
                t: 1,
                p: 1
            }
        );
    }

    fn k(m_kib: u32, t: u32, p: u32) -> KdfParams {
        KdfParams { m_kib, t, p }
    }

    #[test]
    fn strict_bounds() {
        for ok in [k(19_456, 2, 1), k(262_144, 16, 16), k(65_536, 3, 4)] {
            assert!(ok.validate_strict().is_ok());
            assert!(ok.validate().is_ok());
        }
        for bad in [
            k(19_455, 2, 1),
            k(262_145, 2, 1),
            k(19_456, 1, 1),
            k(19_456, 17, 1),
            k(19_456, 2, 0),
            k(19_456, 2, 17),
            k(u32::MAX, 3, 4),
        ] {
            assert!(bad.validate_strict().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn validate_rejects_above_ceiling_and_zero() {
        for bad in [
            k(262_145, 2, 1),
            k(19_456, 17, 1),
            k(19_456, 2, 0),
            k(u32::MAX, 3, 4),
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn fast_floor_under_cfg() {
        assert!(KdfParams::FAST_FOR_TESTS.validate().is_ok());
        assert!(KdfParams::FAST_FOR_TESTS.validate_strict().is_err());
        assert!(k(8_191, 1, 1).validate().is_err());
        assert!(k(8_192, 0, 1).validate().is_err());
    }

    #[test]
    fn huge_memory_rejected_before_running() {
        let start = std::time::Instant::now();
        let r = argon2id(b"password", &[0; 16], &k(u32::MAX, 3, 4));
        assert!(r.is_err());
        assert!(start.elapsed().as_secs() < 2);
    }

    #[test]
    fn normalization_fixed_results() {
        let n = |s: &str| normalize_password(s).expose().to_vec();
        assert_eq!(n("e\u{301}"), [0xC3, 0xA9]);
        assert_eq!(n("\u{FB01}"), [0x66, 0x69]);
        assert_eq!(n("\u{B5}"), [0xCE, 0xBC]);
        assert_eq!(n("\u{FF11}"), [0x31]);
    }

    #[test]
    fn password_minimum_after_normalization() {
        assert!(check_new_password("").is_err());
        assert!(check_new_password("1234567").is_err());
        assert!(check_new_password("12345678").is_ok());
        // 7 chars that expand to 8 after NFKC (U+FB01 -> "fi")
        assert!(check_new_password("\u{FB01}12345 ").is_ok());
        // 8 scalars that compose to 7 (e + U+0301 -> é)
        assert!(check_new_password("e\u{301}123456").is_err());
        assert!(check_new_password("e\u{301}1234567").is_ok());
    }

    #[test]
    fn default_params_smoke_and_determinism() {
        let a = argon2id(b"correct horse", &[7; 16], &KdfParams::DEFAULT).unwrap();
        let b = argon2id(b"correct horse", &[7; 16], &KdfParams::DEFAULT).unwrap();
        let c = argon2id(b"correct horsf", &[7; 16], &KdfParams::DEFAULT).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
    }
}
