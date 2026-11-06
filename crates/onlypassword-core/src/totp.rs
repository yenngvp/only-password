//! HOTP (RFC 4226) and TOTP (RFC 6238). The clock is never read here: the
//! caller passes the Unix time explicitly.

use crate::base32::parse_totp_secret;
use crate::error::{Error, Result};
use crate::item::{TotpAlgorithm, TotpConfig};
use hmac::{Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

const SECRET_MIN: usize = 10;
const SECRET_MAX: usize = 128;

fn bad() -> Error {
    Error::InvalidInput("invalid TOTP parameter")
}

/// HMAC of `msg` under `key`; the tag is wrapped so it is wiped on drop.
pub(crate) fn hmac(alg: TotpAlgorithm, key: &[u8], msg: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    fn run<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut m = <M as KeyInit>::new_from_slice(key).map_err(|_| bad())?;
        m.update(msg);
        Ok(Zeroizing::new(m.finalize().into_bytes().to_vec()))
    }
    match alg {
        TotpAlgorithm::Sha1 => run::<Hmac<sha1::Sha1>>(key, msg),
        TotpAlgorithm::Sha256 => run::<Hmac<sha2::Sha256>>(key, msg),
        TotpAlgorithm::Sha512 => run::<Hmac<sha2::Sha512>>(key, msg),
    }
}

/// HOTP value for `counter` with 6..=8 digits, zero padded on the left.
pub fn hotp(secret: &[u8], counter: u64, alg: TotpAlgorithm, digits: u8) -> Result<String> {
    if !(6..=8).contains(&digits) || !(SECRET_MIN..=SECRET_MAX).contains(&secret.len()) {
        return Err(bad());
    }
    let tag = hmac(alg, secret, &counter.to_be_bytes())?;
    let offset = usize::from(tag.last().copied().ok_or_else(bad)? & 0x0f);
    let chunk = tag.get(offset..offset + 4).ok_or_else(bad)?;
    let mut b = [0u8; 4];
    b.copy_from_slice(chunk);
    let bin = u32::from_be_bytes(b) & 0x7fff_ffff;
    let code = bin % 10u32.pow(u32::from(digits));
    Ok(format!("{code:0width$}", width = usize::from(digits)))
}

/// TOTP value at `unix_secs`: HOTP with `T = floor(unix_secs / period)`.
pub fn totp(
    secret: &[u8],
    unix_secs: u64,
    period: u32,
    alg: TotpAlgorithm,
    digits: u8,
) -> Result<String> {
    if !(1..=300).contains(&period) {
        return Err(bad());
    }
    hotp(secret, unix_secs / u64::from(period), alg, digits)
}

/// TOTP for a stored item configuration; the base32 secret must parse.
pub fn totp_for_item(cfg: &TotpConfig, unix_secs: u64) -> Result<String> {
    let secret = parse_totp_secret(cfg.secret.expose())?;
    totp(
        secret.expose(),
        unix_secs,
        cfg.period,
        cfg.algorithm,
        cfg.digits,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretString;
    use crate::testutil::{field, load_vectors};

    fn alg(name: &str) -> TotpAlgorithm {
        match name {
            "SHA1" => TotpAlgorithm::Sha1,
            "SHA256" => TotpAlgorithm::Sha256,
            "SHA512" => TotpAlgorithm::Sha512,
            _ => panic!("unknown mode"),
        }
    }

    #[test]
    fn totp_vectors() {
        let vs = load_vectors("totp.json");
        assert_eq!(vs.len(), 18);
        for v in &vs {
            let got = totp(
                &field(v, "secret_hex"),
                v["time"].as_u64().unwrap(),
                30,
                alg(v["mode"].as_str().unwrap()),
                8,
            )
            .unwrap();
            assert_eq!(got, v["totp"].as_str().unwrap());
        }
    }

    #[test]
    fn leading_zero_preserved() {
        let vs = load_vectors("totp.json");
        assert!(vs.iter().any(|v| v["totp"] == "07081804"));
    }

    #[test]
    fn hotp_vectors() {
        let doc = load_vectors("hotp.json");
        assert_eq!(doc.len(), 10);
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/vectors/hotp.json");
        let top: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let secret = crate::base32::hex_decode(top["secret_hex"].as_str().unwrap()).unwrap();
        for v in &doc {
            let got = hotp(
                &secret,
                v["counter"].as_u64().unwrap(),
                TotpAlgorithm::Sha1,
                6,
            )
            .unwrap();
            assert_eq!(got, v["hotp_6_digits"].as_str().unwrap());
        }
    }

    #[test]
    fn hmac_sha2_vectors() {
        for v in &load_vectors("hmac-sha2.json") {
            let (k, d) = (field(v, "key"), field(v, "data"));
            assert_eq!(
                *hmac(TotpAlgorithm::Sha256, &k, &d).unwrap(),
                field(v, "hmac_sha256")
            );
            assert_eq!(
                *hmac(TotpAlgorithm::Sha512, &k, &d).unwrap(),
                field(v, "hmac_sha512")
            );
        }
    }

    #[test]
    fn hmac_sha1_vectors() {
        let vs = load_vectors("hmac-sha1.json");
        assert_eq!(vs.len(), 4);
        for v in &vs {
            let got = hmac(TotpAlgorithm::Sha1, &field(v, "key"), &field(v, "data")).unwrap();
            assert_eq!(*got, field(v, "hmac_sha1"));
        }
    }

    #[test]
    fn invalid_parameters() {
        let s = [7u8; 20];
        let a = TotpAlgorithm::Sha1;
        for d in [5u8, 9, 0] {
            assert!(matches!(totp(&s, 0, 30, a, d), Err(Error::InvalidInput(_))));
            assert!(matches!(hotp(&s, 0, a, d), Err(Error::InvalidInput(_))));
        }
        for p in [0u32, 301] {
            assert!(matches!(totp(&s, 0, p, a, 6), Err(Error::InvalidInput(_))));
        }
        for n in [0usize, 9, 129] {
            let k = vec![1u8; n];
            assert!(matches!(totp(&k, 0, 30, a, 6), Err(Error::InvalidInput(_))));
            assert!(matches!(hotp(&k, 0, a, 6), Err(Error::InvalidInput(_))));
        }
        assert!(totp(&[1u8; 10], 0, 30, a, 6).is_ok());
        assert!(totp(&[1u8; 128], u64::MAX, 1, a, 8).is_ok());
    }

    fn cfg(secret: &str, period: u32, digits: u8) -> TotpConfig {
        TotpConfig {
            secret: SecretString::new(secret.into()),
            algorithm: TotpAlgorithm::Sha1,
            digits,
            period,
        }
    }

    #[test]
    fn item_matches_raw() {
        // base32 of "12345678901234567890"
        let c = cfg("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 30, 8);
        assert_eq!(totp_for_item(&c, 59).unwrap(), "94287082");
        // tolerant text form
        let c = cfg("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq==", 30, 8);
        assert_eq!(totp_for_item(&c, 59).unwrap(), "94287082");
    }

    #[test]
    fn item_rejects_bad_config() {
        assert!(totp_for_item(&cfg("GEZDGNBV1Y3TQOJQGEZD", 30, 6), 0).is_err());
        assert!(totp_for_item(&cfg("MFRGGZDF", 30, 6), 0).is_err()); // 5 bytes
        assert!(totp_for_item(&cfg("", 30, 6), 0).is_err());
        assert!(totp_for_item(&cfg("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 0, 6), 0).is_err());
        assert!(totp_for_item(&cfg("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 30, 9), 0).is_err());
    }

    #[test]
    fn secret_parsing() {
        let want = b"12345678901234567890".to_vec();
        for t in [
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
            "GEZD GNBV-GY3T QOJQ GEZD GNBV GY3T QOJQ====",
        ] {
            assert_eq!(parse_totp_secret(t).unwrap().expose(), &want[..]);
        }
        assert!(parse_totp_secret("GEZDGNBV0Y3TQOJQ").is_err());
        assert!(parse_totp_secret("GEZDGNBV!Y3TQOJQ").is_err());
    }
}
