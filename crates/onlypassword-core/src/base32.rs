//! RFC 4648 base32 (section 6 alphabet) and a small lower-case hex codec.
//!
//! Encoding never pads. Decoding is tolerant about case, ASCII spaces, `-` and
//! a trailing run of `=`, and strict about everything else. No function here
//! panics on any input.

use crate::error::{Error, Result};

fn bad() -> Error {
    Error::InvalidInput("invalid base32 or hex text")
}
use crate::secret::{SecretString, SecretVec};
use zeroize::Zeroizing;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Smallest and largest decoded TOTP secret length in bytes.
const TOTP_MIN: usize = 10;
const TOTP_MAX: usize = 128;

/// Encode to upper-case base32 without padding.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            push_symbol(&mut out, (acc >> bits) & 31);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        push_symbol(&mut out, (acc << (5 - bits)) & 31);
    }
    out
}

fn push_symbol(out: &mut String, v: u32) {
    if let Some(&c) = ALPHABET.get(v as usize) {
        out.push(char::from(c));
    }
}

/// Tolerant decode: trailing bits are not checked.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if let Err(e) = decode_inner(text, false, &mut out) {
        zeroize::Zeroize::zeroize(&mut out);
        return Err(e);
    }
    Ok(out)
}

/// Like [`decode`] but rejects non-zero unused trailing bits (canonical form).
pub fn decode_strict(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if let Err(e) = decode_inner(text, true, &mut out) {
        zeroize::Zeroize::zeroize(&mut out);
        return Err(e);
    }
    Ok(out)
}

fn symbol_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a')),
        b'2'..=b'7' => Some(u32::from(c - b'2') + 26),
        _ => None,
    }
}

fn decode_inner(text: &str, strict: bool, out: &mut Vec<u8>) -> Result<()> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut symbols: usize = 0;
    let mut pad: usize = 0;
    for &c in text.as_bytes() {
        match c {
            b' ' | b'-' => {}
            b'=' => pad += 1,
            _ => {
                // Any symbol after '=' means '=' was not only trailing.
                if pad > 0 {
                    return Err(bad());
                }
                let v = symbol_value(c).ok_or(bad())?;
                acc = (acc << 5) | v;
                bits += 5;
                symbols += 1;
                if bits >= 8 {
                    bits -= 8;
                    out.push(((acc >> bits) & 0xff) as u8);
                    acc &= (1 << bits) - 1;
                }
            }
        }
    }
    // Symbol counts 1, 3 and 6 (mod 8) cannot come from whole bytes. The
    // number of trailing "=" is not checked (lenient for user input).
    if matches!(symbols % 8, 1 | 3 | 6) {
        return Err(bad());
    }
    if strict && acc != 0 {
        return Err(bad());
    }
    Ok(())
}

/// Parse user-entered TOTP secret text into its raw bytes (10..=128 bytes).
pub fn parse_totp_secret(text: &str) -> Result<SecretVec> {
    let mut out = Zeroizing::new(Vec::new());
    decode_inner(text, false, &mut out)?;
    if !(TOTP_MIN..=TOTP_MAX).contains(&out.len()) {
        return Err(bad());
    }
    Ok(SecretVec::new(std::mem::take(&mut *out)))
}

/// Canonical stored form of a TOTP secret: upper case, no padding or
/// separators, unused trailing bits zero.
pub fn normalize_totp_secret(text: &str) -> Result<SecretString> {
    let raw = parse_totp_secret(text)?;
    Ok(SecretString::new(encode(raw.expose())))
}

/// Lower-case hex encoding.
pub fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        for nib in [b >> 4, b & 15] {
            if let Some(&c) = HEX.get(usize::from(nib)) {
                out.push(char::from(c));
            }
        }
    }
    out
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Strict hex decoding: lower case only, even length.
pub fn hex_decode(text: &str) -> Result<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(bad());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut it = bytes.iter();
    while let (Some(&h), Some(&l)) = (it.next(), it.next()) {
        match (hex_val(h), hex_val(l)) {
            (Some(h), Some(l)) => out.push((h << 4) | l),
            _ => return Err(bad()),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Extract the string value following `"key":` occurrences, in order.
    fn json_strings(src: &str, key: &str) -> Vec<String> {
        let pat = format!("\"{key}\"");
        let mut res = Vec::new();
        let mut rest = src;
        while let Some(i) = rest.find(&pat) {
            rest = &rest[i + pat.len()..];
            let q1 = rest.find('"').unwrap();
            let after = &rest[q1 + 1..];
            let q2 = after.find('"').unwrap();
            res.push(after[..q2].to_string());
            rest = &after[q2 + 1..];
        }
        res
    }

    #[test]
    fn rfc_vectors() {
        let src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/base32.json"
        ))
        .unwrap();
        let inputs = json_strings(&src, "input_ascii");
        let encoded = json_strings(&src, "encoded");
        assert_eq!(inputs.len(), 7);
        assert_eq!(inputs.len(), encoded.len());
        for (i, e) in inputs.iter().zip(&encoded) {
            assert_eq!(encode(i.as_bytes()), e.trim_end_matches('='));
            assert_eq!(decode(e).unwrap(), i.as_bytes());
            assert_eq!(decode_strict(e).unwrap(), i.as_bytes());
        }
    }

    #[test]
    fn decode_tolerates_case_space_dash_padding() {
        assert_eq!(decode("mzxw 6ytb-oi").unwrap(), b"foobar");
        assert_eq!(decode("MZXW6YTBOI======").unwrap(), b"foobar");
        assert_eq!(decode("MZXW6YTBOI").unwrap(), b"foobar");
        assert_eq!(decode("=").unwrap(), b"");
    }

    #[test]
    fn decode_rejects_bad_input() {
        for bad in [
            "MZXW1YTB",      // '1' not in alphabet
            "MZXW0YTB",      // '0'
            "MZXW8YTB",      // '8'
            "MZ\u{e9}W6YTB", // non-ASCII
            "MZXW\tYTB",     // tab
            "MZ=XW6YTB",     // '=' in the middle
            "=MZXW6YTB",     // leading '='
            "MZXW6===x",     // data after '='
            "M",             // 1 symbol cannot occur
            "MZX",           // 3 symbols cannot occur
            "MZXW6Y",        // 6 symbols cannot occur
            "MZXW6YTBO",     // 9 -> 1 mod 8
        ] {
            assert!(decode(bad).is_err(), "{bad:?} must fail");
        }
    }

    #[test]
    fn strict_rejects_nonzero_trailing_bits() {
        // "MZ" = 'f' with 2 trailing zero bits; "MR" has non-zero trailing bits.
        assert!(decode_strict("MY").is_ok());
        assert!(decode_strict("MZ").is_err());
        assert_eq!(decode("MZ").unwrap(), b"f");
        assert!(decode_strict("MZXW6YTBOJ").is_err());
    }

    #[test]
    fn decode_never_panics_on_random_input() {
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..10_000 {
            let len = (next() % 64) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let text = String::from_utf8_lossy(&bytes).into_owned();
            let _ = decode(&text);
            let _ = decode_strict(&text);
            let _ = parse_totp_secret(&text);
            let _ = hex_decode(&text);
        }
    }

    #[test]
    fn roundtrip_all_lengths() {
        for n in 0..40u8 {
            let data: Vec<u8> = (0..n)
                .map(|i| i.wrapping_mul(37).wrapping_add(11))
                .collect();
            let e = encode(&data);
            assert!(!e.contains('='));
            assert_eq!(decode_strict(&e).unwrap(), data);
        }
    }

    fn secret_text(n: usize) -> String {
        encode(&vec![0x5a; n])
    }

    #[test]
    fn parse_totp_secret_rules() {
        let want = b"1234567890";
        for ok in [
            "GEZDGNBVGY3TQOJQ",
            "gezdgnbvgy3tqojq",
            "gezd gnbv-gy3t qojq",
            "gezdgnbvgy3tqojq=",
            "GEZD-GNBV-GY3T-QOJQ====",
        ] {
            assert_eq!(parse_totp_secret(ok).unwrap().expose(), want, "{ok}");
        }
        assert!(parse_totp_secret("GEZDGNBV1Y3TQOJQ").is_err());
        assert!(parse_totp_secret("").is_err());
        assert!(parse_totp_secret(" - = ").is_err());
        assert!(parse_totp_secret(&secret_text(9)).is_err());
        assert!(parse_totp_secret(&secret_text(10)).is_ok());
        assert!(parse_totp_secret(&secret_text(128)).is_ok());
        assert!(parse_totp_secret(&secret_text(129)).is_err());
    }

    #[test]
    fn normalize_totp_secret_canonical_and_idempotent() {
        let n = normalize_totp_secret("gezd gnbv-gy3t qojq==").unwrap();
        assert_eq!(n.expose(), "GEZDGNBVGY3TQOJQ");
        let again = normalize_totp_secret(n.expose()).unwrap();
        assert_eq!(again.expose(), n.expose());
        // Non-zero trailing bits are cleared in the canonical form.
        let canon = encode(&[0x5a; 11]);
        let mut dirty = canon.clone();
        dirty.pop();
        dirty.push('J');
        assert_ne!(dirty, canon);
        assert!(decode_strict(&dirty).is_err());
        let m = normalize_totp_secret(&dirty).unwrap();
        assert_eq!(m.expose(), canon);
        assert!(normalize_totp_secret("abc").is_err());
    }

    #[test]
    fn hex_codec() {
        assert_eq!(hex_encode(&[0x00, 0xab, 0xff, 0x10]), "00abff10");
        assert_eq!(
            hex_decode("00abff10").unwrap(),
            vec![0x00, 0xab, 0xff, 0x10]
        );
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(hex_decode(&hex_encode(&all)).unwrap(), all);
        for bad in ["AB", "aB", "abc", "a", "zz", "0x", "ab cd", "\u{e9}\u{e9}"] {
            assert!(hex_decode(bad).is_err(), "{bad:?}");
        }
    }
}
