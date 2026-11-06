//! Random password generator (architecture.md, "Password generator definitions").

use crate::error::{Error, Result};
use crate::rng::{uniform_with, RandomSource};
use crate::secret::SecretString;
use zeroize::Zeroizing;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/";
const AMBIGUOUS: &[u8] = b"0Oo1lI";

/// Options for [`generate_password`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordOptions {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
    pub require_each: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        PasswordOptions {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
            require_each: true,
        }
    }
}

/// Generate a random password using the operating-system random source.
pub fn generate_password(o: &PasswordOptions) -> Result<SecretString> {
    generate_password_with(&mut crate::rng::os_source(), o)
}

pub(crate) fn generate_password_with(
    r: &mut dyn RandomSource,
    o: &PasswordOptions,
) -> Result<SecretString> {
    if !(4..=256).contains(&o.length) {
        return Err(Error::InvalidInput("password length out of range"));
    }
    let mut classes: Vec<Vec<u8>> = Vec::with_capacity(4);
    for (on, set) in [
        (o.lower, LOWER),
        (o.upper, UPPER),
        (o.digits, DIGITS),
        (o.symbols, SYMBOLS),
    ] {
        if on {
            let c: Vec<u8> = set
                .iter()
                .copied()
                .filter(|b| !(o.exclude_ambiguous && AMBIGUOUS.contains(b)))
                .collect();
            if c.is_empty() {
                return Err(Error::InvalidInput("character class is empty"));
            }
            classes.push(c);
        }
    }
    if classes.is_empty() {
        return Err(Error::InvalidInput("no character class enabled"));
    }
    if o.require_each && o.length < classes.len() {
        return Err(Error::InvalidInput("length below number of classes"));
    }
    let union: Vec<u8> = classes.iter().flatten().copied().collect();

    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(o.length));
    if o.require_each {
        for c in &classes {
            out.push(pick(r, c)?);
        }
    }
    while out.len() < o.length {
        out.push(pick(r, &union)?);
    }
    // Fisher–Yates shuffle.
    for i in (1..out.len()).rev() {
        let j = uniform_with(r, i as u64 + 1)? as usize;
        out.swap(i, j);
    }
    let mut s = String::with_capacity(o.length);
    s.extend(out.iter().map(|&b| b as char));
    Ok(SecretString::new(s))
}

fn pick(r: &mut dyn RandomSource, set: &[u8]) -> Result<u8> {
    let i = uniform_with(r, set.len() as u64)? as usize;
    set.get(i)
        .copied()
        .ok_or(Error::InvalidInput("index out of range"))
}

/// Options for [`generate_passphrase`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_digit: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        PassphraseOptions {
            words: 7,
            separator: "-".to_string(),
            capitalize: false,
            include_digit: false,
        }
    }
}

/// Generate a word-based passphrase using the operating-system random source.
pub fn generate_passphrase(o: &PassphraseOptions) -> Result<SecretString> {
    generate_passphrase_with(&mut crate::rng::os_source(), o)
}

pub(crate) fn generate_passphrase_with(
    r: &mut dyn RandomSource,
    o: &PassphraseOptions,
) -> Result<SecretString> {
    if !(4..=24).contains(&o.words) {
        return Err(Error::InvalidInput("word count out of range"));
    }
    if o.separator.len() > 8 || !o.separator.is_ascii() {
        return Err(Error::InvalidInput("invalid separator"));
    }
    let list = bip39::Language::English.word_list();
    let mut words: Vec<Zeroizing<String>> = Vec::with_capacity(o.words);
    for _ in 0..o.words {
        let i = uniform_with(r, list.len() as u64)? as usize;
        let w = list
            .get(i)
            .ok_or(Error::InvalidInput("index out of range"))?;
        let mut w = Zeroizing::new((*w).to_string());
        if o.capitalize {
            if let Some(first) = w.get_mut(..1) {
                first.make_ascii_uppercase();
            }
        }
        words.push(w);
    }
    if o.include_digit {
        let wi = uniform_with(r, o.words as u64)? as usize;
        let d = uniform_with(r, 10)? as u8;
        let w = words
            .get_mut(wi)
            .ok_or(Error::InvalidInput("index out of range"))?;
        w.push((b'0' + d) as char);
    }
    let mut out = Zeroizing::new(String::new());
    for (i, w) in words.iter().enumerate() {
        if i > 0 {
            out.push_str(&o.separator);
        }
        out.push_str(w);
    }
    Ok(SecretString::new(out.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Deterministic splitmix64 stream.
    struct Stub(u64);
    impl RandomSource for Stub {
        fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
            for chunk in buf.chunks_mut(8) {
                self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^= z >> 31;
                let b = z.to_be_bytes();
                let l = chunk.len();
                chunk.copy_from_slice(b.get(..l).ok_or(Error::Rng)?);
            }
            Ok(())
        }
    }
    struct Failing;
    impl RandomSource for Failing {
        fn fill(&mut self, _: &mut [u8]) -> Result<()> {
            Err(Error::Rng)
        }
    }

    fn gen(seed: u64, o: &PasswordOptions) -> String {
        generate_password_with(&mut Stub(seed), o)
            .unwrap()
            .expose()
            .to_string()
    }

    #[test]
    fn default_options_values() {
        let o = PasswordOptions::default();
        assert_eq!(o.length, 20);
        assert!(o.lower && o.upper && o.digits && o.symbols && o.require_each);
        assert!(!o.exclude_ambiguous);
    }

    #[test]
    fn default_has_20_chars_with_each_class() {
        for seed in 0..500 {
            let p = gen(seed, &PasswordOptions::default());
            assert_eq!(p.len(), 20);
            assert!(p.bytes().any(|b| LOWER.contains(&b)));
            assert!(p.bytes().any(|b| UPPER.contains(&b)));
            assert!(p.bytes().any(|b| DIGITS.contains(&b)));
            assert!(p.bytes().any(|b| SYMBOLS.contains(&b)));
        }
    }

    #[test]
    fn symbol_set_has_24_distinct() {
        let mut s = SYMBOLS.to_vec();
        s.sort();
        s.dedup();
        assert_eq!(s.len(), 24);
    }

    #[test]
    fn length_bounds() {
        for len in [4, 5, 20, 255, 256] {
            let o = PasswordOptions {
                length: len,
                ..Default::default()
            };
            assert_eq!(gen(1, &o).len(), len);
        }
        for len in [0, 3, 257, 1000] {
            let o = PasswordOptions {
                length: len,
                ..Default::default()
            };
            assert!(matches!(
                generate_password_with(&mut Stub(1), &o),
                Err(Error::InvalidInput(_))
            ));
        }
    }

    #[test]
    fn all_option_combinations() {
        for mask in 0u8..16 {
            for amb in [false, true] {
                for req in [false, true] {
                    for len in [4usize, 7, 64, 256] {
                        let o = PasswordOptions {
                            length: len,
                            lower: mask & 1 != 0,
                            upper: mask & 2 != 0,
                            digits: mask & 4 != 0,
                            symbols: mask & 8 != 0,
                            exclude_ambiguous: amb,
                            require_each: req,
                        };
                        let res = generate_password_with(&mut Stub(mask as u64), &o);
                        if mask == 0 {
                            assert!(matches!(res, Err(Error::InvalidInput(_))));
                            continue;
                        }
                        let p = res.unwrap();
                        let p = p.expose();
                        assert_eq!(p.len(), len);
                        let sets = [
                            (o.lower, LOWER),
                            (o.upper, UPPER),
                            (o.digits, DIGITS),
                            (o.symbols, SYMBOLS),
                        ];
                        for b in p.bytes() {
                            assert!(sets.iter().any(|(on, s)| *on && s.contains(&b)));
                            assert!(!(amb && AMBIGUOUS.contains(&b)));
                        }
                        if req {
                            for (on, s) in sets {
                                if on {
                                    assert!(p.bytes().any(
                                        |b| s.contains(&b) && !(amb && AMBIGUOUS.contains(&b))
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn length_below_required_classes_is_invalid() {
        // Lengths are >= 4 and classes <= 4, so this can only trip via the length check
        // first; the class-count check is exercised with the minimum length and all classes.
        let o = PasswordOptions {
            length: 4,
            ..Default::default()
        };
        assert_eq!(gen(3, &o).len(), 4);
        let o = PasswordOptions {
            length: 3,
            ..Default::default()
        };
        assert!(generate_password_with(&mut Stub(3), &o).is_err());
    }

    #[test]
    fn length_4_with_require_each_has_one_of_each() {
        for seed in 0..200 {
            let p = gen(
                seed,
                &PasswordOptions {
                    length: 4,
                    ..Default::default()
                },
            );
            for s in [LOWER, UPPER, DIGITS, SYMBOLS] {
                assert_eq!(p.bytes().filter(|b| s.contains(b)).count(), 1);
            }
        }
    }

    #[test]
    fn exclude_ambiguous_never_emits_them() {
        let o = PasswordOptions {
            exclude_ambiguous: true,
            ..Default::default()
        };
        for seed in 0..1000 {
            let p = gen(seed, &o);
            assert!(!p.chars().any(|c| "0Oo1lI".contains(c)));
        }
    }

    #[test]
    fn deterministic_for_same_stream() {
        let o = PasswordOptions::default();
        assert_eq!(gen(42, &o), gen(42, &o));
        assert_ne!(gen(42, &o), gen(43, &o));
    }

    #[test]
    fn frequencies_are_equal_across_union() {
        // Without require_each every character is one draw from the 86-char union,
        // then the shuffle only permutes. Deterministic stream => deterministic test.
        let o = PasswordOptions {
            length: 256,
            require_each: false,
            ..Default::default()
        };
        let mut counts: HashMap<char, u32> = HashMap::new();
        let mut rng = Stub(7);
        let runs = 2000;
        for _ in 0..runs {
            let p = generate_password_with(&mut rng, &o).unwrap();
            for c in p.expose().chars() {
                *counts.entry(c).or_default() += 1;
            }
        }
        assert_eq!(counts.len(), 86);
        let expected = (runs * 256) as f64 / 86.0; // ~5953, sd ~77
        for (c, n) in counts {
            assert!(
                (n as f64 - expected).abs() < expected * 0.06,
                "char {c:?} count {n} vs {expected}"
            );
        }
    }

    #[test]
    fn shuffle_spreads_required_characters() {
        // The first position must not always hold the lowercase pick.
        let o = PasswordOptions {
            length: 4,
            ..Default::default()
        };
        let mut first_lower = 0;
        for seed in 0..400 {
            if gen(seed, &o)
                .bytes()
                .next()
                .is_some_and(|b| LOWER.contains(&b))
            {
                first_lower += 1;
            }
        }
        assert!((60..140).contains(&first_lower), "{first_lower}");
    }

    #[test]
    fn rng_failure_returns_rng() {
        let r = generate_password_with(&mut Failing, &PasswordOptions::default());
        assert!(matches!(r, Err(Error::Rng)));
        // Fails also when the source dies mid-way.
        struct Dies(u32, Stub);
        impl RandomSource for Dies {
            fn fill(&mut self, b: &mut [u8]) -> Result<()> {
                if self.0 == 0 {
                    return Err(Error::Rng);
                }
                self.0 -= 1;
                self.1.fill(b)
            }
        }
        for n in [0, 5, 25, 30] {
            let r = generate_password_with(&mut Dies(n, Stub(1)), &PasswordOptions::default());
            assert!(matches!(r, Err(Error::Rng)));
        }
    }

    #[test]
    fn result_is_secret_string_with_redacted_debug() {
        let p: SecretString = generate_password(&PasswordOptions::default()).unwrap();
        let d = format!("{p:?}");
        assert!(d.contains("redacted"));
        assert!(!d.contains(p.expose()));
        assert_eq!(p.expose().len(), 20);
    }

    // ---- passphrase ----
    use bip39::Language;

    /// Yields fixed u64 values as big-endian bytes; errors when exhausted.
    struct Seq(Vec<u64>, usize);
    impl RandomSource for Seq {
        fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
            let v = *self.0.get(self.1).ok_or(Error::Rng)?;
            self.1 += 1;
            buf.copy_from_slice(&v.to_be_bytes()[..buf.len()]);
            Ok(())
        }
    }

    fn phrase(seed: u64, o: &PassphraseOptions) -> String {
        generate_passphrase_with(&mut Stub(seed), o)
            .unwrap()
            .expose()
            .to_string()
    }

    fn in_list(w: &str) -> bool {
        Language::English.word_list().contains(&w)
    }

    #[test]
    fn word_list_has_2048_distinct_entries() {
        let l = Language::English.word_list();
        assert_eq!(l.len(), 2048);
        let set: std::collections::HashSet<_> = l.iter().collect();
        assert_eq!(set.len(), 2048);
    }

    #[test]
    fn passphrase_defaults() {
        let o = PassphraseOptions::default();
        assert_eq!(o.words, 7);
        assert_eq!(o.separator, "-");
        assert!(!o.capitalize && !o.include_digit);
        let p = phrase(1, &o);
        let parts: Vec<&str> = p.split('-').collect();
        assert_eq!(parts.len(), 7);
        for w in parts {
            assert!(in_list(w), "{w}");
        }
    }

    #[test]
    fn passphrase_option_validation() {
        let bad = |f: &dyn Fn(&mut PassphraseOptions)| {
            let mut o = PassphraseOptions::default();
            f(&mut o);
            assert!(matches!(
                generate_passphrase_with(&mut Stub(1), &o),
                Err(Error::InvalidInput(_))
            ));
        };
        for w in [4, 24] {
            let o = PassphraseOptions {
                words: w,
                ..Default::default()
            };
            assert_eq!(phrase(2, &o).split('-').count(), w);
        }
        bad(&|o| o.words = 3);
        bad(&|o| o.words = 25);
        bad(&|o| o.separator = "123456789".into());
        bad(&|o| o.separator = "\u{e9}".into());
        bad(&|o| o.separator = "ab\u{e9}".into());
        let ok = PassphraseOptions {
            separator: "12345678".into(),
            ..Default::default()
        };
        assert_eq!(phrase(3, &ok).matches("12345678").count(), 6);
        let empty = PassphraseOptions {
            separator: String::new(),
            ..Default::default()
        };
        assert!(phrase(3, &empty).bytes().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn passphrase_capitalize() {
        let o = PassphraseOptions {
            capitalize: true,
            ..Default::default()
        };
        for seed in 0..20 {
            let p = phrase(seed, &o);
            for w in p.split('-') {
                assert!(w.as_bytes()[0].is_ascii_uppercase(), "{w}");
                assert!(w[1..].bytes().all(|b| b.is_ascii_lowercase()));
                assert!(in_list(&w.to_ascii_lowercase()));
            }
        }
    }

    #[test]
    fn passphrase_digit_on_exactly_one_word() {
        let o = PassphraseOptions {
            include_digit: true,
            ..Default::default()
        };
        for seed in 0..50 {
            let p = phrase(seed, &o);
            assert_eq!(p.bytes().filter(|b| b.is_ascii_digit()).count(), 1);
            let with: Vec<&str> = p
                .split('-')
                .filter(|w| w.ends_with(|c: char| c.is_ascii_digit()))
                .collect();
            assert_eq!(with.len(), 1);
            assert!(in_list(&with[0][..with[0].len() - 1]));
        }
    }

    #[test]
    fn passphrase_stub_draws_map_to_expected_words() {
        let l = Language::English.word_list();
        // 2048 divides 2^64: no rejection, one draw per word, index = draw % 2048.
        let o = PassphraseOptions {
            words: 4,
            separator: " ".into(),
            ..Default::default()
        };
        let mut s = Seq(vec![0, 1, 2047, 2048 + 5], 0);
        let p = generate_passphrase_with(&mut s, &o).unwrap();
        assert_eq!(s.1, 4);
        assert_eq!(
            p.expose(),
            &format!("{} {} {} {}", l[0], l[1], l[2047], l[5])
        );
        // Digit: after the words, one draw picks the word (% 4), one the digit (% 10).
        let o = PassphraseOptions {
            include_digit: true,
            ..o
        };
        let mut s = Seq(vec![0, 1, 2047, 5, 6, 17], 0);
        let p = generate_passphrase_with(&mut s, &o).unwrap();
        assert_eq!(s.1, 6);
        assert_eq!(
            p.expose(),
            &format!("{} {} {}7 {}", l[0], l[1], l[2047], l[5])
        );
    }

    #[test]
    fn passphrase_rng_failure() {
        for d in [false, true] {
            let o = PassphraseOptions {
                include_digit: d,
                ..Default::default()
            };
            assert!(matches!(
                generate_passphrase_with(&mut Failing, &o),
                Err(Error::Rng)
            ));
        }
        let o = PassphraseOptions {
            words: 4,
            include_digit: true,
            ..Default::default()
        };
        assert!(matches!(
            generate_passphrase_with(&mut Seq(vec![0; 4], 0), &o),
            Err(Error::Rng)
        ));
    }

    #[test]
    fn passphrase_os_source_works() {
        let p = generate_passphrase(&PassphraseOptions::default()).unwrap();
        assert_eq!(p.expose().split('-').count(), 7);
    }
}
