//! Randomness: the operating-system source only. There is no fallback source;
//! failure is reported as `Error::Rng`.

use crate::error::{Error, Result};

/// A source of random bytes. Internal seam so tests can inject a deterministic stream.
pub(crate) trait RandomSource {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()>;
}

/// The operating-system CSPRNG via `getrandom`.
struct OsSource;

impl RandomSource for OsSource {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        getrandom::fill(buf).map_err(|_| Error::Rng)
    }
}

/// Fill `buf` with OS random bytes.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    OsSource.fill(buf)
}

/// Return `N` OS random bytes.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    random_array_with(&mut OsSource)
}

pub(crate) fn random_array_with<const N: usize>(src: &mut dyn RandomSource) -> Result<[u8; N]> {
    let mut a = [0u8; N];
    src.fill(&mut a)?;
    Ok(a)
}

/// Unbiased uniform value in `0..n` by rejection sampling. `n == 0` is an error.
pub fn uniform(n: u64) -> Result<u64> {
    uniform_with(&mut OsSource, n)
}

pub(crate) fn uniform_with(src: &mut dyn RandomSource, n: u64) -> Result<u64> {
    reject_sample(n, 64, || {
        let mut b = [0u8; 8];
        src.fill(&mut b)?;
        Ok(u64::from_be_bytes(b))
    })
}

/// Rejection sampling over a raw draw of `bits` bits (1..=64): rejects exactly
/// `2^bits mod n` draws (those below it), so the accepted range is a multiple of `n`.
pub(crate) fn reject_sample(
    n: u64,
    bits: u32,
    mut draw: impl FnMut() -> Result<u64>,
) -> Result<u64> {
    if n == 0 {
        return Err(Error::InvalidInput("range must be non-zero"));
    }
    let t = if bits >= 64 {
        n.wrapping_neg() % n
    } else {
        (1u64 << bits) % n
    };
    loop {
        let x = draw()?;
        if x >= t {
            return Ok(x % n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Yields the given u64 values (big-endian bytes); errors when exhausted.
    struct Seq(std::collections::VecDeque<u64>);
    impl Seq {
        fn new(v: &[u64]) -> Self {
            Seq(v.iter().copied().collect())
        }
    }
    impl RandomSource for Seq {
        fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
            for chunk in buf.chunks_mut(8) {
                let v = self.0.pop_front().ok_or(Error::Rng)?.to_be_bytes();
                let l = chunk.len();
                chunk.copy_from_slice(v.get(8 - l..).ok_or(Error::Rng)?);
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

    #[test]
    fn n3_rejects_below_threshold() {
        // 2^64 mod 3 = 1, so only 0 is rejected.
        let mut s = Seq::new(&[0, 1, 5]);
        assert_eq!(uniform_with(&mut s, 3).unwrap(), 1);
        assert_eq!(uniform_with(&mut s, 3).unwrap(), 2);
        assert!(uniform_with(&mut s, 3).is_err()); // exhausted
    }

    #[test]
    fn n10_rejects_below_threshold() {
        // 2^64 mod 10 = 6: 0..=5 rejected, 6 accepted.
        let mut s = Seq::new(&[0, 5, 6, 17, u64::MAX]);
        assert_eq!(uniform_with(&mut s, 10).unwrap(), 6);
        assert_eq!(uniform_with(&mut s, 10).unwrap(), 7);
        assert_eq!(uniform_with(&mut s, 10).unwrap(), 5);
    }

    #[test]
    fn n_2_63_plus_1_threshold() {
        // 2^64 mod (2^63+1) = 2^63 - 1.
        let n = (1u64 << 63) + 1;
        let t = (1u64 << 63) - 1;
        let mut s = Seq::new(&[0, t - 1, t, t + 1, u64::MAX]);
        assert_eq!(uniform_with(&mut s, n).unwrap(), t);
        assert_eq!(uniform_with(&mut s, n).unwrap(), t + 1);
        assert_eq!(uniform_with(&mut s, n).unwrap(), (1u64 << 63) - 2);
    }

    #[test]
    fn exhaustive_8_bit_is_exactly_uniform() {
        for n in [3u64, 10] {
            let mut counts = vec![0u32; n as usize];
            for x in 0u64..256 {
                // One draw per input; rejected draws are followed by a fallback accepted value
                // only to terminate: use a source that yields x, then 255 if rejected.
                let mut seq = [x, 255 - (255 % n)].into_iter();
                let r = reject_sample(n, 8, || Ok(seq.next().unwrap())).unwrap();
                if x >= 256 % n {
                    counts[r as usize] += 1;
                }
            }
            let first = counts[0];
            assert!(first > 0);
            assert!(counts.iter().all(|&c| c == first), "n={n}: {counts:?}");
        }
    }

    #[test]
    fn exhaustive_8_bit_rejects_exactly_threshold() {
        for n in [3u64, 10] {
            let mut rejected = 0;
            for x in 0u64..256 {
                let mut calls = 0;
                let _ = reject_sample(n, 8, || {
                    calls += 1;
                    Ok(if calls == 1 { x } else { 255 })
                });
                if calls > 1 {
                    rejected += 1;
                }
            }
            assert_eq!(rejected, 256 % n);
        }
    }

    #[test]
    fn generic_width_matches_64_bit_form() {
        // 2^64 mod n via u128 equals the wrapping_neg form.
        for n in [3u64, 10, (1 << 63) + 1, u64::MAX] {
            assert_eq!(n.wrapping_neg() % n, ((1u128 << 64) % n as u128) as u64);
        }
    }

    #[test]
    fn uniform_zero_is_invalid_input() {
        assert!(matches!(uniform(0), Err(Error::InvalidInput(_))));
        assert!(matches!(
            uniform_with(&mut Seq::new(&[1]), 0),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn source_errors_map_to_rng() {
        assert_eq!(uniform_with(&mut Failing, 10), Err(Error::Rng));
        assert_eq!(random_array_with::<16>(&mut Failing), Err(Error::Rng));
    }

    #[test]
    fn os_source_works() {
        let a = random_array::<32>().unwrap();
        let b = random_array::<32>().unwrap();
        assert_ne!(a, b);
        let mut buf = [0u8; 0];
        fill_random(&mut buf).unwrap();
        assert!(uniform(10).unwrap() < 10);
        assert_eq!(uniform(1).unwrap(), 0);
    }
}
