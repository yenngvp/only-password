//! Secret containers: zeroized on drop, redacted `Debug`, no `Display`, no `Serialize`,
//! and no `Clone` (nothing needs it yet).

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret text.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(s: String) -> Self {
        SecretString(s)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

/// Secret bytes of variable length.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    pub fn new(v: Vec<u8>) -> Self {
        SecretVec(v)
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretVec(<redacted>)")
    }
}

/// Secret bytes of fixed length.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    pub fn new(b: [u8; N]) -> Self {
        SecretBytes(b)
    }
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &str = "hunter2-sentinel";

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn all_secret_types_zeroize_on_drop() {
        assert_zeroize_on_drop::<SecretString>();
        assert_zeroize_on_drop::<SecretVec>();
        assert_zeroize_on_drop::<SecretBytes<32>>();
        assert_zeroize_on_drop::<SecretBytes<1>>();
    }

    fn check_redacted(dbg: String) {
        assert!(!dbg.contains(SENTINEL));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn debug_is_redacted() {
        check_redacted(format!("{:?}", SecretString::new(SENTINEL.to_string())));
        check_redacted(format!("{:#?}", SecretString::new(SENTINEL.to_string())));
        check_redacted(format!(
            "{:?}",
            SecretVec::new(SENTINEL.as_bytes().to_vec())
        ));
        let mut b = [0u8; 16];
        b.copy_from_slice(SENTINEL.as_bytes());
        check_redacted(format!("{:?}", SecretBytes::<16>::new(b)));
        // also not via the raw byte values
        let d = format!("{:?}", SecretVec::new(vec![104, 117, 110]));
        assert!(!d.contains("104"));
    }

    #[test]
    fn expose_returns_contents() {
        assert!(SecretString::new(SENTINEL.into()).expose() == SENTINEL);
        let v = SecretVec::new(vec![1, 2, 3]);
        assert!(v.expose() == [1, 2, 3] && v.len() == 3 && !v.is_empty());
        assert!(SecretBytes::<2>::new([9, 8]).expose() == &[9, 8]);
    }

    #[test]
    fn zeroize_wipes_contents() {
        let mut s = SecretString::new(SENTINEL.into());
        s.zeroize();
        assert!(s.expose().is_empty());
        let mut v = SecretVec::new(vec![7; 4]);
        v.zeroize();
        assert!(v.is_empty());
        let mut b = SecretBytes::<4>::new([7; 4]);
        b.zeroize();
        assert!(b.expose() == &[0; 4]);
    }
}
