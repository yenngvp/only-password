//! `SecretBuf`: zeroizing text buffer for secrets typed into forms.

use std::fmt;
use std::ops::Range;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Initial capacity, so ordinary passwords never reallocate.
pub const INITIAL_CAPACITY: usize = 1024;
/// Hard limit on the buffer size in bytes.
pub const MAX_BYTES: usize = 64 * 1024;

/// Secret text. Never `Clone`; `Debug` is redacted; zeroized on drop.
///
/// Every operation that would move the contents (growth, deletion) builds a
/// fresh buffer and zeroizes the old one, so no stale copy stays on the heap.
pub struct SecretBuf(Zeroizing<String>);

impl SecretBuf {
    pub fn new() -> Self {
        SecretBuf(Zeroizing::new(String::with_capacity(INITIAL_CAPACITY)))
    }

    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    /// Append text; returns false (and changes nothing) past the size limit.
    pub fn push_str(&mut self, text: &str) -> bool {
        let end = self.len();
        self.insert_bytes(end, text)
    }

    /// Empty the buffer and wipe its memory, keeping the reserved capacity.
    pub fn clear(&mut self) {
        self.0.zeroize();
        if self.0.capacity() < INITIAL_CAPACITY {
            self.0 = Zeroizing::new(String::with_capacity(INITIAL_CAPACITY));
        }
    }

    /// Insert at a character index (clamped to the end). False if over the limit.
    pub fn insert_at_char(&mut self, char_index: usize, text: &str) -> bool {
        let at = self.byte_of_char(char_index);
        self.insert_bytes(at, text)
    }

    /// Delete a character range (clamped).
    pub fn delete_char_range(&mut self, range: Range<usize>) {
        let start = self.byte_of_char(range.start);
        let end = self.byte_of_char(range.end);
        if start >= end {
            return;
        }
        let mut fresh = Zeroizing::new(String::with_capacity(
            self.0.capacity().max(INITIAL_CAPACITY),
        ));
        let s = self.0.as_str();
        fresh.push_str(s.get(..start).unwrap_or(""));
        fresh.push_str(s.get(end..).unwrap_or(""));
        self.0 = fresh;
    }

    fn byte_of_char(&self, char_index: usize) -> usize {
        self.0
            .char_indices()
            .nth(char_index)
            .map_or(self.0.len(), |(i, _)| i)
    }

    fn insert_bytes(&mut self, at: usize, text: &str) -> bool {
        let new_len = match self.0.len().checked_add(text.len()) {
            Some(n) if n <= MAX_BYTES => n,
            _ => return false,
        };
        if new_len > self.0.capacity() {
            let cap = new_len
                .max(self.0.capacity().saturating_mul(2))
                .min(MAX_BYTES);
            let mut fresh = Zeroizing::new(String::with_capacity(cap));
            let s = self.0.as_str();
            fresh.push_str(s.get(..at).unwrap_or(""));
            fresh.push_str(text);
            fresh.push_str(s.get(at..).unwrap_or(""));
            self.0 = fresh;
        } else {
            self.0.insert_str(at, text);
        }
        true
    }
}

impl Default for SecretBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBuf(<redacted>)")
    }
}

impl Zeroize for SecretBuf {
    fn zeroize(&mut self) {
        self.clear();
    }
}

impl ZeroizeOnDrop for SecretBuf {}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn type_level_and_capacity() {
        assert_zeroize_on_drop::<SecretBuf>();
        let b = SecretBuf::new();
        assert!(b.capacity() >= 1024);
        assert!(b.is_empty());
    }

    #[test]
    fn debug_is_redacted() {
        let mut b = SecretBuf::new();
        b.push_str("pw-SENTINEL");
        let d = format!("{b:?}");
        assert!(!d.contains("SENTINEL"));
    }

    #[test]
    fn edit_operations() {
        let mut b = SecretBuf::new();
        assert!(b.push_str("héllo"));
        assert!(b.insert_at_char(1, "XY"));
        assert_eq!(b.expose(), "hXYéllo");
        b.delete_char_range(1..4);
        assert_eq!(b.expose(), "hllo");
        b.delete_char_range(3..99);
        assert_eq!(b.expose(), "hll");
        b.clear();
        assert!(b.is_empty());
        assert!(b.capacity() >= 1024);
    }

    #[test]
    fn grows_past_initial_capacity_and_enforces_limit() {
        let mut b = SecretBuf::new();
        let chunk = "a".repeat(1000);
        for _ in 0..65 {
            assert!(b.push_str(&chunk));
        }
        assert_eq!(b.len(), 65_000);
        assert!(!b.push_str(&chunk));
        assert_eq!(b.len(), 65_000);
    }
}
