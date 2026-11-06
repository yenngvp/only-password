#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

//! Core library of onlypassword.

pub mod base32;
pub mod crypto;
pub mod error;
pub mod format;
pub mod item;
pub mod rng;
pub mod seal;
pub mod secret;
pub mod storage;
#[cfg(test)]
mod testutil;

pub use error::{Error, Result};
pub use item::{
    CustomField, Item, ItemId, ItemKind, TotpAlgorithm, TotpConfig, MAX_ITEM_PLAINTEXT,
};
pub use secret::{SecretBytes, SecretString, SecretVec};

#[cfg(test)]
mod tests {
    #[test]
    fn workspace_builds_and_tests_run() {
        let v: Result<u8, ()> = "1".parse::<u8>().map_err(|_| ());
        assert_eq!(v.unwrap(), 1);
    }
}
