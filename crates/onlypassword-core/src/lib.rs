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

#[cfg(test)]
mod tests {
    #[test]
    fn workspace_builds_and_tests_run() {
        let v: Result<u8, ()> = "1".parse::<u8>().map_err(|_| ());
        assert_eq!(v.unwrap(), 1);
    }
}
