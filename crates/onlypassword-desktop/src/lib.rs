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

//! The onlypassword desktop application (library part).

pub mod app;
pub mod clipboard;
pub mod clock;
pub mod config;
pub mod error;
pub mod picker;
pub mod secret_buf;
pub mod state;
pub mod view;
