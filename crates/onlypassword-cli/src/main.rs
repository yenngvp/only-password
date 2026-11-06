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

//! The `onlypassword` command-line tool.

mod args;
mod cmd;
mod error;
mod keyfile;
mod prompt;

use std::ffi::OsString;
use std::process::ExitCode;

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    match cmd::run(argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("onlypassword: {}", e.message());
            ExitCode::from(e.exit_code())
        }
    }
}
