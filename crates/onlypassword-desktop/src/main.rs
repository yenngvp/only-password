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

//! Thin binary: the only place that starts the eframe event loop.

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "onlypassword",
        options,
        Box::new(|_cc| Ok(Box::new(onlypassword_desktop::app::DesktopApp::new()))),
    )
}
