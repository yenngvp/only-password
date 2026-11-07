//! Application state (no egui here).

/// The screen currently shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    Open,
}

/// Minimal state; later features replace `Default` with `AppState::new(AppDeps)`.
#[derive(Debug, Default)]
pub struct AppState {}

impl AppState {
    pub fn screen(&self) -> &Screen {
        &Screen::Open
    }
}
