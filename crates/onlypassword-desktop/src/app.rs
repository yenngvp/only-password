//! `DesktopApp`: the `eframe::App` glue.

use onlypassword_core::crypto::kdf::KdfParams;

use crate::clock::SystemUiClock;
use crate::config::ConfigStore;
use crate::picker::RfdPicker;
use crate::state::{AppDeps, AppState};
use crate::view;

/// The eframe application.
#[derive(Debug)]
pub struct DesktopApp {
    state: AppState,
}

impl DesktopApp {
    pub fn new() -> Self {
        let deps = AppDeps {
            clock: Box::new(SystemUiClock::new()),
            picker: Box::new(RfdPicker::new()),
            config_store: ConfigStore::platform_default(),
            kdf: KdfParams::DEFAULT,
        };
        DesktopApp {
            state: AppState::new(deps),
        }
    }
}

impl Default for DesktopApp {
    fn default() -> Self {
        Self::new()
    }
}

impl eframe::App for DesktopApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.state.tick();
        view::show(ui, &mut self.state);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.state.on_exit();
    }
}
