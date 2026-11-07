//! `DesktopApp`: the `eframe::App` glue.

use onlypassword_core::crypto::kdf::KdfParams;

use crate::clipboard::ArboardBackend;
use crate::clock::SystemUiClock;
use crate::config::ConfigStore;
use crate::picker::RfdPicker;
use std::time::Duration;

use crate::state::{Action, AppDeps, AppState};
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
            clipboard: Box::new(ArboardBackend::new()),
            picker: Box::new(RfdPicker::new()),
            config_store: ConfigStore::platform_default(),
            kdf: KdfParams::DEFAULT,
        };
        DesktopApp {
            state: AppState::new(deps),
        }
    }
}

/// When the next repaint is needed without input: within a second while a
/// session exists, so the idle timer fires; never while locked.
pub fn repaint_after(state: &AppState) -> Option<Duration> {
    state.is_unlocked().then_some(Duration::from_secs(1))
}

impl Default for DesktopApp {
    fn default() -> Self {
        Self::new()
    }
}

impl eframe::App for DesktopApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let active = ctx.input(|i| {
            !i.events.is_empty() || i.pointer.is_moving() || i.pointer.delta() != egui::Vec2::ZERO
        });
        if active {
            self.state.dispatch(Action::Activity);
        }
        self.state.tick();
        view::show(ui, &mut self.state);
        if let Some(after) = repaint_after(&self.state) {
            ctx.request_repaint_after(after);
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.state.on_exit();
    }
}
