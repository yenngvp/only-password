//! `DesktopApp`: the `eframe::App` glue.

use crate::{state::AppState, view};

/// The eframe application.
#[derive(Debug, Default)]
pub struct DesktopApp {
    state: AppState,
}

impl DesktopApp {
    pub fn new() -> Self {
        Self::default()
    }
}

impl eframe::App for DesktopApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        view::show(ui, &mut self.state);
    }
}
