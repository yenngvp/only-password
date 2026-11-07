//! Rendering of the application state.

use crate::state::AppState;

/// Draw the current screen.
pub fn show(ui: &mut egui::Ui, _state: &mut AppState) {
    egui::CentralPanel::default().show(ui, |ui| {
        ui.heading("onlypassword");
        ui.label("Locked");
    });
}
