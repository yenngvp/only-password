
## F008 (attempt 2)
- Over-size serialization returns `LimitExceeded`; spec/acceptance only mention InvalidInput for the size limit (on read, `InvalidInput` is used). Owner to confirm.
- `to_plaintext`/`from_plaintext` take/return `(created_ms, updated_ms)`, deviating from the architecture sketch. Owner to confirm.

## F008 (attempt 2)
- Over-size serialization returns `LimitExceeded`; spec/acceptance only mention InvalidInput for the size limit (on read, `InvalidInput` is used). Owner to confirm.
- `to_plaintext`/`from_plaintext` take/return `(created_ms, updated_ms)`, deviating from the architecture sketch. Owner to confirm.

## F024-desktop-skeleton
1. **BLOCKER – cargo-deny licence.** `eframe` feature `default_fonts` (required by approved-deps.txt and the feature text) pulls `epaint_default_fonts 0.37.0`, whose licence is `(MIT OR Apache-2.0) AND OFL-1.1 AND Ubuntu-font-1.0`. `pipeline/deny.toml` allows `LicenseRef-UFL-1.0` but the SPDX id cargo-deny sees is `Ubuntu-font-1.0`, so the gate's cargo-deny step fails ("licenses FAILED"). I may not edit `pipeline/`. Without `default_fonts` the licence check passes but egui panics at first text layout (epaint fonts.rs:806, no fonts), so that is not a safe workaround. Owner: add `Ubuntu-font-1.0` to the allow list in `pipeline/deny.toml` (and probably drop the unused `LicenseRef-UFL-1.0`). The gate was NOT passed; the rest of the gate was not reached.
2. **egui 0.37 API vs spec.** In egui/eframe 0.37 `CentralPanel::show` takes `&mut Ui` and `eframe::App` has `ui(&mut self, ui, frame)` instead of `update(ctx, frame)`. So `view::show` is `show(ui: &mut egui::Ui, state: &mut AppState)`, not `show(ctx: &egui::Context, ..)`, and the kittest harness is `Harness::new_ui_state`. Closest safe reading; architecture.md 7.2/7.8 should be updated.
