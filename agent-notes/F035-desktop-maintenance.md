# F035 desktop maintenance

- `state/maintenance.rs`: `MaintenanceKind`, `MaintenanceForm` (current/new/confirm SecretBufs, `rotate` default true, `confirmed`), `Screen::Maintenance(kind)`.
- Actions: `ShowMaintenance(kind)` (my addition, opens a form from Browse), `SubmitChangePassword|Rotate|Export|Import`, `CancelMaintenance`.
- Decisions the spec left open:
  - File pickers are called inside the Submit action (export: `save_export`; import: `pick_export` then `pick_key_file`). A picker cancel is silent and ends the action.
  - RotateKey form asks for the current password (core needs it) plus a `confirmed` checkbox; without it `UiError::ConfirmationRequired` (new variant, "confirmation is required").
  - Success text goes in `AppState::info()` (fixed strings, "imported N items"); `notice()` stays error-only. `info` is cleared by the next action and on lock.
  - Export password: `form.new`/`form.confirm`; import uses `form.new` only.
  - Buffers are wiped after every submit, cancel, lock/idle and ShowSettings; `is_clean()` checks them.
- Tests: `tests/maintenance.rs` (core vectors not needed; ciphertext checks use `format::HEADER_LEN/TRAILER_LEN` regions).
