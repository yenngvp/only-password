# F032-desktop-totp

- `state/totp.rs`: pure `totp_view(&TotpConfig, unix_secs) -> TotpView` (code in `Zeroizing`,
  or the core's `Error::to_string()` in `error`; `remaining` = period - unix % period, 0 only for
  an invalid period 0). `Debug` redacted.
- `BrowseState.totp` is set on Select and recomputed by `AppState::tick` (`refresh_totp`); cleared on
  Back, failed Select, vault-item removal and lock (session drop). `AppState::totp()` reads it.
- `FieldRef::TotpCode` (copy only; never revealable) goes through `Action::Copy` and the clipboard service.
- `view::totp_section`: code label, Copy button, "Expires in N s" label and `ProgressBar`.
  Shown only for a valid config; an invalid one shows only the fixed message.
- Repaint: `repaint_after` already requests 1 s repaints while unlocked, which covers this.
- Spec issues (see spec-issues.md): acceptance says 21 s remaining at 1111111109, formula gives 1;
  invalid digits cannot be stored via the core API, so that case is tested on `totp_view` directly.
