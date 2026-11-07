//! TOTP display state for the detail screen (REQ-GUI-040, REQ-GUI-041). No egui.

use std::fmt;

use onlypassword_core::{totp_for_item, TotpConfig};
use zeroize::Zeroizing;

/// The code (or the core's fixed error message) and the time left in the period.
pub struct TotpView {
    /// The current code; `None` when the stored parameters are invalid.
    pub code: Option<Zeroizing<String>>,
    /// The core's fixed message when `code` is `None`.
    pub error: Option<String>,
    /// Whole seconds until the next code, in `1..=period` (0 only for period 0).
    pub remaining: u32,
    pub period: u32,
}

impl fmt::Debug for TotpView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpView { .. }")
    }
}

/// Pure: code and remaining seconds for `cfg` at `unix_secs`.
pub fn totp_view(cfg: &TotpConfig, unix_secs: u64) -> TotpView {
    let period = cfg.period;
    let remaining = u64::from(period)
        .checked_sub(unix_secs.checked_rem(u64::from(period)).unwrap_or(0))
        .and_then(|r| u32::try_from(r).ok())
        .unwrap_or(0);
    match totp_for_item(cfg, unix_secs) {
        Ok(code) => TotpView {
            code: Some(Zeroizing::new(code)),
            error: None,
            remaining,
            period,
        },
        Err(e) => TotpView {
            code: None,
            error: Some(e.to_string()),
            remaining,
            period,
        },
    }
}
