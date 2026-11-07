# F031-desktop-clipboard

Built `clipboard.rs` in the desktop crate: `ClipboardBackend`, `ArboardBackend`
(lazy connect; Windows: exclude_from_history + exclude_from_cloud; macOS:
exclude_from_history; Linux: arboard 3.7 offers none, plain set), `MemoryClipboard`
(text, sensitive, failure switch, read/set/clear counters, `set_external`), and
`ClipboardService` (digest `[u8; 32]`, deadline from UiClock, Debug prints only a pending flag).

Wiring: `AppDeps.clipboard`; `AppState` splits `AppDeps` into a private `Deps` plus the
service (which owns the backend). `Action::Copy(FieldRef)` works on the detail screen, borrows the
text from the held item (no copy). `tick` polls; `lock_now` (Lock, idle, on_exit) calls `clear_now`;
`SaveSettings` calls `set_timeout` (pending deadline unchanged). `is_clean` includes the service.
Copy buttons: all masked fields plus plain custom fields (labelled "Copy <name>").

Decisions: a failed `copy` leaves an earlier pending clear in place (clipboard still holds the old
value). A failed read/clear at the deadline or lock sets `UiError::Clipboard` from `tick` (not from
lock, which must not depend on the clipboard) and forgets the pending value. Username/URL have no
Copy button (FieldRef has no variant for them).
Deps added: `arboard` (default-features off, `wayland-data-control`) and `sha2`; both in approved-deps.
