# F036 desktop hardening

Added `crates/onlypassword-desktop/tests/hardening_scan.rs` (source scans with self-tests on synthetic
text, Cargo.lock denylist, `[dependencies]` feature check) and `tests/hardening_session.rs`
(sentinel session, 4 seeded 2 000-action runs, fixed Display list).

- Scanner strips `//` comments, and for the panic scan stops at the first `#[cfg(test)]`. Indexing is left
  to the crate-root clippy lints (checked by `crate_roots_forbid_unsafe_and_deny_panicking_lints`).
- Only src change: `Action::Lock` without a session wipes typed secrets (`wipe_idle_forms`).
- tokio lock exception and "i/o error" slash: see `spec-issues.md` (F036 section).
- Random run uses an xorshift RNG; sentinels are asserted absent from Debug/notice/info after every action.
