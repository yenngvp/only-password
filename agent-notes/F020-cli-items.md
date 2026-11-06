# F020 CLI items

Added `add-login` and `update` (args.rs `item_flags`, cmd.rs `apply_prompted`). Flags and prompt
order follow architecture.md section 5: master, item password (skipped by `--generate`), TOTP
secret, notes, hidden values in flag order. TOTP goes through `base32::normalize_totp_secret`.

Decisions where the spec was open:
- Usage errors (exit 2), all before any prompt: totp parameter flags without `--totp`, clear flag
  plus setter, `--notes` with `--notes-file`, repeated switches, bad digits/period/algorithm,
  `--field` without `=`, `add-login` without `--title`.
- `--generate` and `--show-secrets` exist only on add-login; `--new-password` and `--clear-*` only
  on update (elsewhere they are unknown flags, exit 2). `add-login --generate --show-secrets`
  prints an extra `password: ...` line after the id. Generation uses `PasswordOptions::default()`.
- `--field` and `--hidden-field` keep command-line order in the stored list.
- Note-illegal flags on update (`--username`, `--url`, `--new-password`, `--totp`) are caught by
  core validation in `Vault::update` (exit 1, nothing written).
- `update` prints `updated <id>`. Invalid TOTP secret exits 1 (static message) after its prompt.
- Tests: crates/onlypassword-cli/tests/e2e.rs (`add_login_*`, `update_*`, `invalid_totp_*`); the
  argv of each run is checked to contain no secret value.
