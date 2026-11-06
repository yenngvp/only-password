# F021 CLI advanced

Added `passwd [--rotate]`, `rotate-key`, `export --out`, `import --in --source-secret-key-file`,
`totp <ID> [--time]`, `generate password|passphrase` (args.rs, cmd.rs). Tests: tests/e2e_advanced.rs
(real binary; records are parsed per crypto-spec §5 to show every body changes on rotation).

Decisions where the spec was open:
- `generate` needs no `--vault`/`--secret-key-file`; they are accepted and ignored. Ranges are
  checked in the parser (length 4..=256, words 4..=24, separator <=8 ASCII, at least one class) so
  they exit 2 rather than the core's exit 1.
- `export --out` equal to the vault (via `storage::same_file_path`) is checked before any prompt,
  exit 2. Export/passwd use `KdfParams::DEFAULT`. Export password is confirmed; import's is not.
- `import` reads the source key file before prompting; target key mismatch = exit 3 via core.
- `totp` prints `<code>\n<N> seconds remaining`; an item without TOTP exits 1.
- `passwd` without `--rotate` prints a reminder that the vault key was NOT rotated.
- Added `serde_json` (approved) as a CLI dev-dependency to load spec/vectors/totp.json.
