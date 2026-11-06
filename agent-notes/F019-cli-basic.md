# F019 CLI basic

Built `onlypassword` (crates/onlypassword-cli): `args.rs` (hand-written parser), `prompt.rs`
(rpassword / `--stdin` lines, bounded 1 MiB), `keyfile.rs`, `error.rs` (exit 0/1/2/3), `cmd.rs`
(init, add-note, get, list, search, delete). Deps added to cli: rpassword, zeroize, tempfile
(dev), onlypassword-core (dev as well, for tests that insert items).

Decisions where the spec was open:
- Only exact flag spellings; `--flag=value` forms are unknown flags (usage error). Global
  options must precede the command. Not-yet-implemented commands (add-login, update, passwd,
  ...) are "unknown command" (exit 2) until later features.
- add-note accepts only `--title`, `--notes`, `--notes-file`.
- Key file is read before the master password prompt; `--notes-file` before both.
- Malformed item id exits 1 (same as unknown id); `--stdin` confirm mismatch in init exits 2.
- `get` prints `notes:` only when notes are non-empty; control chars in metadata are replaced
  with spaces in list/get output (keeps tab-separated lines intact, blocks escape sequences).
- init uses `KdfParams::DEFAULT` (tests run the real parameters, ~0.3 s per command).
- Key file is written as `<text>\n`. Prompts print nothing in `--stdin` mode.
- Key read-back is compared with a local constant-time fold, not `==`.
