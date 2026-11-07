# F037 desktop e2e

Added `crates/onlypassword-desktop/tests/e2e.rs`: one scenario `phase2_definition_of_done` with
`KdfParams::DEFAULT`, ManualClock, MemoryClipboard, ScriptedPicker and tempdir config dirs
(no `common` helper, because that one uses the fast KDF).

Order: create -> add login (TOTP SHA-1/8 from spec/vectors/totp.json, plain + hidden field) and note
(title typed in the kittest edit view) -> manual lock (kittest button) -> unlock (kittest view) ->
read back via `Select`/`selected()`, TOTP code at 1111111109, clipboard copy + clear at 30 s -> idle
lock by advancing ManualClock -> change password (rotate) -> old password gives Authentication ->
export -> second vault, import with its own key (Authentication) then the first key -> compare ->
lock both and scan Debug, config.json files, captured notices/info for all secrets and key text.

Decisions: items are compared as field snapshots (ids may differ); the key file text is read from disk
for the scan. Runs in about 3 s in the dev profile (argon2 is built at opt-level 3).
