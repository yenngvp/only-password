# Requirements

"The core" means the library crate `onlypassword-core`; "the CLI" means the binary crate
`onlypassword-cli`. Byte-level details are in `crypto-spec.md` (cited as CS §n). Every
requirement is testable; `features.json` maps each one to a feature that tests it.

## KEY — unlock keys

- **REQ-KEY-001** When a vault is created, the core shall generate a 256-bit secret key from the operating system's random source and return it to the caller, and shall not write it to the vault file.
- **REQ-KEY-002** When a vault is unlocked, the core shall derive the master key from the NFKC-normalized master password with Argon2id (parameters read from the authenticated header) and combine it with the secret key through HKDF-SHA-256 exactly as in CS §3.3.
- **REQ-KEY-003** When a vault is created or its master password is changed without explicit parameters, the core shall use Argon2id m = 65 536 KiB, t = 3, p = 4 (CS §10), and shall never default to a memory cost above 64 MiB.
- **REQ-KEY-004** When asked to create, or to open a file declaring, Argon2id parameters outside the bounds of CS §10 (floor m ≥ 19 456 KiB, t ≥ 2, p ≥ 1; ceiling m ≤ 262 144 KiB, t ≤ 16, p ≤ 16), the core shall return `InvalidInput` (creation) or `Corrupt` (file) before running Argon2id; only builds with `cfg(test)` or the non-default `insecure-fast-kdf` feature may accept lower values, and `KdfParams::validate_strict` always enforces the real floor.
- **REQ-KEY-005** When the password or the secret key is wrong, the core shall return the single error `Authentication`, without indicating which of the two was wrong.
- **REQ-KEY-006** When a secret key is formatted or parsed in text form, the core shall use the `OPSK1-` encoding of CS §3.2, and shall return `InvalidInput` for a wrong prefix, wrong length, invalid character or non-zero trailing bits.
- **REQ-KEY-007** When a master password or export password shorter than 8 Unicode scalar values after normalization is supplied for creating a vault, changing the password or exporting, the core shall return `InvalidInput`; unlock and import shall not apply the minimum.
- **REQ-KEY-008** The core shall not provide any recovery, reset, hint or backdoor path that decrypts a vault without both the master password and the secret key.

## HIER — key hierarchy

- **REQ-HIER-001** When a vault is created, the core shall generate a random 256-bit vault key and store it only wrapped by the master key (CS §6.2).
- **REQ-HIER-002** When an item revision is written, the core shall generate a fresh random 256-bit item key and store it only wrapped by the item-key-wrapping subkey derived from the vault key (CS §3.4, §6.3).
- **REQ-HIER-003** The core shall derive purpose-separated subkeys from the vault key only with the HKDF info labels listed in CS §3.5, and shall not use the vault key directly as an AEAD key.

## ENC — encryption

- **REQ-ENC-001** When encrypting, the core shall use XChaCha20-Poly1305 with a fresh random 24-byte nonce for every encryption and shall never reuse or derive a nonce.
- **REQ-ENC-002** When encrypting or decrypting an item, the core shall bind the ciphertext to vault ID, item ID, revision, item schema version and format version through the associated data in CS §6.3.
- **REQ-ENC-003** When a record is copied to a different item ID, vault, revision or format/schema version, decryption shall fail with `Authentication`.
- **REQ-ENC-004** When a record is removed, added or replaced by an older valid record of the same vault, the file trailer check (CS §6.4) shall fail on unlock with `Authentication`.
- **REQ-ENC-005** When any single byte of a vault file is changed, the core shall return an error (`Authentication`, `Corrupt` or `UnsupportedVersion`) on unlock or on reading the affected item, and shall return no plaintext.
- **REQ-ENC-006** When the file trailer or `wrapped_vk` fails verification, the core shall not decrypt any item record.

## FMT — vault file and versions

- **REQ-FMT-001** The core shall write and read vault files exactly as laid out in CS §5, in a single file.
- **REQ-FMT-002** When a vault or export file has a format version, KDF id or KDF version, or a JSON `schema`/`export_schema`, other than the one supported (smaller or larger), the core shall return `UnsupportedVersion`; the other checks of the ordered tables in CS §9 return the errors listed there (the first failing check decides), and the core shall not attempt to read, convert or re-save an unsupported file. A changed record `item_schema` is `Authentication` (it is only authenticated, never pre-checked).
- **REQ-FMT-003** When a vault file is truncated, has trailing bytes, has non-zero flags, has out-of-bound lengths or counts, or has unsorted or duplicate record IDs, the core shall return `Corrupt` without panicking and without allocating more than the file's own length.
- **REQ-FMT-004** When the core saves a vault, it shall write a temporary file in the same directory, flush and fsync it, rename it over the target, and fsync the directory where the platform supports it, so that a failure at any point leaves either the complete old file or the complete new file.
- **REQ-FMT-005** When a vault file is created on a Unix platform, the core shall create it with permissions 0600.
- **REQ-FMT-006** When a save fails, the core shall remove its temporary file, leave the target file unchanged, and return `Io`.
- **REQ-FMT-008** When a new vault file is created, the core shall write a temporary file (0600, fsync), publish it with `std::fs::hard_link` (which fails if the target exists), remove the temporary file and fsync the directory (CS §6.6); it shall never use `rename` for creation, so an existing file is never replaced and a crash leaves either no vault or a complete one; where hard links are unavailable it returns `Io`.
- **REQ-FMT-009** When a save targets a symbolic link, the core shall write and rename next to and over the resolved file, so the link remains.
- **REQ-FMT-007** The core shall check magic and version before interpreting any other header field (CS §9 order).

## ITM — item model

- **REQ-ITM-001** The core shall represent a login item with title, username, password, a list of URLs, notes, an optional TOTP secret with algorithm, digits and period, and custom fields (name, value, hidden flag).
- **REQ-ITM-002** The core shall represent a secure note item with title and notes, and shall reject a note carrying username, password, URLs or TOTP.
- **REQ-ITM-003** The core shall store `created_ms` and `updated_ms` timestamps; when an item is added both are set to the current time, and when it is updated `created_ms` is kept and `updated_ms` is set to the current time (never earlier than `created_ms`).
- **REQ-ITM-004** The core shall serialize items as the compact, fixed-key-order versioned JSON of CS §7 and, when deserializing, shall read `schema` first (`UnsupportedVersion` unless 1) and then reject unknown fields, duplicate keys (also inside `totp` and `fields[]`), missing fields, **including absent nullable keys** (`username`, `password`, `totp` must be present, possibly `null`), wrong types and values over the limits of CS §7.
- **REQ-ITM-005** When an item is added, the core shall assign it a random 128-bit ID (shown as 32 lowercase hex characters) that is unique in the vault.
- **REQ-ITM-007** The core shall store a TOTP secret only in the canonical form of CS §7 (upper-case base32, no padding or separators, 10..=128 decoded bytes); `Item::validate` shall reject any other form with `InvalidInput`, and `normalize_totp_secret` shall produce the canonical form from user input.
- **REQ-ITM-006** When an item violates a limit in CS §7 (sizes, counts, kind rules, TOTP parameters), the core shall return `InvalidInput` and leave the vault unchanged.

## LIF — lifecycle

- **REQ-LIF-001** When `create` is called, the core shall write a new, empty, valid vault file using the create procedure of CS §6.6 (REQ-FMT-008) and return an unlocked vault and the new secret key; `create_with_key` shall do the same with a caller-supplied secret key. If the target path already exists, even if it appears between the temporary write and the publication, the core shall return an error and leave the existing file untouched.
- **REQ-LIF-002** When `unlock` is called with the correct password and secret key, the core shall return an unlocked vault from which all items can be read.
- **REQ-LIF-003** When a vault is locked or dropped, the core shall zeroize the vault key, subkeys and any decrypted item contents it holds; a locked vault is not representable as a usable value.
- **REQ-LIF-004** When `add` is called with a valid item, the core shall persist it atomically and return its new ID, with revision 1.
- **REQ-LIF-005** When `get` is called with an existing ID, the core shall return the decrypted item with its ID and revision; for an unknown ID it shall return `NotFound`.
- **REQ-LIF-006** When `update` is called for an existing ID, the core shall replace the item with a new revision (revision + 1, fresh item key and nonces), persist atomically, and keep the ID and `created_ms`; for an unknown ID it shall return `NotFound`, and for a stored revision of `u64::MAX` it shall return `LimitExceeded`.
- **REQ-LIF-007** When `delete` is called for an existing ID, the core shall remove the record, persist atomically, and afterwards `get` for that ID shall return `NotFound`.
- **REQ-LIF-008** When `list` is called, the core shall return summaries (ID, kind, title, username, `updated_ms`, revision) sorted by `title.to_lowercase()` compared byte-wise, then by ID, and the summaries shall not contain passwords, notes, TOTP secrets or hidden field values.
- **REQ-LIF-009** When `search` is called with a query, the core shall return the summaries whose title, username or any URL contains the query as a substring after both are lower-cased with `str::to_lowercase()`, and shall not search passwords, notes, TOTP secrets or custom fields.
- **REQ-LIF-010** When `change_master_password` is called, the core shall verify the current password, re-wrap the same vault key under a master key derived from a new random salt and the new password (same secret key), leave all item records byte-identical, persist atomically, and afterwards the old password shall fail with `Authentication`.
- **REQ-LIF-011** When `rotate_vault_key` is called, the core shall generate a new vault key, re-encrypt every item under a fresh item key and fresh nonces with unchanged revisions and contents, re-wrap and persist atomically, and afterwards no old item key or old ciphertext shall validate against the new file.
- **REQ-LIF-012** When any mutating operation fails (including on I/O error), the on-disk file and the in-memory vault shall be unchanged.
- **REQ-LIF-014** When `add`, `update` or `import` would produce a vault image above 512 MiB or more than 100 000 records, the core shall return `LimitExceeded` before writing anything; `export` shall return `LimitExceeded` rather than write a payload above `MAX_EXPORT_PLAINTEXT` (CS §10).
- **REQ-LIF-015** The core shall provide `change_master_password_and_rotate_key`, which changes the password and rotates the vault key in one atomic write; `change_master_password` alone does not revoke earlier knowledge of the vault key (CS §6.5) and its documentation shall say so.
- **REQ-LIF-013** When the core is asked to change the master password to the current password, it shall still generate a new salt and nonce.

## GEN — password generator

- **REQ-GEN-001** When a random password is requested, the core shall produce a string of the configured length (4..=256, default 20) from the enabled character classes (lowercase, uppercase, digits, symbols as defined in architecture.md), with an option to exclude the ambiguous characters `0 O o 1 l I` and an option (default on) to require at least one character from every enabled class.
- **REQ-GEN-002** When a passphrase is requested, the core shall produce 4..=24 words (default 7) chosen uniformly from the BIP-39 English list of 2 048 words, with a configurable separator (default `-`, at most 8 ASCII characters), optional capitalization and an optional single trailing digit on one random word.
- **REQ-GEN-003** The core shall obtain all random choices from the operating system's random source and shall remove modulo bias by rejection sampling (`uniform(n)` in architecture.md); a statistical test with a deterministic RNG stub shall show equal frequencies for a range that does not divide 2^64.
- **REQ-GEN-004** When generator options are invalid (length out of range, no class enabled, an enabled class empty after exclusions, length smaller than the number of required classes, word count out of range, over-long separator), the core shall return `InvalidInput`.
- **REQ-GEN-005** When the operating system random source fails, the generator shall return `Rng` and shall not fall back to any other source.

## TOT — one-time codes

- **REQ-TOT-001** When a TOTP code is requested for a secret, algorithm (SHA-1, SHA-256, SHA-512), digit count (6..=8), period and Unix time, the core shall return the RFC 6238 value, computed with HOTP per RFC 4226 §5.3 dynamic truncation.
- **REQ-TOT-002** The core shall match every row of `spec/vectors/totp.json` and `spec/vectors/hotp.json`.
- **REQ-TOT-003** When a TOTP secret is parsed from text, the core shall accept RFC 4648 base32 case-insensitively, ignoring spaces and `-` and optional trailing `=`, requiring 10..=128 decoded bytes, and shall return `InvalidInput` otherwise.
- **REQ-TOT-004** The core shall take the time as an explicit argument and shall not read the clock inside the TOTP functions.
- **REQ-TOT-005** When the stored TOTP parameters of an item are out of range, the core shall return `InvalidInput` instead of computing a code.

## EXP — export and import

- **REQ-EXP-001** When an export is requested with an export password, the core shall write an export file in the format of CS §8 containing every item of the unlocked vault, atomically (REQ-FMT-004). The export key shall combine the export password and the vault's secret key (`export` takes the key as an argument), so that the export is useless without both; `export` shall return `InvalidInput` when the target is the vault file itself (canonicalized comparison).
- **REQ-EXP-002** When an export file is imported into an unlocked vault with the correct export password and the secret key of the vault it was exported from (`source_key`, which need not be the target vault's key), the core shall add every item under its original ID, revision and content, and an export of vault A imported into a fresh vault B shall make B's `list` and every `get` equal A's.
- **REQ-EXP-003** When the export password or the source secret key is wrong or any byte of the export file is changed, import shall fail with `Authentication`, `Corrupt` or `UnsupportedVersion` (never plaintext) and shall change nothing; wrong password and wrong key give the same `Authentication`.
- **REQ-EXP-004** When an import contains an item ID that already exists in the target vault, the core shall return `Conflict` and import nothing (all or nothing).
- **REQ-EXP-005** The export file shall not contain the secret key, the vault key, any item key or the master password in any form.
- **REQ-EXP-007** When the export target is the vault file itself (compared after canonicalization, including through a symbolic link), `export` shall return `InvalidInput` and leave the vault untouched; the CLI shall exit 2.
- **REQ-EXP-006** When an export file exceeds the limits in CS §10 or declares an inconsistent `ct_len`, the core shall return `Corrupt` without allocating more than the file's own length.

## SEC — secrets and robustness (negative requirements)

- **REQ-SEC-001** The core shall zeroize on drop every type that holds key material, passwords, decrypted item fields or plaintext buffers, including the serialized item plaintext before encryption (a `Zeroizing<Vec<u8>>` with preallocated capacity); copies left by `serde_json` and `String`/`Vec` growth are a documented residual risk (architecture.md §4).
- **REQ-SEC-002** The core shall not implement `Debug`, `Display` or `Serialize` in a way that reveals key material or plaintext; the `Debug` output of every secret-holding type shall be a fixed redacted string.
- **REQ-SEC-003** The core shall not place passwords, keys, plaintext or item content in any error value, error message, log line or panic message.
- **REQ-SEC-004** When given malformed or hostile input (vault file, export file, item JSON, secret key text, TOTP secret, CLI arguments), the core and the CLI shall return an error and shall not panic, abort, loop forever or allocate memory proportional to an attacker-declared length.
- **REQ-SEC-005** The core shall not contain `unsafe` code, and every crate root shall carry `#![forbid(unsafe_code)]`.
- **REQ-SEC-006** The core shall not contain network code, telemetry or logging of secrets, and shall not read or write any file other than the paths the caller passes in (plus its own temporary file in the same directory).
- **REQ-SEC-007** The core shall not use any cryptographic primitive other than those in CS §2, and shall not use `rand`-style non-OS random sources for keys, nonces, salts, IDs or generated passwords.
- **REQ-SEC-008** The core shall not fall back to a weaker, older or alternative format, KDF or cipher in any error path.
- **REQ-SEC-009** The core shall compare nothing secret with `==` on plain byte slices; authenticity checks are performed only by the AEAD implementation.

## CLI — command-line tool

- **REQ-CLI-001** The CLI `onlypassword` shall provide the commands `init`, `add-login`, `add-note`, `get`, `list`, `search`, `update`, `delete`, `passwd`, `rotate-key`, `export`, `import`, `generate`, `totp` as specified in architecture.md.
- **REQ-CLI-002** The CLI shall read every password, TOTP secret, item secret, hidden custom-field value and item notes only from an interactive no-echo prompt or, with `--stdin`, from standard input lines in the documented order (or, for notes, from `--notes-file`), and shall never accept them as command-line arguments or environment variables; `--field NAME=VALUE` is accepted only for non-hidden fields.
- **REQ-CLI-003** When `init` runs, the CLI shall follow the order of architecture.md §5 (check paths, generate the key, write the key file exclusively with permissions 0600 and fsync, read it back, only then create the vault with `create_with_key`, and remove the key file again if vault creation fails), so that no vault exists without its key file; it shall never overwrite an existing key file or vault, print only the paths and a reminder, and not print the key unless `--print-secret-key` is given.
- **REQ-CLI-004** When a command fails, the CLI shall exit non-zero with a one-line message that contains no secret, and exit 0 on success; exit codes are 1 (error), 2 (usage), 3 (authentication failure).
- **REQ-CLI-005** When `get` prints an item, the CLI shall omit the password, notes, TOTP secret and hidden field values (printing `<hidden>`) unless `--show-secrets` is given.
- **REQ-CLI-007** The CLI shall let the user set every item attribute of the core's item model (title, username, URLs, notes, TOTP secret, algorithm, digits and period, non-hidden and hidden custom fields) on `add-login` and `update`, and clear them on `update`, with the flags and replace semantics of architecture.md §5.
- **REQ-CLI-008** `passwd --rotate` shall change the password and rotate the vault key in one atomic write; `import` shall take the secret key of the exporting vault via `--source-secret-key-file`.
- **REQ-CLI-006** The CLI shall not link any code beyond the core, the standard library, and the approved prompt crate, and shall keep no state outside the vault file and the key file.

## BLD — build discipline

- **REQ-BLD-001** The workspace shall pass `bash pipeline/gate.sh` with only the dependencies in `spec/approved-deps.txt`.
- **REQ-BLD-002** Known-answer tests shall load their vectors from `spec/vectors/*.json` at test time and shall not copy vector values into source files.
- **REQ-BLD-003** Tests shall not be deleted, weakened or ignored, and no real passwords, keys or personal data shall appear in the repository.

---

# Phase 2 — desktop application

"The desktop app" means the crate `onlypassword-desktop` (library `onlypassword_desktop`, binary
`onlypassword-desktop`); see architecture.md §7. Phase 2 adds requirements only; every REQ above
still holds, and the pilot's CLI is unchanged. "Headlessly" means: in a test that runs under
`cargo test` with no display, either against the state machine (`AppState::dispatch`/`tick`) or
through `egui_kittest` driving the views over the same state. A "fixed message" is a string
literal of the core's `Error` `Display` or of `UiError` (architecture.md §7.6); it never contains
a field value, a path or a key.

## IDX — core: item index for list views (phase-2 core addition)

- **REQ-IDX-001** The core shall provide `Vault::index()` returning an `ItemIndex` that holds the `ItemSummary` of every item, sorted exactly as `list()` (REQ-LIF-008), and `ItemIndex::search(query)` shall return exactly the summaries `Vault::search(query)` returns (REQ-LIF-009), in the same order, without decrypting any record.
- **REQ-IDX-002** The index shall be built when a vault is created or unlocked and shall be updated by `add`, `update`, `delete`, `import`, `change_master_password`, `rotate_vault_key` and `change_master_password_and_rotate_key`; after any sequence of operations `index().entries()` shall equal `list()`, and after a failed mutation the index shall be unchanged (REQ-LIF-012).
- **REQ-IDX-003** The index shall hold no password, notes, TOTP secret or custom-field value, shall implement `Debug` as a fixed redacted string, and shall zeroize its strings when the vault is locked or dropped (REQ-LIF-003).

## KFL — core: secret-key files and guided creation (phase-2 core addition)

- **REQ-KFL-001** The core shall provide `keyfile::read(path)` that reads at most 4 096 bytes (a larger file is `InvalidInput`, never fully read), trims ASCII whitespace at both ends and parses with `SecretKey::from_text` exactly as architecture.md §5 describes for the CLI, returning `InvalidInput` for malformed text and `Io` for I/O failures, with the file content held only in zeroizing buffers.
- **REQ-KFL-002** The core shall provide `keyfile::write_new(path, key)` that creates the file exclusively (an existing file or symlink at the path is `Io(AlreadyExists)` and left untouched), with permissions 0600 on Unix, writes the key text and a newline, calls `sync_all`, and removes the file again if any later step fails.
- **REQ-KFL-003** The core shall provide `Vault::create_with_key_file(vault_path, key_path, password, params)` that follows the order of architecture.md §5 *init order* (paths differ, neither exists, generate key, `write_new`, read back and compare through `keyfile::read`, `create_with_key`, remove the key file if vault creation fails), so that no vault exists without a key file that opens it and no existing file is overwritten.

## GUI — desktop application

### Opening and creating (brief scope 1)

- **REQ-GUI-001** When the user submits a vault path, a master password and a secret-key file path on the open screen, the app shall unlock the vault through `keyfile::read` and `Vault::unlock` and show the browse screen; the password buffer shall be emptied after every submission, successful or not.
- **REQ-GUI-002** When the user submits a new vault path, a new secret-key file path, a password and its confirmation on the create screen, the app shall call `Vault::create_with_key_file` with the app's KDF parameters (default `KdfParams::DEFAULT`), so the key file is new, 0600 on Unix and never overwrites; a mismatched confirmation shall be reported (`UiError::PasswordMismatch`) without touching the disk; the secret key text shall not be displayed.
- **REQ-GUI-003** When unlocking fails because the password or the secret key is wrong, the app shall show the single fixed message of `Error::Authentication`, identical for both causes, and shall stay on the unlock screen; an unreadable or malformed key file, a missing vault file and a corrupt vault shall show the core's other fixed messages and shall never be reported as "wrong password".

### Lock state (brief scope 2)

- **REQ-LOCK-001** When the user locks manually, the app shall lock the vault (`Vault::lock`), drop every key, plaintext, list row, draft and revealed value, and show only the unlock screen.
- **REQ-LOCK-002** When no user activity (keyboard, pointer or touch event) has occurred for the configured idle timeout (default 300 s), the app shall lock exactly as in REQ-LOCK-001 on its next `tick`, whichever screen or dialog is showing; any activity resets the timer.
- **REQ-LOCK-003** After a lock, `AppState::is_clean()` shall be true: no `Vault`, no `SecretKey`, no `SecretBuf` with content, no draft, no list rows or detail, no revealed-field set, no generated value, no pending clipboard value; and `format!("{:?}", state)` shall contain no value that was on screen before the lock.
- **REQ-LOCK-004** Locking shall succeed regardless of the state of the clipboard service, of an open draft with unsaved changes (discarded without prompt, zeroized) or of an open dialog or maintenance form; a lock while already locked shall do nothing.
- **REQ-LOCK-005** When the clock jumps or a blocking native file dialog returns after more than the idle timeout has elapsed since the last activity, the first `tick` afterwards shall lock the vault before any further action is processed.
- **REQ-LOCK-006** The idle timer shall use a monotonic clock supplied through the `UiClock` trait so that tests can advance it without sleeping; the idle timeout shall be changeable at run time (REQ-CFG-008).

### Browsing (brief scope 3)

- **REQ-GUI-010** The browse screen shall list every item from `Vault::index()` in the core's order, each row showing kind, title and username only.
- **REQ-GUI-011** When the search text changes, the list shall update immediately to `ItemIndex::search(text)` (title, username and URL, case-insensitive substring); an empty text shows all items; the search text itself is not a secret and is cleared on lock.
- **REQ-GUI-012** Selecting a row shall show a detail view with every field of the item: for a login, title, username, password, URLs, notes, TOTP (REQ-GUI-040) and all custom fields with their names and hidden flags; for a secure note, title and notes. The detail data shall be loaded with `Vault::get`, held in the core's secret types, and dropped when another item is selected, the item is edited, or the app locks.

### Editing (brief scope 4)

- **REQ-GUI-020** The app shall add a login or a secure note, and edit an existing item, through a draft that offers every attribute of the core's `Item` (title, username, password, URLs, notes, TOTP secret with algorithm, digits and period, custom fields with a hidden flag); saving shall call `Vault::add` or `Vault::update`, then return to the detail view of that item.
- **REQ-GUI-021** When the core rejects a draft (`InvalidInput`, `LimitExceeded`, `Io`, …) the app shall show the core's fixed message, keep the draft and leave the vault unchanged (REQ-LIF-012); the TOTP secret typed by the user shall be passed through `normalize_totp_secret` before saving, and a failure there shall be shown as the core's `InvalidInput` message.
- **REQ-GUI-022** When the user chooses delete, the app shall ask for confirmation naming only the item's title, delete (`Vault::delete`) only after an explicit confirm action, and leave the item untouched on cancel, on lock or when the selection changes.
- **REQ-GUI-023** When the user cancels an edit, or navigates away, the draft shall be dropped (zeroized) without saving; a note draft shall not offer, and shall not submit, login-only fields.

### Secrets on screen and clipboard (brief scope 5)

- **REQ-GUI-030** Passwords, notes, TOTP secrets and hidden custom-field values shall be masked by default in the detail view and in edit forms; the masked rendering shall consist of a fixed placeholder that does not reveal the value's length or content, and no accessibility label, widget text or `Debug` output of the rendered views shall contain the value.
- **REQ-GUI-031** The user shall be able to reveal one field at a time on request (a per-field toggle); revealing one field shall not reveal any other.
- **REQ-GUI-032** Revealed fields shall be re-masked when the app locks, when another item is selected, when the item is left for edit and when the user toggles the field again.
- **REQ-GUI-033** Secret text in forms (master password, export password, secret fields of a draft) shall be edited in `SecretBuf` buffers that are cleared and zeroized when the form is submitted, cancelled or the app locks, and that are masked while edited unless the user reveals them.
- **REQ-CLIP-001** When the user copies a field, the app shall place its text on the clipboard through the `ClipboardBackend`, marking it as sensitive where the platform supports it, and shall remember only a SHA-256 digest of the copied text and the time, never the text.
- **REQ-CLIP-002** When the clipboard timeout (default 30 s) has elapsed since the copy and the clipboard still holds text whose digest equals the remembered digest, the service shall clear the clipboard; if the clipboard holds anything else, the service shall leave it untouched and forget the pending clear.
- **REQ-CLIP-003** A second copy shall replace the pending digest and restart the timeout; the clipboard timeout shall be changeable at run time (REQ-CFG-008).
- **REQ-CLIP-004** When the app locks or its window closes, the service shall perform the pending clear immediately under the same "still holds our value" rule and then drop the digest.
- **REQ-CLIP-005** When the clipboard backend fails, the app shall show the fixed `UiError::Clipboard` message, hold no pending clear for a copy that did not happen, and remain usable; the copied value shall not appear in any message.
- **REQ-CLIP-006** The service shall perform no clipboard read except for the comparison of REQ-CLIP-002/-004, and the copied text shall exist in the app only as the transient argument of the backend call.

### TOTP (brief scope 6)

- **REQ-GUI-040** For a login with a TOTP configuration the detail view shall show the current code computed by `totp_for_item` with the Unix time from `UiClock`, and the whole seconds remaining in the current period (`period − (t mod period)`, between 1 and `period`), and shall show the next code once the period rolls over, without user action.
- **REQ-GUI-041** When the stored TOTP parameters are invalid, the view shall show the core's fixed message in place of the code and shall not panic; the code and countdown shall not be computed for items without TOTP and shall be dropped when the item is left or the app locks.

### Generator (brief scope 7)

- **REQ-GUI-050** The generator panel shall expose every option of `PasswordOptions` and `PassphraseOptions`, produce values only through `generate_password` / `generate_passphrase`, show the core's fixed `InvalidInput` message for invalid options, and keep the generated value in a `SecretString` that is dropped on discard, on use or on lock.
- **REQ-GUI-051** When the user chooses "use this" while editing an item, the generated password shall be placed in the draft's password field (replacing it) and the panel's copy dropped; with no draft open the action shall be unavailable; the generated value can also be copied through the clipboard service.

### Maintenance (brief scope 8)

- **REQ-GUI-060** Change master password: the app shall ask for the current password, the new password and its confirmation (with a "also rotate the vault key" choice, on by default) and call `change_master_password_and_rotate_key` or `change_master_password`; a mismatching confirmation is `UiError::PasswordMismatch` without calling the core; a wrong current password is the single `Authentication` message; a new password under 8 scalar values is the core's `InvalidInput`; after success the old password shall no longer unlock (REQ-LIF-010) and the vault stays unlocked.
- **REQ-GUI-061** Rotate vault key: the app shall ask for confirmation, call `rotate_vault_key`, and afterwards every item shall read back unchanged.
- **REQ-GUI-062** Export: the app shall ask for a target path, an export password and its confirmation, and call `Vault::export` with the unlocked vault's own secret key; a target equal to the vault file shall produce the core's `InvalidInput` message and leave the vault untouched; the export password buffers shall be zeroized after the call.
- **REQ-GUI-063** Import: the app shall ask for an export file, an export password and the secret-key file of the vault the export came from, call `Vault::import`, and report the number of imported items on success; an `Authentication` or `Corrupt` failure changes nothing, a `Conflict` is reported with its fixed message, and the item list shall reflect the vault after the call.
- **REQ-GUI-064** Every path used in the maintenance screens shall be passed to the core exactly as chosen (no canonicalization or symlink resolution by the app; REQ-FMT-009 and REQ-EXP-007 apply), and key files read for import shall be read only through `keyfile::read`.

### Settings (brief scope 9)

- **REQ-CFG-001** The app shall store its settings in a file `config.json` in the operating system's per-user configuration directory for the application (`directories::ProjectDirs`, qualifier `""`, organization `""`, application `onlypassword`), created with permissions 0600 on Unix; the store takes the directory as an argument so tests use a temporary one.
- **REQ-CFG-002** The config file shall be JSON with exactly the keys `version` (1), `idle_timeout_secs` (default 300), `clipboard_clear_secs` (default 30), `theme` (`"system"` default, `"light"`, `"dark"`) and `last_vault_path` (string or null); no other key shall be written, and no secret, key-file path, password, item data or vault content shall ever be written.
- **REQ-CFG-003** On load, a missing file shall yield the defaults; a file that is unreadable, larger than 4 096 bytes, not valid UTF-8 or JSON, has an unknown key, a wrong type, `version` other than 1, `idle_timeout_secs` outside 10..=86 400 or `clipboard_clear_secs` outside 5..=600 shall yield the defaults and the fixed notice `UiError::ConfigInvalid`, shall not panic, and shall not rewrite the file until the user saves settings.
- **REQ-CFG-004** Saving shall write atomically (temporary file in the same directory, `sync_all`, rename), reject out-of-range values with `UiError::InvalidSetting` before writing, and on failure leave the old file unchanged and report `UiError::ConfigWrite`; a failure to read or write the config shall never prevent the app from running.
- **REQ-CFG-005** After a successful unlock or create, `last_vault_path` shall be set to the vault path and saved; the open and unlock screens shall prefill that path; no other path (in particular, never the key-file path) is stored.
- **REQ-CFG-006** The theme setting shall select the egui visuals (light, dark, or the system's preference where eframe reports it, light when it does not) and shall apply to the next frame.
- **REQ-CFG-007** The settings screen shall edit the idle timeout, the clipboard timeout and the theme, validate on save (REQ-CFG-004) and show the fixed message on invalid input; it is available on the unlock screen and when unlocked.
- **REQ-CFG-008** When settings are saved, the idle timer and the clipboard service shall use the new values immediately, without restart (a pending clipboard clear keeps its original deadline).

### Non-negotiables of the desktop app

- **REQ-GUI-070** The desktop crate shall not log, print or format any field value, password, key or note: it shall contain no `println!`, `eprintln!`, `print!`, `dbg!`, `log::` or `tracing::` invocation, and every type holding secrets or plaintext shall implement `Debug` as a fixed redacted string (REQ-SEC-002 applies).
- **REQ-GUI-071** The desktop app shall not use the network: it shall not use `std::net`, shall not depend on any HTTP, TLS, socket or telemetry crate (a test checks the desktop crate's sources and `Cargo.lock` against a denylist), and shall contain no update check, telemetry or crash reporting.
- **REQ-GUI-072** The desktop app shall hold key material and plaintext only in the core's secret types and `SecretBuf` (REQ-GUI-033), shall not convert them to plain `String`/`Vec<u8>` except for the transient arguments of egui text editing and of the clipboard call, and shall never write them to the config file or any file other than through core functions.
- **REQ-GUI-073** The desktop crate shall carry `#![forbid(unsafe_code)]` in its library and binary roots and the panic-free `cfg_attr` lints of architecture.md §1; messages shown to the user shall be exactly the core's fixed messages or the fixed `UiError` messages (architecture.md §7.6), and no message shall contain a path, a field value or a key.
- **REQ-GUI-074** Platform-specific code shall be gated with `cfg(target_os = …)` / `cfg(unix)` / `cfg(windows)` so that the crate passes `cargo check --workspace --all-targets --all-features` for `x86_64-pc-windows-msvc` and `aarch64-apple-darwin` (gate step), and the Linux code path shall be covered by the headless tests; the desktop crate shall not enable the core's `insecure-fast-kdf` or `test-hooks` features outside `[dev-dependencies]`.
- **REQ-GUI-075** Every screen's main flows shall have headless tests (no window, no display, no network, no real clock sleeping): the state machine through `dispatch`/`tick`, and the views through `egui_kittest`; `eframe::run_native` shall be called only from `main.rs`.
- **REQ-GUI-076** The pilot's CLI and core behaviour shall be unchanged: the pilot tests (including `onlypassword-cli/tests/e2e.rs`) shall keep passing, and phase 2 shall add to the core only the APIs of REQ-IDX-* and REQ-KFL-*.
- **REQ-GUI-077** The end-to-end scenario of F037 (create, add login with TOTP and custom fields and a note, lock, unlock, read back, change master password, export, import into a fresh vault, no plaintext after lock) shall run headlessly under the gate with the real default KDF parameters for the create and unlock steps it contains.
