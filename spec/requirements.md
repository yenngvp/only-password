# Requirements

"The core" means the library crate `onlypassword-core`; "the CLI" means the binary crate
`onlypassword-cli`. Byte-level details are in `crypto-spec.md` (cited as CS §n). Every
requirement is testable; `features.json` maps each one to a feature that tests it.

## KEY — unlock keys

- **REQ-KEY-001** When a vault is created, the core shall generate a 256-bit secret key from the operating system's random source and return it to the caller, and shall not write it to the vault file.
- **REQ-KEY-002** When a vault is unlocked, the core shall derive the master key from the NFKC-normalized master password with Argon2id (parameters read from the authenticated header) and combine it with the secret key through HKDF-SHA-256 exactly as in CS §3.3.
- **REQ-KEY-003** When a vault is created or its master password is changed without explicit parameters, the core shall use Argon2id m = 65 536 KiB, t = 3, p = 4 (CS §10), and shall never default to a memory cost above 64 MiB.
- **REQ-KEY-004** When asked to create or accept Argon2id parameters outside the bounds of CS §10, the core shall return an error before running Argon2id.
- **REQ-KEY-005** When the password or the secret key is wrong, the core shall return the single error `Authentication`, without indicating which of the two was wrong.
- **REQ-KEY-006** When a secret key is formatted or parsed in text form, the core shall use the `OPSK1-` encoding of CS §3.2, and shall return `InvalidInput` for a wrong prefix, wrong length, invalid character or non-zero trailing bits.
- **REQ-KEY-007** When a master password or export password shorter than 8 Unicode scalar values after normalization is supplied for creating a vault, changing the password or exporting, the core shall return `InvalidInput`.
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
- **REQ-FMT-002** When a vault or export file has a format version, item schema, export schema, KDF id or KDF version other than the one supported (smaller or larger), the core shall return `UnsupportedVersion` or `Corrupt` as specified in CS §9, and shall not attempt to read, convert or re-save it.
- **REQ-FMT-003** When a vault file is truncated, has trailing bytes, has non-zero flags, has out-of-bound lengths or counts, or has unsorted or duplicate record IDs, the core shall return `Corrupt` without panicking and without allocating more than the file's own length.
- **REQ-FMT-004** When the core saves a vault, it shall write a temporary file in the same directory, flush and fsync it, rename it over the target, and fsync the directory where the platform supports it, so that a failure at any point leaves either the complete old file or the complete new file.
- **REQ-FMT-005** When a vault file is created on a Unix platform, the core shall create it with permissions 0600.
- **REQ-FMT-006** When a save fails, the core shall remove its temporary file, leave the target file unchanged, and return `Io`.
- **REQ-FMT-007** The core shall check magic and version before interpreting any other header field (CS §9 order).

## ITM — item model

- **REQ-ITM-001** The core shall represent a login item with title, username, password, a list of URLs, notes, an optional TOTP secret with algorithm, digits and period, and custom fields (name, value, hidden flag).
- **REQ-ITM-002** The core shall represent a secure note item with title and notes, and shall reject a note carrying username, password, URLs or TOTP.
- **REQ-ITM-003** The core shall store `created_ms` and `updated_ms` timestamps; when an item is added both are set to the current time, and when it is updated `created_ms` is kept and `updated_ms` is set to the current time (never earlier than `created_ms`).
- **REQ-ITM-004** The core shall serialize items as the versioned JSON of CS §7 and, when deserializing, shall reject unknown fields, duplicate keys, missing fields, wrong types, values over the limits of CS §7, and `schema` values other than 1.
- **REQ-ITM-005** When an item is added, the core shall assign it a random 128-bit ID (shown as 32 lowercase hex characters) that is unique in the vault.
- **REQ-ITM-006** When an item violates a limit in CS §7 (sizes, counts, kind rules, TOTP parameters), the core shall return `InvalidInput` and leave the vault unchanged.

## LIF — lifecycle

- **REQ-LIF-001** When `create` is called, the core shall write a new, empty, valid vault file and return an unlocked vault and the new secret key; if the target path already exists, it shall return an error and leave the existing file untouched.
- **REQ-LIF-002** When `unlock` is called with the correct password and secret key, the core shall return an unlocked vault from which all items can be read.
- **REQ-LIF-003** When a vault is locked or dropped, the core shall zeroize the vault key, subkeys and any decrypted item contents it holds; a locked vault is not representable as a usable value.
- **REQ-LIF-004** When `add` is called with a valid item, the core shall persist it atomically and return its new ID, with revision 1.
- **REQ-LIF-005** When `get` is called with an existing ID, the core shall return the decrypted item with its ID and revision; for an unknown ID it shall return `NotFound`.
- **REQ-LIF-006** When `update` is called for an existing ID, the core shall replace the item with a new revision (revision + 1, fresh item key and nonces), persist atomically, and keep the ID and `created_ms`; for an unknown ID it shall return `NotFound`.
- **REQ-LIF-007** When `delete` is called for an existing ID, the core shall remove the record, persist atomically, and afterwards `get` for that ID shall return `NotFound`.
- **REQ-LIF-008** When `list` is called, the core shall return summaries (ID, kind, title, username, `updated_ms`, revision) sorted by title (case-insensitive, then ID), and the summaries shall not contain passwords, notes, TOTP secrets or hidden field values.
- **REQ-LIF-009** When `search` is called with a query, the core shall return the summaries whose title, username or any URL contains the query as a case-insensitive substring, and shall not search passwords, notes, TOTP secrets or custom fields.
- **REQ-LIF-010** When `change_master_password` is called, the core shall verify the current password, re-wrap the same vault key under a master key derived from a new random salt and the new password (same secret key), leave all item records byte-identical, persist atomically, and afterwards the old password shall fail with `Authentication`.
- **REQ-LIF-011** When `rotate_vault_key` is called, the core shall generate a new vault key, re-encrypt every item under a fresh item key and fresh nonces with unchanged revisions and contents, re-wrap and persist atomically, and afterwards no old item key or old ciphertext shall validate against the new file.
- **REQ-LIF-012** When any mutating operation fails (including on I/O error), the on-disk file and the in-memory vault shall be unchanged.
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

- **REQ-EXP-001** When an export is requested with an export password, the core shall write an export file in the format of CS §8 containing every item of the unlocked vault, atomically (REQ-FMT-004).
- **REQ-EXP-002** When an export file is imported into an unlocked vault with the correct export password, the core shall add every item under its original ID, revision and content, and an export of vault A imported into a fresh vault B shall make B's `list` and every `get` equal A's.
- **REQ-EXP-003** When the export password is wrong or any byte of the export file is changed, import shall fail with `Authentication`, `Corrupt` or `UnsupportedVersion` and shall change nothing.
- **REQ-EXP-004** When an import contains an item ID that already exists in the target vault, the core shall return `Conflict` and import nothing (all or nothing).
- **REQ-EXP-005** The export file shall not contain the secret key, the vault key, any item key or the master password in any form.
- **REQ-EXP-006** When an export file exceeds the limits in CS §10 or declares an inconsistent `ct_len`, the core shall return `Corrupt` without allocating more than the file's own length.

## SEC — secrets and robustness (negative requirements)

- **REQ-SEC-001** The core shall zeroize on drop every type that holds key material, passwords, decrypted item fields or plaintext buffers.
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
- **REQ-CLI-002** The CLI shall read every password, TOTP secret and item secret only from an interactive no-echo prompt or, with `--stdin`, from standard input lines in the documented order, and shall never accept them as command-line arguments or environment variables.
- **REQ-CLI-003** When `init` runs, the CLI shall write the secret key text to the file given by `--secret-key-file` with permissions 0600 (created exclusively, never overwritten), print only the path and a reminder, and not print the key unless `--print-secret-key` is given.
- **REQ-CLI-004** When a command fails, the CLI shall exit non-zero with a one-line message that contains no secret, and exit 0 on success; exit codes are 1 (error), 2 (usage), 3 (authentication failure).
- **REQ-CLI-005** When `get` prints an item, the CLI shall omit the password, TOTP secret and hidden field values unless `--show-secrets` is given.
- **REQ-CLI-006** The CLI shall not link any code beyond the core, the standard library, and the approved prompt crate, and shall keep no state outside the vault file and the key file.

## BLD — build discipline

- **REQ-BLD-001** The workspace shall pass `bash pipeline/gate.sh` with only the dependencies in `spec/approved-deps.txt`.
- **REQ-BLD-002** Known-answer tests shall load their vectors from `spec/vectors/*.json` at test time and shall not copy vector values into source files.
- **REQ-BLD-003** Tests shall not be deleted, weakened or ignored, and no real passwords, keys or personal data shall appear in the repository.
