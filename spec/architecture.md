# Architecture

## 1. Workspace

```
Cargo.toml                      virtual workspace, resolver = "2", members = ["crates/*"]
Cargo.lock                      committed
crates/onlypassword-core/       library  (lib name: onlypassword_core)
crates/onlypassword-cli/        binary   (bin name: onlypassword)
```

Both crates set `publish = false`, `edition = "2021"`, carry `#![forbid(unsafe_code)]`
in `lib.rs` / `main.rs`, and `#![deny(missing_debug_implementations)]` is **not** used
(secret types implement `Debug` by hand, see §4). Panic-free parsing is enforced with
`#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing))]`
in each crate root (not in `[workspace.lints]`, which would also hit tests under the gate's
`clippy --all-targets`). The core has the non-default cargo features `insecure-fast-kdf`
and `test-hooks` (CS §10, §2 below); the CLI crate never enables either. Only the CLI depends on `rpassword`; the core has no I/O
dependency beyond `std`.

### Core modules (`crates/onlypassword-core/src/`)

| module | content |
|---|---|
| `error` | `Error`, `Result` |
| `secret` | `SecretBytes<const N>` / `SecretVec`, `SecretString` (zeroize-on-drop, redacted `Debug`) |
| `rng` | `fill_random`, `random_array::<N>()`, `uniform(n)`; trait `RandomSource` (internal, for stubbing in tests) |
| `base32` | RFC 4648 encode/decode (no padding on encode, tolerant decode); `parse_totp_secret`, `normalize_totp_secret` (CS §7); a small hex codec for IDs (no `hex` crate) |
| `crypto` | `aead` (XChaCha20-Poly1305 wrappers), `kdf` (`KdfParams`, Argon2id), `hkdf` helpers, `keys` (`SecretKey`, `MasterKey`, `VaultKey`, `ItemKey`, subkeys) |
| `item` | `Item`, `ItemKind`, `Totp*`, `CustomField`, JSON (de)serialization and validation (CS §7) |
| `format` | pure byte codec for the vault file (CS §5): `VaultFile`, `Header`, `Record`; no keys, no I/O |
| `seal` | uses `crypto` + `format`: wrap/unwrap VK, seal/open records, trailer (CS §6) |
| `storage` | `write_atomic` (save), `create_new_atomic` (temp + `hard_link`), symlink resolution, permissions, bounded file read |
| `vault` | `Vault` lifecycle and item operations |
| `export` | export/import (CS §8) |
| `generator` | password and passphrase generation |
| `totp` | HOTP/TOTP |

Dependencies flow downward in that order; `format` knows nothing about keys and `crypto`
knows nothing about files.

## 2. Public API sketch (types and signatures; no bodies)

The crate root re-exports exactly these names; everything else is `pub(crate)`.

```rust
pub const FORMAT_VERSION: u16 = 1;

// ---- error ----
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    Authentication,                 // wrong password/secret key, or failed AEAD tag
    Corrupt(&'static str),          // structurally invalid input; static text only
    UnsupportedVersion,             // version/kdf id/schema we do not read (smaller or larger)
    InvalidInput(&'static str),     // caller-supplied value outside limits
    NotFound,
    Conflict,
    LimitExceeded,
    Rng,
    Io(std::io::ErrorKind),         // kind only, never a path or message
}
impl std::fmt::Display for Error { /* fixed strings */ }
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

// ---- secrets ----
pub struct SecretString(/* Zeroizing<String> */);   // Debug => SecretString(<redacted>)
impl SecretString { pub fn new(s: String) -> Self; pub fn expose(&self) -> &str; }
pub struct SecretKey(/* [u8;32], ZeroizeOnDrop */);
impl SecretKey {
    pub fn generate() -> Result<Self>;
    pub fn to_text(&self) -> SecretString;                 // "OPSK1-XXXX-…" (CS §3.2)
    pub fn from_text(s: &str) -> Result<Self>;
}

// ---- KDF parameters ----   (CS §10)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams { pub m_kib: u32, pub t: u32, pub p: u32 }
impl KdfParams {
    pub const DEFAULT: KdfParams = KdfParams { m_kib: 65_536, t: 3, p: 4 };
    pub const MIN: KdfParams = KdfParams { m_kib: 19_456, t: 2, p: 1 };  // real floor
    #[cfg(any(test, feature = "insecure-fast-kdf"))]
    pub const FAST_FOR_TESTS: KdfParams = KdfParams { m_kib: 8_192, t: 1, p: 1 };
    pub fn validate(&self) -> Result<()>;         // floor lowered to FAST_FOR_TESTS only under that cfg
    pub fn validate_strict(&self) -> Result<()>;  // always the real floor and ceiling
}

// ---- items ----
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum ItemKind { Login, Note }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum TotpAlgorithm { Sha1, Sha256, Sha512 }

pub struct TotpConfig { pub secret: SecretString /* canonical base32, CS §7 */,
                        pub algorithm: TotpAlgorithm, pub digits: u8, pub period: u32 }
pub struct CustomField { pub name: String, pub value: SecretString, pub hidden: bool }
pub struct Item {
    pub kind: ItemKind, pub title: String,
    pub username: Option<String>, pub password: Option<SecretString>,
    pub urls: Vec<String>, pub notes: SecretString,
    pub totp: Option<TotpConfig>, pub fields: Vec<CustomField>,
}
impl Item {
    pub fn new_login(title: impl Into<String>) -> Item;
    pub fn new_note(title: impl Into<String>, notes: SecretString) -> Item;
    pub fn validate(&self) -> Result<()>;                                // CS §7 limits, canonical TOTP secret
}
// Item/TotpConfig/CustomField implement Debug with redaction and ZeroizeOnDrop.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemId(pub [u8; 16]);     // Display/FromStr as 32 lowercase hex chars
pub struct StoredItem { pub id: ItemId, pub revision: u64, pub created_ms: u64,
                        pub updated_ms: u64, pub item: Item }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSummary { pub id: ItemId, pub kind: ItemKind, pub title: String,
                         pub username: Option<String>, pub revision: u64, pub updated_ms: u64 }

// ---- vault ----
pub trait Clock { fn now_ms(&self) -> u64; }
pub struct SystemClock;                                   // default
pub const MAX_ITEMS: usize = 100_000;                     // CS §10
pub struct Vault { /* path, parsed file, VK, K_iw, K_fa, clock; ZeroizeOnDrop */ }
impl std::fmt::Debug for Vault { /* redacted */ }

impl Vault {
    /// Generates a secret key, then `create_with_key`. For callers that can persist the key
    /// only after seeing it; the CLI uses `create_with_key` (see §5 `init`).
    pub fn create(path: &Path, password: &SecretString, params: KdfParams)
        -> Result<(Vault, SecretKey)>;
    /// Writes a new empty vault with the caller's key via `storage::create_new_atomic`
    /// (CS §6.6); fails with `Io` if `path` exists; never replaces an existing file.
    pub fn create_with_key(path: &Path, password: &SecretString, params: KdfParams,
                           key: &SecretKey) -> Result<Vault>;
    pub fn unlock(path: &Path, password: &SecretString, key: &SecretKey) -> Result<Vault>;
    pub fn lock(self);                                    // consumes; zeroizes
    pub fn kdf_params(&self) -> KdfParams;                // so a UI can warn on weak vaults
    #[doc(hidden)] #[cfg(any(test, feature = "test-hooks"))]
    pub fn set_clock(&mut self, clock: Box<dyn Clock>);   // tests only; not in default builds

    pub fn add(&mut self, item: Item) -> Result<ItemId>;
    pub fn get(&self, id: &ItemId) -> Result<StoredItem>;
    /// `NotFound`; `LimitExceeded` if the stored revision is `u64::MAX` or a size limit is hit.
    pub fn update(&mut self, id: &ItemId, item: Item) -> Result<u64 /* new revision */>;
    pub fn delete(&mut self, id: &ItemId) -> Result<()>;
    pub fn list(&self) -> Result<Vec<ItemSummary>>;
    pub fn search(&self, query: &str) -> Result<Vec<ItemSummary>>;

    pub fn change_master_password(&mut self, current: &SecretString, new: &SecretString,
                                  key: &SecretKey, params: KdfParams) -> Result<()>;
    pub fn rotate_vault_key(&mut self) -> Result<()>;
    /// Both in one atomic write: new VK, new salt, new MK (CS §6.5). CLI `passwd --rotate`.
    pub fn change_master_password_and_rotate_key(&mut self, current: &SecretString,
        new: &SecretString, key: &SecretKey, params: KdfParams) -> Result<()>;

    /// `key` is the vault's own secret key (CS §8). Rejects a target equal to the vault file.
    pub fn export(&self, path: &Path, export_password: &SecretString, key: &SecretKey,
                  params: KdfParams) -> Result<()>;
    /// `source_key` is the secret key of the vault the export was made from (not
    /// necessarily this vault's). Returns the number of items imported.
    pub fn import(&mut self, path: &Path, export_password: &SecretString,
                  source_key: &SecretKey) -> Result<usize>;
}

// ---- generator ----
pub struct PasswordOptions { pub length: usize, pub lower: bool, pub upper: bool,
    pub digits: bool, pub symbols: bool, pub exclude_ambiguous: bool, pub require_each: bool }
impl Default for PasswordOptions { /* 20, all classes on, ambiguous kept, require_each = true */ }
pub struct PassphraseOptions { pub words: usize, pub separator: String,
                               pub capitalize: bool, pub include_digit: bool }
impl Default for PassphraseOptions { /* 7, "-", false, false */ }
pub fn generate_password(o: &PasswordOptions) -> Result<SecretString>;
pub fn generate_passphrase(o: &PassphraseOptions) -> Result<SecretString>;
// pub(crate), used by unit tests to inject a deterministic RandomSource (no public equivalent):
// fn generate_password_with(r: &mut dyn RandomSource, o: &PasswordOptions) -> Result<SecretString>;
// fn generate_passphrase_with(r: &mut dyn RandomSource, o: &PassphraseOptions) -> Result<SecretString>;

// ---- totp ----
pub fn hotp(secret: &[u8], counter: u64, alg: TotpAlgorithm, digits: u8) -> Result<String>;
pub fn totp(secret: &[u8], unix_secs: u64, period: u32, alg: TotpAlgorithm, digits: u8) -> Result<String>;
pub fn totp_for_item(cfg: &TotpConfig, unix_secs: u64) -> Result<String>;   // parses base32, validates
pub fn parse_totp_secret(text: &str) -> Result<SecretVec>;        // tolerant input, 10..=128 bytes
pub fn normalize_totp_secret(text: &str) -> Result<SecretString>; // canonical stored form (CS §7)
```

`Vault` is *the* unlocked state: there is no locked `Vault` value. `change_master_password`
takes `key` because the new master key needs the secret key; it verifies `current` by
re-deriving and comparing through AEAD unwrap of `wrapped_vk` (never by `==`). `Vault`
holds the parsed file in memory (encrypted records) and decrypts items on demand; every
mutation builds the new complete file image, checks the limits of CS §10 (`LimitExceeded`
before writing), writes it with `storage::write_atomic`, and only then replaces the in-memory
image (REQ-LIF-012). `create_with_key` writes with `storage::create_new_atomic`; its unit
tests use a `pub(crate)` hook between the temporary write and the `hard_link` to create the
target in the gap (the call must fail and leave that file untouched) and to simulate a crash
before the link (no vault at the target).

**Ordering rules.** `list` sorts by `title.to_lowercase()` (Rust `str::to_lowercase`, full
Unicode lowercase) compared byte-wise, then by ID bytes. `search` lower-cases both query and
fields with the same function and tests `contains`. Non-ASCII behaviour is tested (e.g. `İ`,
`Σ`).

`Vault::import` does the whole import against a copy of the record list and writes once.

### Password generator definitions

- Symbols: the 24 characters `!@#$%^&*()-_=+[]{};:,.?/`; lowercase `a-z`; uppercase `A-Z`;
  digits `0-9`. `exclude_ambiguous` removes `0 O o 1 l I` from every class.
- Password algorithm: for each enabled class with `require_each`, pick one character
  uniformly from that class; fill the rest uniformly from the union of enabled classes;
  Fisher–Yates shuffle using `uniform`. Without `require_each`, all characters come from the
  union.
- `uniform(n: u64) -> Result<u64>` (n > 0): `let t = n.wrapping_neg() % n;` loop: draw a
  random `u64` `x` from the OS; if `x >= t` return `x % n`. (Rejects exactly `2^64 mod n`
  values; the rest is a multiple of `n`.) The draw goes through `RandomSource` so tests can
  inject a deterministic stream.
- `uniform` assembles each `u64` from 8 OS bytes with `u64::from_be_bytes`. Capitalize means ASCII-upper-casing the first byte of each word.
- Passphrase words: `bip39::Language::English.word_list()` (2 048 words, 11 bits/word,
  7 words ≈ 77 bits). `include_digit` appends one digit (uniform 0–9) to one uniformly
  chosen word. The list is a crate constant, not a file the core reads. Use `bip39` without its `rand` feature and with the fewest features that expose `Language::English.word_list()`; the builder records the chosen feature set in `agent-notes/`.

## 3. Error model

- One `Error` enum (above). Variants carry **only** `&'static str` or `io::ErrorKind`.
  No `String`, no path, no byte value, no secret ever enters an error (REQ-SEC-003).
- `Authentication` is returned for: wrong password, wrong secret key, tampered header
  (`wrapped_vk` tag), failed trailer tag, failed record tag, failed export tag. These are
  deliberately indistinguishable.
- `Corrupt` for structure that fails before any key is involved (bad magic, `flags`, KDF
  bounds, lengths, ordering, trailing bytes) and for JSON that does not parse or violates the
  schema after successful authentication.
- `UnsupportedVersion` for `format_version`, `kdf_id`, `kdf_version` ≠ the supported value, and
  for JSON `schema` / `export_schema` ≠ 1 (read before anything else in the JSON). The exact,
  ordered table for vault files and export files is crypto-spec.md §9; it is the authority.
- Parsers use checked slicing (`get(..)`, `split_at_checked`, a bounds-checked reader
  struct) and checked arithmetic; no `unwrap`/`expect`/indexing on untrusted data.
- The CLI maps errors to exit codes (REQ-CLI-004): `Authentication` → 3, usage problems →
  2, everything else → 1, printing e.g. `error: authentication failed`.

## 4. Rules for handling secrets in code

1. Key material and plaintext live only in types that derive/implement `Zeroize` +
   `ZeroizeOnDrop` (`Zeroizing<…>`, `SecretString`, `SecretKey`, key newtypes). Decrypted
   buffers are `Zeroizing<Vec<u8>>`.
2. Secret types implement `Debug` manually, printing a constant such as
   `SecretKey(<redacted>)`; they implement neither `Display` nor `Serialize`, nor `Clone`
   unless a feature needs it (clones are themselves zeroizing types).
3. No secret in `format!`/`println!`/`panic!`/`assert!` messages in non-test code. Tests may
   assert on secret equality only through `expose()` and must not print on failure
   (use `assert!(a == b)`, not `assert_eq!`, for secret values).
4. Secrets are never `Clone`d into plain `String`/`Vec<u8>` that outlive the call; any
   intermediate plain buffer is wrapped in `Zeroizing` immediately.
5. `serde_json` parsing and serialization, `String` growth (`push`, `reserve`) and `Vec`
   reallocation can leave copies of plaintext in freed memory that this design cannot
   zeroize; this is a known, accepted limit (threat-model.md, residual risks). Mitigations:
   parse from a `Zeroizing<Vec<u8>>`; serialize into a `Zeroizing<Vec<u8>>` created with
   `with_capacity` (the size is known from the item); build secret strings with
   `String::with_capacity`; copy fields into `SecretString` at once and drop intermediates
   promptly.
6. Keys are passed by reference; key newtypes are not `Copy`.
7. No secret-dependent branching other than the AEAD tag check performed by the
   `chacha20poly1305` crate; no hand-written comparison of secret bytes.
8. `Item` fields that are not secrets (title, username, URLs, field names) are plain
   `String`; the password, notes, TOTP secret and custom field *values* are `SecretString`.

## 5. CLI (`onlypassword`)

Global options (before the command): `--vault <PATH>` (required except for `generate`),
`--secret-key-file <PATH>` (required except for `generate`), `--stdin` (read prompts from
stdin lines). Argument parsing is hand-written (no `clap`); unknown flags are usage errors.
Nothing secret is ever an argument: a flag that would carry a secret is a *prompt switch*
and the value is read as a prompt (below). `--field NAME=VALUE` carries a **non-hidden**
custom field, whose value is by definition not secret; hidden values are prompted.

### Item flags (shared by `add-login`, `add-note` and `update`)

| flag | meaning |
|---|---|
| `--title T`, `--username U`, `--url U` (repeatable) | plain item metadata |
| `--notes` | prompt switch: read the notes as one prompt line |
| `--notes-file <PATH>` | read the notes from a UTF-8 file (≤ 65 536 bytes); mutually exclusive with `--notes` |
| `--generate` (`add-login`) | generate a password with the default options instead of prompting; it is printed only if `--show-secrets` is also given, otherwise it is readable later with `get --show-secrets` |
| `--new-password` (`update`) | prompt switch for the item password |
| `--totp` | prompt switch for the TOTP secret (stored through `normalize_totp_secret`) |
| `--totp-algorithm sha1\|sha256\|sha512` | default `sha1`; only valid together with `--totp` (else usage error) |
| `--totp-digits N` | 6..=8, default 6; only with `--totp` |
| `--totp-period N` | 1..=300, default 30; only with `--totp` |
| `--field NAME=VALUE` (repeatable) | custom field with `hidden = false` (split at the first `=`) |
| `--hidden-field NAME` (repeatable) | custom field with `hidden = true`; value is a prompt |
| `update` only: `--clear-username`, `--clear-urls`, `--clear-notes`, `--clear-totp`, `--clear-fields` | set to null / empty |

Semantics of `update`: a field the command line does not mention is unchanged. `--url` given
at least once **replaces** the whole URL list; `--field`/`--hidden-field` given at least once
**replace** the whole custom-field list; `--totp` replaces the whole TOTP configuration
(unspecified parameters take the defaults above). A `--clear-X` together with a setter of
the same field is a usage error. Flags that do not apply to a note (`--username`, `--url`,
`--totp…`, `--generate`, `--new-password`) are rejected by the core's validation (exit 1).

### Commands and prompts

Prompts appear in this order: master password, then (if requested) the item password,
TOTP secret, notes, and the hidden field values in the order their `--hidden-field` flags
appear on the command line.

| command | options | prompts, in order |
|---|---|---|
| `init` | `[--print-secret-key]` | master password; confirm |
| `add-login` | `--title T` + item flags | master; item password (skipped with `--generate`); TOTP secret (`--totp`); notes (`--notes`); hidden values |
| `add-note` | `--title T` and exactly one of `--notes`, `--notes-file` | master; notes (`--notes`) |
| `get <ID>` | `[--show-secrets]` | master |
| `list` / `search <QUERY>` | | master |
| `update <ID>` | item flags + clear flags | master; item password (`--new-password`); TOTP secret (`--totp`); notes (`--notes`); hidden values |
| `delete <ID>` | | master |
| `passwd` | `[--rotate]` | master; new master password; confirm |
| `rotate-key` | | master |
| `export` | `--out <PATH>` | master; export password; confirm |
| `import` | `--in <PATH> --source-secret-key-file <PATH>` | master; export password |
| `totp <ID>` | `[--time <unix>]` | master |
| `generate password` | `[--length N] [--no-lower] [--no-upper] [--no-digits] [--no-symbols] [--exclude-ambiguous]` | none |
| `generate passphrase` | `[--words N] [--separator S] [--capitalize] [--digit]` | none |

`passwd --rotate` calls `change_master_password_and_rotate_key` (one atomic write); without
`--rotate` it calls `change_master_password` and prints a reminder that the vault key was
not rotated. `export` uses the global `--secret-key-file` as the export's secret key.
`import` reads the secret key of the vault the export came from from
`--source-secret-key-file` (for a restore into a fresh vault this is the old vault's key
file); the global `--secret-key-file` still unlocks the target vault.
`export --out` equal to `--vault` (canonicalized) is a usage error (exit 2).

With `--stdin`, each prompt consumes one line (terminator stripped; `\r\n` accepted;
EOF before a required line is a usage error). Without `--stdin`, prompts use a no-echo
terminal read and "confirm" prompts re-ask. Outputs: `init` prints the vault and key-file
paths; `add-*` prints the new ID; `list`/`search` print one line per item
(`<id>\t<kind>\t<title>\t<username>`); `get` prints labelled lines, with the password,
**notes**, TOTP secret and hidden field values replaced by `<hidden>` unless
`--show-secrets`; `totp` prints the code and the seconds remaining; `generate` prints the
result. The CLI reads the secret key from the key file (CS §3.2: trim ASCII whitespace at
both ends, then `SecretKey::from_text`; the exact form is 58 characters, but dashes and
spaces inside are accepted) and never echoes it.

### `init` order (no lost key)

The vault must never exist without a key file that can open it. `init` does, in this order:

1. read and confirm the master password (length check; no disk access yet);
2. check that neither the key-file path nor the vault path exists, and that they differ
   (else exit 1 and nothing is created);
3. generate the secret key;
4. create the key file with `create_new`, mode 0600, write the key text, `sync_all`;
5. read the key file back and parse it with the key-file rules above; it must equal the
   generated key (else remove the key file, exit 1);
6. `Vault::create_with_key` with that key;
7. if step 6 fails, remove the key file created in step 4 (best effort) and exit 1.

Tests: key file already exists, key-file directory missing, vault path already exists, and an
injected failure at step 6 (an unwritable vault directory) each leave no new file behind and
never overwrite an existing one.

## 6. Test strategy

- **Where**: unit tests inline (`#[cfg(test)]`); integration tests in
  `crates/onlypassword-core/tests/`; end-to-end CLI test in
  `crates/onlypassword-cli/tests/e2e.rs`, driving the real binary through
  `env!("CARGO_BIN_EXE_onlypassword")` with `--stdin`.
- **Known-answer tests** read `spec/vectors/<name>.json` via
  `Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/…")` and `serde_json`; they
  never copy the values into source (REQ-BLD-002). Each KAT test fails if the file is
  missing or has zero vectors.
- **Layout tests** assert header size 130, record fixed part 126, trailer 40, export header
  74, and the offset of each field against CS §5, §8 using a hand-built buffer.
- **Round-trip** tests for every lifecycle operation, using `KdfParams::FAST_FOR_TESTS` (fast;
  unit tests via `cfg(test)`, integration tests via `--features insecure-fast-kdf`, which the
  gate's `--all-features` provides) and `tempfile` directories; one test uses
  `KdfParams::DEFAULT` to confirm defaults work. Integration test files that need the fast parameters start with
  `#![cfg(feature = "insecure-fast-kdf")]` (no self-referential dev-dependency); the gate always
  runs them because it passes `--all-features`.
- **Tamper tests**: flip each byte of a small vault (and export) file one at a time —
  every flip must produce an error from `unlock` or from `get` of every affected item,
  never a plaintext; truncate at every length; append bytes; swap two records; copy a
  record onto another ID; replay an old record; delete a record; version bytes 0 and 2.
- **Negative tests**: wrong password, wrong secret key (same error), short passwords,
  bounds on KDF parameters (asserted on `validate_strict`), unknown JSON fields, oversize inputs, ID not found, duplicate
  import ID.
- **Robustness**: parsers get a deterministic corpus (truncations, single-byte mutations
  with a seeded xorshift generator written in the test, random garbage of assorted sizes)
  and must return `Err` without panicking; no fuzzing infrastructure (brief).
- **Statistical** test for `uniform` and the generators using the injected
  `RandomSource` (deterministic stream), not a flaky live RNG test.
- **Limits**: unit tests with reduced limits (an internal constant overridable under
  `cfg(test)`) show `add`/`update`/`import` return `LimitExceeded` without writing, and that
  `update` at revision `u64::MAX` (reached through import) returns `LimitExceeded`.
- **Secrets**: compile-time assertions that secret types implement `ZeroizeOnDrop`;
  tests that `format!("{:?}")` of every secret-holding type contains none of a sentinel
  value placed in it.
- **Gate**: tests must be deterministic, offline, and finish in a few minutes in total
  (`KdfParams::FAST_FOR_TESTS` everywhere except the one default-params test and the CLI e2e, which
  runs the real defaults a handful of times).
