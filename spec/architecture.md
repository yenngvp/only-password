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

---

# Phase 2 — desktop application

Sections 1–6 describe the pilot and are unchanged. The CLI (§5) stays exactly as it is, including
its private `keyfile` module; it is not refactored onto the new core helpers. Names below are the
contract between this document, `requirements.md` and `features.json`; a generator that wants a
different name records it in `agent-notes/spec-issues.md`.

## 7. `crates/onlypassword-desktop`

### 7.1 Core additions (own features, before the GUI uses them)

The code in `crates/onlypassword-core` is authoritative for existing signatures (the §2 sketch is
informative; e.g. `add`/`update` take `&Item`). Phase 2 adds exactly these public items:

```rust
// module `vault` (re-exported at the crate root)
pub struct ItemIndex { /* Vec<ItemSummary> sorted as list(); zeroizes on drop */ }
impl ItemIndex {
    pub fn entries(&self) -> &[ItemSummary];
    pub fn search(&self, query: &str) -> Vec<&ItemSummary>;   // same rule as Vault::search
    pub fn len(&self) -> usize;  pub fn is_empty(&self) -> bool;
}
impl Vault { pub fn index(&self) -> &ItemIndex; }              // built at create/unlock

// new module `keyfile` (pub mod keyfile)
pub fn read(path: &Path) -> Result<SecretKey>;                 // <= 4096 bytes, trim ASCII ws, from_text
pub fn write_new(path: &Path, key: &SecretKey) -> Result<()>;  // create_new, 0600 (unix), text + "\n", sync_all
impl Vault {
    pub fn create_with_key_file(vault_path: &Path, key_path: &Path, password: &SecretString,
                                params: KdfParams) -> Result<Vault>;   // init order of §5
}
```

`Vault` keeps the index next to the parsed file and replaces it together with `self.file` after a
successful write (REQ-LIF-012). `ItemIndex` implements `Debug` (redacted) and `Drop` zeroizing every
string it owns. `Vault::list`/`search` keep their behaviour; the index only avoids decrypting every
record per keystroke. For test determinism a counter of record decryptions is exposed under the
existing `test-hooks` feature (`Vault::decrypt_count()`), used to show `index().search` decrypts
nothing.

### 7.2 Layout

Library `onlypassword_desktop` (`src/lib.rs`) plus a thin binary (`src/main.rs`), both with
`#![forbid(unsafe_code)]` and the panic-free `cfg_attr` of §1. The root `Cargo.toml` `members` list
gains `crates/onlypassword-desktop`. `publish = false`, edition 2021. The crate has no cargo features.

| module | content | depends on egui? |
|---|---|---|
| `error` | `UiError` (§7.6) | no |
| `secret_buf` | `SecretBuf`: a `Zeroizing<String>` created with capacity 1 024 (limit 64 KiB, CS §10 notes limit), `push_str`, `clear`, `expose()`, redacted `Debug`; never `Clone` | no |
| `clock` | trait `UiClock { fn now(&self) -> Duration /* monotonic since start */; fn unix_secs(&self) -> u64 }`, `SystemUiClock`, and a public `ManualClock` (shared handle, `advance(Duration)`, `set_unix(u64)`) for tests | no |
| `config` | `Theme { System, Light, Dark }`, `Config { idle_timeout_secs: u64, clipboard_clear_secs: u64, theme: Theme, last_vault_path: Option<PathBuf> }`, `Config::default()`, `Config::validate()`, `ConfigStore { dir: PathBuf }` with `ConfigStore::new(dir)`, `ConfigStore::platform_default() -> Option<ConfigStore>` (via `directories::ProjectDirs::from("", "", "onlypassword")`), `load() -> (Config, Option<UiError>)`, `save(&Config) -> Result<(), UiError>` | no |
| `clipboard` | trait `ClipboardBackend { fn get_text(&mut self) -> Result<Option<String>, ()>; fn set_secret_text(&mut self, text: &str) -> Result<(), ()>; fn clear(&mut self) -> Result<(), ()>; }` (errors are mapped to `UiError::Clipboard`, no detail kept), `ArboardBackend` (real, cfg-gated parts), public `MemoryClipboard` (shared handle, records `sensitive` flag, can be told to fail), and `ClipboardService` (§7.4) | no |
| `picker` | trait `FilePicker { fn pick_vault(&mut self) -> Option<PathBuf>; fn pick_key_file(&mut self) -> Option<PathBuf>; fn save_vault(&mut self) -> Option<PathBuf>; fn save_key_file(&mut self) -> Option<PathBuf>; fn pick_export(&mut self) -> Option<PathBuf>; fn save_export(&mut self) -> Option<PathBuf>; }`, `RfdPicker` (real), public `ScriptedPicker` (queue of answers) | no |
| `state` | `AppState`, `Screen`, `Action`, `Session`, `Draft`, `Notice`, sub-modules `session`, `browse`, `edit`, `generator`, `maintenance`, `idle`, `settings` | no |
| `view` | `show(ctx: &egui::Context, state: &mut AppState)` and one function per screen (`view::open`, `create`, `unlock`, `browse`, `detail`, `edit`, `generator`, `maintenance`, `settings`), plus `view::secret_edit` (the egui `TextBuffer` adapter, §7.3) | yes |
| `app` | `DesktopApp` implementing `eframe::App`: builds `AppState` from real dependencies, forwards frame input activity, calls `view::show`, schedules repaints (`request_repaint_after` ≤ 1 s while unlocked so timers fire), performs `AppState::on_exit` | yes |

Only `view` and `app` (and `main.rs`) may name `egui`/`eframe`; a test greps `src/state`, `src/error.rs`,
`src/secret_buf.rs`, `src/clock.rs`, `src/config.rs`, `src/clipboard.rs` and `src/picker.rs` for
`egui` and `eframe` — except that `clipboard.rs` and `picker.rs` may name `arboard` and `rfd`.

### 7.3 State machine and secrets in the UI

```rust
pub struct AppDeps { pub clock: Box<dyn UiClock>, pub clipboard: Box<dyn ClipboardBackend>,
                     pub picker: Box<dyn FilePicker>, pub config_store: Option<ConfigStore>,
                     pub kdf: KdfParams /* default KdfParams::DEFAULT */ }
pub enum Screen { Open, Create, Unlock, Browse, Detail(ItemId), Edit(Option<ItemId>),
                  Generator, Maintenance(MaintenanceKind), Settings }
impl AppState {
    pub fn new(deps: AppDeps) -> AppState;             // loads config; Screen::Open (or Unlock if last_vault_path is set)
    pub fn dispatch(&mut self, action: Action);        // never panics; failures become `notice()`
    pub fn tick(&mut self);                            // idle timer, TOTP rollover, clipboard deadline
    pub fn screen(&self) -> &Screen;
    pub fn notice(&self) -> Option<&UiError>;          // last fixed message, cleared by the next action
    pub fn is_clean(&self) -> bool;                    // REQ-LOCK-003
    pub fn on_exit(&mut self);                         // REQ-CLIP-004
    /// read-only views for rendering and tests (rows, selected item, totp display, ...)
}
```

`Action` is an enum covering every user intent (`SubmitOpen`, `SubmitCreate`, `Lock`, `Search(String)`,
`Select(ItemId)`, `ToggleReveal(FieldRef)`, `Copy(FieldRef)`, `BeginEdit`, `BeginAdd(ItemKind)`,
`SaveDraft`, `CancelDraft`, `ConfirmDelete`, `GenerateNow`, `UseGenerated`, `SubmitChangePassword`,
`SubmitRotate`, `SubmitExport`, `SubmitImport`, `SaveSettings`, `Activity`, …); the exact variant set
is the generator's, and tests only use `dispatch`, `tick` and the read-only views. Text the user is
typing goes into form buffers owned by the state (`SecretBuf` for secrets, plain `String` for
non-secrets such as paths and the search text) through setter actions or direct access to the
buffers from `view`.

`Session` holds, while unlocked: the `Vault`, the `SecretKey` (needed for export and password
change), the cached rows (`Vec<Row>` copied from `Vault::index()`; `Row` is a plain struct that
implements `Zeroize` and zeroizes on drop), and the open detail (`StoredItem`) or `Draft`. Dropping
the `Session` (which `Action::Lock`, the idle timer and `on_exit` do) drops all of it; `Vault::lock`
is called explicitly first. `AppState` has no `Clone` and a redacted `Debug` that prints only the
screen name and booleans. `is_clean()` is true iff: no `Session`; all `SecretBuf`s are empty; no
`Draft`; no generated value; revealed set empty; the clipboard service has no pending digest;
the screen is `Open`, `Create`, `Unlock` or `Settings`.

**Secret text in egui.** A `Draft` holds `SecretBuf`s for the password, notes, TOTP secret and
hidden field values (and plain `String`s for title, username, URLs and field names, which are not
secrets, §4.8). `view::secret_edit` wraps a `&mut SecretBuf` in a private newtype implementing
`egui::TextBuffer`, so `egui::TextEdit` edits the zeroizing buffer in place and egui never receives a
`String` copy; widgets are `.password(true)` while masked. Because egui keeps text in its own caches
(edit state with undo history, galley cache), the view calls `ctx.memory_mut(|m| m.data.clear())`
and, where the egui version has it, `ctx.forget_all_images()` whenever a form is submitted,
cancelled or the state becomes clean, and stores no secret in egui memory through its own code
(`ctx.data_mut`, `persist`). Residual: egui's layout of a *revealed* value contains a copy in
the galley cache until it is evicted; this is a documented limit (threat-model §7).

**Masked rendering.** A masked secret (detail view) is drawn as a fixed placeholder label (`••••••••`,
always eight bullets, independent of length) next to "Reveal" and "Copy" buttons; the secret is
read from the `StoredItem` only when the user toggles reveal or presses copy. Revealed text is drawn
once per frame from the held `SecretString::expose()` as a `Label`; no secret is ever formatted into a
widget id, accessibility label or tooltip.

**Reveal set.** `FieldRef { Password, Notes, TotpSecret, Custom(usize) }`; the state keeps a
`BTreeSet<FieldRef>` cleared by lock, selection change and edit.

**Idle timer.** `IdleTimer { timeout: Duration, last_activity: Duration }` in `state::idle`;
`touch(now)`, `expired(now)`, `set_timeout`. `DesktopApp::update` dispatches `Action::Activity` when the
frame's input has events or pointer movement; `tick()` locks when `expired(clock.now())`. Locking happens
before any other pending action of that tick (REQ-LOCK-005). The timer is only armed while a `Session`
exists.

**Blocking operations.** Argon2id (64 MiB, about one second) runs synchronously inside `dispatch`;
the view shows a "Working…" notice for that frame. Native file dialogs are blocking calls on the UI
thread inside `FilePicker`; the idle timer is re-evaluated on the next `tick` (REQ-LOCK-005).

### 7.4 Clipboard service

`ClipboardService { backend, timeout, pending: Option<Pending { digest: [u8; 32], deadline: Duration }> }`.
`copy(&mut self, text: &str, now)` calls `backend.set_secret_text(text)`, stores `SHA-256(text)` (the
`sha2` crate) and `now + timeout`, replacing any earlier pending value. `poll(now)` does nothing before
the deadline; at or after it, `clear_if_ours()`: read the clipboard once, and only if the text's
digest equals the pending digest call `backend.clear()`; then forget the pending value either way.
`clear_now()` (lock, exit) is `clear_if_ours()` without the deadline. The digest is compared with
`==` on non-secret-dependent data (a hash of a value the app itself just wrote; no attacker-visible
oracle), which is the one place where §4.7's "no hand-written comparison" is knowingly relaxed. The
real backend, `ArboardBackend`, wraps `arboard::Clipboard` and, behind `cfg(target_os = …)`, asks
the platform to exclude the entry from clipboard history/cloud sync where arboard offers it; where it
does not, it is a plain `set_text`. `set_secret_text` is the only way the app writes the clipboard.

### 7.5 Config module

`ConfigStore::load` reads `config.json` through a bounded read (≤ 4 096 bytes), parses it with
`serde_json` into a struct with `#[serde(deny_unknown_fields)]`, validates ranges (REQ-CFG-003), and
returns `(Config::default(), Some(UiError::ConfigInvalid))` on any problem. `save` serializes only the
`Config` struct (so nothing else can leak in), writes `config.json.tmp` (0600 on Unix), `sync_all`,
renames over `config.json`, and removes the temporary file on failure. `last_vault_path` is stored with
`to_str` (a non-UTF-8 path is simply not stored). Defaults: idle 300 s, clipboard 30 s, theme System.
A test serializes a `Config` and asserts that the set of JSON keys is exactly the five of REQ-CFG-002.

### 7.6 Error surface

`UiError` is a closed enum with `Display` giving fixed strings; it has no `String` payloads:

```rust
pub enum UiError {
    Core(onlypassword_core::Error),   // Display = the core's fixed text; Authentication is one message
    PasswordMismatch, EmptyField, NoSelection,
    Clipboard, ConfigInvalid, ConfigWrite, InvalidSetting,
    PickerCancelled,                  // not shown; ends the action silently
}
```

`impl From<onlypassword_core::Error> for UiError`. Unlock failures with `Authentication` show the
single sentence of the core; no code path distinguishes password from key. The view prints
`notice().to_string()` only. No message contains a path, a value or a key; tests iterate every
`UiError` variant and the core `Error` variants and assert that the strings are literals from a
fixed list.

### 7.7 Dependencies and portability rules

Direct dependencies of the desktop crate are the ones marked "desktop" in `approved-deps.txt`.
All work in the library is `cfg`-free except: `ArboardBackend` extension traits (`cfg(windows)`,
`cfg(target_os = "macos")`, `cfg(all(unix, not(target_os = "macos")))`), the 0600 permission calls
(`cfg(unix)`), and `RfdPicker` (rfd's backends are selected by rfd itself). Nothing in the crate
may call a Linux-only API outside such a gate. The two cross targets only `cargo check` (all
targets, all features, offline, locked); linking and running them is not done by the pipeline, so
the generator must not add `build.rs` scripts or native libraries beyond what the approved crates
bring. The agent container's system libraries are pkg-config, libwayland-dev, libxkbcommon-dev, libgtk-3-dev,
libgl1-mesa-dev, libegl1-mesa-dev, libfontconfig1-dev and libssl-dev; a feature that needs a different system library is a
spec issue, not a Dockerfile change.

### 7.8 Test strategy (desktop)

- **State-machine tests** (`crates/onlypassword-desktop/tests/*.rs` and inline): build an `AppState`
  with `ManualClock`, `MemoryClipboard`, `ScriptedPicker`, a `ConfigStore` over a `tempfile`
  directory and `KdfParams::FAST_FOR_TESTS`. The desktop crate's `[dev-dependencies]` enable the core
  features `insecure-fast-kdf` and `test-hooks` (never `[dependencies]`; REQ-GUI-074); only the
  end-to-end test (F037) uses default parameters. Tests drive `dispatch` and `tick`, never sleep.
- **View tests** with `egui_kittest` (`Harness::new_state`, running `view::show` over an `AppState`):
  find widgets by accessibility label, click, type, and assert both on the state and on the
  accessibility tree (for example that a masked password's text appears nowhere in the tree). No
  snapshot (image) tests, no `wgpu` feature, no real window.
- **Sentinel scans**: tests put distinctive fake values (`"pw-SENTINEL-…"`) in items, then assert
  they are absent from `format!("{:?}", state)`, from every `UiError` string, from the config file
  and from `MemoryClipboard` after the clear.
- **Source-scan tests**: no `println!`-family or logging macros, no `std::net`, no `egui` outside
  `view`/`app`/`main`, no network crates in `Cargo.lock` (denylist: `reqwest`, `hyper`, `ureq`,
  `isahc`, `curl`, `surf`, `attohttpc`, `native-tls`, `rustls`, `openssl`, `tokio`, `async-std`,
  `zbus`, `ashpd`, `sentry`, `opentelemetry`; `openssl-sys` must not appear either).
- **Gate**: runs the whole suite on Linux without a display; the real `main.rs` window is never
  opened by a test.
- **Real-window smoke** (not in the gate): `cargo run -p onlypassword-desktop` by a person.
