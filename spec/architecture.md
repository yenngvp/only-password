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
(secret types implement `Debug` by hand, see §4). Workspace `[workspace.lints]` may enable
`clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`, `clippy::indexing_slicing`
for non-test code of the parsers. Only the CLI depends on `rpassword`; the core has no I/O
dependency beyond `std`.

### Core modules (`crates/onlypassword-core/src/`)

| module | content |
|---|---|
| `error` | `Error`, `Result` |
| `secret` | `SecretBytes<const N>` / `SecretVec`, `SecretString` (zeroize-on-drop, redacted `Debug`) |
| `rng` | `fill_random`, `random_array::<N>()`, `uniform(n)`; trait `RandomSource` (internal, for stubbing in tests) |
| `base32` | RFC 4648 encode/decode (no padding on encode, tolerant decode) |
| `crypto` | `aead` (XChaCha20-Poly1305 wrappers), `kdf` (`KdfParams`, Argon2id), `hkdf` helpers, `keys` (`SecretKey`, `MasterKey`, `VaultKey`, `ItemKey`, subkeys) |
| `item` | `Item`, `ItemKind`, `Totp*`, `CustomField`, JSON (de)serialization and validation (CS §7) |
| `format` | pure byte codec for the vault file (CS §5): `VaultFile`, `Header`, `Record`; no keys, no I/O |
| `seal` | uses `crypto` + `format`: wrap/unwrap VK, seal/open records, trailer (CS §6) |
| `storage` | atomic file write, permissions, bounded file read |
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

// ---- KDF parameters ----
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams { pub m_kib: u32, pub t: u32, pub p: u32 }
impl KdfParams {
    pub const DEFAULT: KdfParams = KdfParams { m_kib: 65_536, t: 3, p: 4 };
    pub const MIN: KdfParams = KdfParams { m_kib: 8_192, t: 1, p: 1 };   // floor, used by tests
    pub fn validate(&self) -> Result<()>;                                 // CS §10
}

// ---- items ----
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum ItemKind { Login, Note }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum TotpAlgorithm { Sha1, Sha256, Sha512 }

pub struct TotpConfig { pub secret: SecretString /* base32, upper case, no padding */,
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
    pub fn validate(&self) -> Result<()>;                                // CS §7 limits
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
pub struct Vault { /* path, parsed file, VK, K_iw, K_fa, clock; ZeroizeOnDrop */ }
impl std::fmt::Debug for Vault { /* redacted */ }

impl Vault {
    pub fn create(path: &Path, password: &SecretString, params: KdfParams)
        -> Result<(Vault, SecretKey)>;
    pub fn unlock(path: &Path, password: &SecretString, key: &SecretKey) -> Result<Vault>;
    pub fn lock(self);                                    // consumes; zeroizes
    pub fn set_clock(&mut self, clock: Box<dyn Clock>);   // tests

    pub fn add(&mut self, item: Item) -> Result<ItemId>;
    pub fn get(&self, id: &ItemId) -> Result<StoredItem>;
    pub fn update(&mut self, id: &ItemId, item: Item) -> Result<u64 /* new revision */>;
    pub fn delete(&mut self, id: &ItemId) -> Result<()>;
    pub fn list(&self) -> Result<Vec<ItemSummary>>;
    pub fn search(&self, query: &str) -> Result<Vec<ItemSummary>>;

    pub fn change_master_password(&mut self, current: &SecretString, new: &SecretString,
                                  key: &SecretKey, params: KdfParams) -> Result<()>;
    pub fn rotate_vault_key(&mut self) -> Result<()>;

    pub fn export(&self, path: &Path, export_password: &SecretString, params: KdfParams) -> Result<()>;
    pub fn import(&mut self, path: &Path, export_password: &SecretString) -> Result<usize>;
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

// ---- totp ----
pub fn hotp(secret: &[u8], counter: u64, alg: TotpAlgorithm, digits: u8) -> Result<String>;
pub fn totp(secret: &[u8], unix_secs: u64, period: u32, alg: TotpAlgorithm, digits: u8) -> Result<String>;
pub fn totp_for_item(cfg: &TotpConfig, unix_secs: u64) -> Result<String>;   // parses base32, validates
pub fn parse_totp_secret(text: &str) -> Result<SecretVec>;
```

`Vault` is *the* unlocked state: there is no locked `Vault` value. `change_master_password`
takes `key` because the new master key needs the secret key; it verifies `current` by
re-deriving and comparing through AEAD unwrap of `wrapped_vk` (never by `==`). `Vault`
holds the parsed file in memory (encrypted records) and decrypts items on demand; every
mutation builds the new complete file image, writes it with `storage::write_atomic`, and
only then replaces the in-memory image (REQ-LIF-012).

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
- Passphrase words: `bip39::Language::English.word_list()` (2 048 words, 11 bits/word,
  7 words ≈ 77 bits). `include_digit` appends one digit (uniform 0–9) to one uniformly
  chosen word. The list is a crate constant, not a file the core reads.

## 3. Error model

- One `Error` enum (above). Variants carry **only** `&'static str` or `io::ErrorKind`.
  No `String`, no path, no byte value, no secret ever enters an error (REQ-SEC-003).
- `Authentication` is returned for: wrong password, wrong secret key, tampered header
  (`wrapped_vk` tag), failed trailer tag, failed record tag, failed export tag. These are
  deliberately indistinguishable.
- `Corrupt` for structure that fails before any key is involved (bounds, lengths,
  ordering, unexpected `flags`/`kdf_id`/`kdf_version`, trailing bytes, JSON that does not
  parse or violates the schema after successful authentication).
- `UnsupportedVersion` for `format_version`, `item_schema`, `export_schema` ≠ 1.
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
5. `serde_json` parsing of decrypted items can leave copies in its intermediate
   allocations that this design cannot zeroize; this is a known, accepted limit
   (threat-model.md, residual risks). Mitigation: parse from a `Zeroizing<Vec<u8>>`, copy
   fields into `SecretString` at once, and drop the intermediate promptly.
6. Keys are passed by reference; key newtypes are not `Copy`.
7. No secret-dependent branching other than the AEAD tag check performed by the
   `chacha20poly1305` crate; no hand-written comparison of secret bytes.
8. `Item` fields that are not secrets (title, username, URLs, field names) are plain
   `String`; the password, notes, TOTP secret and custom field *values* are `SecretString`.

## 5. CLI (`onlypassword`)

Global options (before the command): `--vault <PATH>` (required except for `generate`),
`--secret-key-file <PATH>` (required except for `generate`), `--stdin` (read prompts from
stdin lines). Argument parsing is hand-written (no `clap`); unknown flags are usage errors.

| command | options | prompts, in order |
|---|---|---|
| `init` | `[--print-secret-key]` | master password; confirm |
| `add-login` | `--title T [--username U] [--url U]… [--notes N] [--generate] [--totp]` | master; item password (skipped with `--generate`); TOTP secret (only with `--totp`) |
| `add-note` | `--title T --notes N` | master |
| `get <ID>` | `[--show-secrets]` | master |
| `list` / `search <QUERY>` | | master |
| `update <ID>` | `[--title T] [--username U] [--url U]… [--notes N] [--new-password]` | master; new item password (only with `--new-password`) |
| `delete <ID>` | | master |
| `passwd` | | master; new master password; confirm |
| `rotate-key` | | master |
| `export` | `--out <PATH>` | master; export password; confirm |
| `import` | `--in <PATH>` | master; export password |
| `totp <ID>` | `[--time <unix>]` | master |
| `generate password` | `[--length N] [--no-lower] [--no-upper] [--no-digits] [--no-symbols] [--exclude-ambiguous]` | none |
| `generate passphrase` | `[--words N] [--separator S] [--capitalize] [--digit]` | none |

With `--stdin`, each prompt consumes one line (terminator stripped; `\r\n` accepted;
EOF before a required line is a usage error). Without `--stdin`, prompts use a no-echo
terminal read and "confirm" prompts re-ask. Outputs: `init` prints the vault and key-file
paths; `add-*` prints the new ID; `list`/`search` print one line per item
(`<id>\t<kind>\t<title>\t<username>`); `get` prints labelled lines, with secrets replaced by
`<hidden>` unless `--show-secrets`; `totp` prints the code and the seconds remaining;
`generate` prints the result. The CLI reads the secret key text from the key file (32+ chars,
trailing whitespace trimmed) and never echoes it.

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
- **Round-trip** tests for every lifecycle operation, using `KdfParams::MIN` (fast) and
  `tempfile` directories; one test uses `KdfParams::DEFAULT` to confirm defaults work.
- **Tamper tests**: flip each byte of a small vault (and export) file one at a time —
  every flip must produce an error from `unlock` or from `get` of every affected item,
  never a plaintext; truncate at every length; append bytes; swap two records; copy a
  record onto another ID; replay an old record; delete a record; version bytes 0 and 2.
- **Negative tests**: wrong password, wrong secret key (same error), short passwords,
  bounds on KDF parameters, unknown JSON fields, oversize inputs, ID not found, duplicate
  import ID.
- **Robustness**: parsers get a deterministic corpus (truncations, single-byte mutations
  with a seeded xorshift generator written in the test, random garbage of assorted sizes)
  and must return `Err` without panicking; no fuzzing infrastructure (brief).
- **Statistical** test for `uniform` and the generators using the injected
  `RandomSource` (deterministic stream), not a flaky live RNG test.
- **Secrets**: compile-time assertions that secret types implement `ZeroizeOnDrop`;
  tests that `format!("{:?}")` of every secret-holding type contains none of a sentinel
  value placed in it.
- **Gate**: tests must be deterministic, offline, and finish in a few minutes in total
  (`KdfParams::MIN` everywhere except the one default-params test and the CLI e2e, which
  runs the real defaults a handful of times).
