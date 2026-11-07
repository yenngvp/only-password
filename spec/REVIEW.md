# Independent specification review

Reviewer: critic agent (did not write the spec). Reviewed: `CLAUDE.md`, `spec/brief.md`, every
file under `spec/`, `pipeline/gate.sh`, `pipeline/deny.toml`. Nothing else was changed.

Summary: no blocker in the cryptographic design itself. I found one blocker in the feature
list (a feature whose acceptance criteria cannot be met by the specified CLI) and several
majors where a literal builder would produce an insecure or lossy behaviour or where two
builders would diverge. All test vectors match their sources.

Severity: `blocker` = insecure or unbuildable; `major` = a builder would get it wrong;
`minor` = everything else.

---

## Findings

### R-01 — blocker — `architecture.md` §5 (CLI) vs `features.json` F020, F022
The CLI cannot express what F020 and F022 require. `add-login --totp` takes only the secret
(one prompt); there is no way to set algorithm, digits or period, and no way to add custom
fields (not on `add-login`, not on `update`). But:
- F020 requires `totp --time 59` to print `94287082` — 8 digits. Without a digits option the
  item gets some unspecified default (6 digits) and prints `287082`.
- F022 requires "login with TOTP and custom fields" and a compare of `get --show-secrets`
  output across vaults.

A generator cannot satisfy these without inventing CLI surface the spec does not define
(rule 2 forbids silent deviation), so F020/F022 would end `blocked` after 3 attempts.
**Fix:** add to `add-login` and `update`: `--totp-algorithm sha1|sha256|sha512` (default
sha1), `--totp-digits N` (default 6), `--totp-period N` (default 30), repeatable
`--field NAME=VALUE` and `--hidden-field NAME` (value from a prompt, in a stated order),
`--clear-totp`, `--clear-fields`. State the defaults in CS §7 / architecture §5. Add the
prompt order for the new prompts.

Resolution: Fixed. architecture.md §5 now defines shared item flags (--totp-algorithm/--totp-digits/--totp-period, --field, --hidden-field, --clear-*), prompt order and `update` replace semantics; new REQ-CLI-007; F020 split out as `F020-cli-items` (later features renumbered F021–F023); F021 TOTP test uses `add-login --totp --totp-digits 8`.

### R-02 — major — `crypto-spec.md` §8, `OPEN-QUESTIONS.md` #8, `threat-model.md` residual risk 4
The export key is derived from the export password alone (no secret key). The brief says
"Stolen vault data must be useless without both" the master password and the secret key. An
export holds the entire vault, is meant to be stored off-device, and is attackable offline
with only an 8-character password and, at the floor, `m = 8 MiB, t = 1`. It is the weakest
link in the product and silently voids the two-secret property. Calling it an accepted
risk is the owner's call, but the spec does not say it contradicts the brief's wording.
**Fix (preferred):** `K_x = HKDF(salt = kdf_salt, IKM = export_pw_key ‖ SK, info = INFO_EXPORT)`
and make import take the secret key (a fresh device still has the key file/written copy,
which it needs anyway to unlock anything). If the owner wants a portable export, keep the
current design but (a) enforce at least the default KDF parameters for export
(`m ≥ 65 536, t ≥ 3`), (b) raise the export password floor (e.g. 12 scalar values), and
(c) record the deviation from the brief in `OPEN-QUESTIONS.md` item 8 as an explicit
owner decision, not a default.

Resolution: Fixed with the preferred option. CS §8: `K_x = HKDF(salt, export_pw_key ‖ SK, INFO_EXPORT)`; `export(.., key, ..)`/`import(.., source_key)` take the secret key; CLI `import --source-secret-key-file`. Export KDF params share the raised floor. Updated requirements (REQ-EXP-001..003), threat model (A7, ATK-4, T-EXPLEAK, residual risk 4), OPEN-QUESTIONS #8 (the portable-password-only alternative is recorded as an owner decision, not applied), F018/F021/F023.

### R-03 — major — `crypto-spec.md` §9, §6.3, §8; `requirements.md` REQ-FMT-002, REQ-ENC-003; F009, F010, F018
Error classes for version/identifier mismatches contradict each other.
- §9 bullet 1 says a smaller or larger `kdf_id`/`kdf_version` is `UnsupportedVersion`;
  §9 check order step 4, architecture §3 and F009 say unexpected `kdf_id`/`kdf_version`
  is `Corrupt`.
- `item_schema` in a record: no check order is defined. If a reader rejects
  `item_schema != 1` before decrypting, the result is `UnsupportedVersion`; REQ-ENC-003 and
  F010 require `Authentication` when `item_schema` is changed. Both cannot hold.
- The export file has no check order at all (F018 says "CS 9 order"; §9 covers only vaults).
  "`export_schema 2 or format_version 2 inside/outside returns UnsupportedVersion/Corrupt as
  specified`" specifies nothing. `export_schema` is inside the AEAD, so it can only be seen
  after authentication.
- JSON `schema` ≠ 1 vs unknown fields: a schema-2 body with new fields returns `Corrupt` or
  `UnsupportedVersion` depending on whether the `schema` key is read first. F021 accepts
  either.
**Fix:** one table in CS §9 giving, for vault and for export, the ordered checks and the
exact error for each. Suggested: `kdf_id`/`kdf_version` → `UnsupportedVersion` (they are
versions); record `item_schema` is never pre-checked and is only authenticated (a changed
value is `Authentication`; the only value that can decrypt is the one sealed, and after
decryption `schema != 1` is `UnsupportedVersion`); export order: length ≥ 90, magic,
`format_version`, flags/kdf_id/kdf_version, KDF bounds, `ct_len`, Argon2, AEAD,
`export_schema`, payload validation. Parse the JSON `schema` field first (two-pass), and
return `UnsupportedVersion` before any unknown-field check.

Resolution: Fixed. CS §9 now has one ordered table for vault files and one for export files with the exact error per step. kdf_id/kdf_version → `UnsupportedVersion`; `item_schema` is never pre-checked (changed value → `Authentication`); JSON is read in two passes with `schema`/`export_schema` first → `UnsupportedVersion` before any unknown-field check; item schema inside an export likewise. architecture §3, REQ-FMT-002, F009, F010, F018, F022 aligned.

### R-04 — major — `features.json` F012, F011 (`create_exclusive`), REQ-LIF-001, REQ-FMT-004
`Vault::create` is specified to write "with create_exclusive semantics". A direct
exclusive write puts a partial vault at the final path if the process dies mid-write, which
breaks REQ-FMT-004/T-CRASH, and the user's key file may already have been shown. If instead
a builder uses write-temp-then-rename for `create`, `rename` silently replaces a file that
appeared in the meantime, breaking REQ-LIF-001 ("existing file untouched").
**Fix:** specify create as: write temp file (0600, fsync), `std::fs::hard_link(temp, target)`
(fails if `target` exists on all platforms), remove temp, fsync directory; fall back to an
error, not to rename, where hard links are unavailable. Add an acceptance test with the
target created between temp write and link (via an injectable hook) and one with a crash
simulated before the link.

Resolution: Fixed. CS §6.6 specifies create as temp file + `hard_link` + remove temp + fsync dir, no rename fallback; new REQ-FMT-008; F011 `create_new_atomic` with a pub(crate) hook and tests for the race and for a crash before the link; F012 acceptance extended.

### R-05 — major — `architecture.md` §5 `init`, F019, REQ-CLI-003, F012
`Vault::create` writes the vault and only then returns the secret key; the CLI then writes
the key file. If the key file cannot be written (exists, directory missing, disk full) or
the process dies in between, the vault exists and its secret key is gone forever — permanent
lock-out of an empty vault at best, and for `passwd`-style flows a real loss path. Order is
unspecified. F019 only tests "does not overwrite an existing key file".
**Fix:** CLI `init` must (1) check both paths do not exist, (2) generate the key, (3) write
the key file exclusively and fsync it, (4) read it back and parse it, (5) only then create
the vault with that key. That needs `Vault::create_with_key(path, password, params, &SecretKey)`
(or `create` taking `Option<SecretKey>`); add it to the API sketch. If vault creation fails,
the CLI removes the key file it created. Add a test for each failure.

Resolution: Fixed. `Vault::create_with_key` added (architecture §2); architecture §5 "init order" defines the seven steps with read-back and cleanup; REQ-CLI-003 rewritten; F019 acceptance has one test per failure mode.

### R-06 — major — `crypto-spec.md` §7, REQ-ITM-004, F008
"Reject a missing required field" is not what serde derive does for `Option<T>` fields: a
missing `username`, `password` or `totp` key silently becomes `None`. `username`/`password`
are "string or null" and `totp` "object or null" and are *required* keys. Also
`#[serde(default)]` on any field defeats the rule. Duplicate keys are rejected by derive for
structs but not by `serde_json::Value`.
**Fix:** say explicitly that nullable fields must be present (`deserialize_with` or a
non-`Option` wrapper type, or a pre-pass over `Value` checking the key set equals the schema
for the kind), and add a test row per nullable field "key absent → error". Name the check
for duplicates in nested objects (`fields[]`, `totp`).

Resolution: Fixed. CS §7 requires present-but-nullable keys via `deserialize_with`/wrapper, forbids `serde(default)`/`flatten`, and names duplicate-key rejection in nested objects; REQ-ITM-004 and F008 add a row per absent nullable key and nested duplicates.

### R-07 — major — `architecture.md` §5, REQ-CLI-002, REQ-CLI-005, T-LOGLEAK
`add-login`, `add-note` and `update` take `--notes N` on argv. `notes` is a `SecretString`
in the core and the threat model (ATK-6) says "nothing secret crosses argv". Notes
routinely hold recovery codes. `get` prints notes unmasked (REQ-CLI-005 hides only the
password, TOTP secret and hidden fields) although the core treats notes as secret.
**Fix:** read notes from a prompt/stdin line (state the order), or from `--notes-file`;
list notes among the hidden values for `get` unless `--show-secrets`. Update REQ-CLI-002,
REQ-CLI-005 and the F019 test.

Resolution: Fixed. `--notes` is now a prompt switch (plus `--notes-file`); notes are hidden by `get` unless `--show-secrets`; REQ-CLI-002, REQ-CLI-005, architecture §5, F019/F020 tests updated. `--field NAME=VALUE` is limited to non-hidden fields.

### R-08 — major — `crypto-spec.md` §7 vs `OPEN-QUESTIONS.md` #12, REQ-TOT-003, F008, F017
CS §7 (the byte-level authority) gives the TOTP secret as "base32, no padding, upper case"
but no length rule; the 10..=128 decoded-byte rule lives only in OPEN-QUESTIONS/REQ-TOT-003
and F017, while `Item::validate` (F008, earlier than F017) must already enforce "TOTP
parameters" (REQ-ITM-006). It is also unstated whether `validate` rejects a lower-case or
padded secret or canonicalizes it, and whether the stored form is canonical (two builders
produce different JSON and different round-trips). F008's tests cover only digits and
period.
**Fix:** put in CS §7: decoded length 10..=128 bytes; stored secret must already be
canonical (upper case, no padding, no separators) — `validate` rejects otherwise; the CLI
and `parse_totp_secret` canonicalize before storing. Add negative tests to F008.

Resolution: Fixed. CS §7 states the canonical form and 10..=128 decoded-byte rule; `Item::validate` rejects non-canonical secrets; `normalize_totp_secret`/`parse_totp_secret` live in the F004 base32 module (also resolves R-19); new REQ-ITM-007; negative tests added to F004 and F008.

### R-09 — minor — `crypto-spec.md` §10, F013, F018, REQ list
Limits are only enforced on parse. No requirement or acceptance test enforces
"items per vault ≤ 100 000" or "vault file ≤ 512 MiB" on `add`/`import`/`update`
(`Error::LimitExceeded` is defined but never required). A vault that grows past the limit
becomes unreadable by the core's own parser. Also inconsistent: 100 000 items × 1 MiB
allowed vs 512 MiB file and 256 MiB export plaintext limits, so a valid vault can fail to
export. **Fix:** require mutations to return `LimitExceeded` before writing when the new
image would exceed 512 MiB, 100 000 items, or the export limit; derive the export limit
from the vault limit (e.g. `MAX_EXPORT_PLAINTEXT = 2 × 512 MiB`, or lower the vault limit to
fit). Add tests.

Resolution: Fixed. REQ-LIF-014 and CS §10 "Enforcement on mutation": `LimitExceeded` before writing for 512 MiB / 100 000 items; `MAX_EXPORT_PLAINTEXT` raised to 1 GiB (2 × vault limit) with a size argument that a valid vault always fits; tests in F013 (reduced limits under cfg(test)) and F018.

### R-10 — minor — `crypto-spec.md` §10, `architecture.md` §2 `KdfParams::MIN`
The "floor" (8 MiB, t = 1, p = 1) is far below RFC 9106's second recommended option and the
public API can create a real vault with it (`create`, `change_master_password`, `export`
take arbitrary params ≥ floor). A tamperer cannot lower parameters on an existing file
(header is authenticated), so this is not a downgrade attack, but a caller bug or a
future UI could create weak vaults, and an old weak vault is never flagged.
**Fix:** raise the public floor (e.g. m ≥ 19 456 KiB, t ≥ 2) and give tests a way to go
lower only under `#[cfg(test)]`/an explicit non-default cargo feature that the CLI never
enables (note that `--all-features` in the gate enables features; use `cfg(test)`-only
constructors plus a `pub(crate)` test seam, and for integration tests a feature named
`insecure-fast-kdf` that is not in `default`). Optionally add `Vault::kdf_params()` so a UI
can warn on weak parameters.

Resolution: Fixed. Public floor raised to m ≥ 19 456 KiB, t ≥ 2, p ≥ 1 (also enforced when opening files, so REQ-KEY-004 changed from the old 8 MiB/t=1 floor). Test seam: `KdfParams::FAST_FOR_TESTS` and a lowered `validate` floor only under `cfg(test)` or non-default feature `insecure-fast-kdf`; `validate_strict` always real and unit-tested, so `--all-features` in the gate still tests the real floor. `Vault::kdf_params()` added. Self-referential dev-dependency avoided; integration tests use `#![cfg(feature = ...)]`.

### R-11 — minor — `crypto-spec.md` §6.5, `threat-model.md` T-PWCHANGE
`change_master_password` keeps the vault key and every item key. Anyone who held the old
password, the secret key and *any past copy of the header* can recover `VK` and decrypt all
future records. The threat model presents password change as removing the old password's
access. **Fix:** document that password change does not revoke access derived from a
previously compromised password+secret key and that `rotate_vault_key` is required in that
case; make CLI `passwd --rotate` (or a prompt) do both in one atomic write.

Resolution: Fixed. CS §6.5 documents that password change does not revoke earlier knowledge of VK; new `change_master_password_and_rotate_key` (REQ-LIF-015, F014) and CLI `passwd --rotate` (REQ-CLI-008); threat model T-PWCHANGE and OPEN-QUESTIONS #17 updated.

### R-12 — minor — `architecture.md` §2 `export`/`import`, REQ-EXP-001
`export --out` and `import --in` may point at the vault file itself (or a symlink to it).
Exporting over the vault replaces the vault with an export file. Rename over a symlink
replaces the link, not the target. **Fix:** reject (`InvalidInput`) when the export target
equals the vault path (compare canonicalized paths); state symlink behaviour of
`write_atomic` (resolve the final path first, then temp in its directory).

Resolution: Fixed. CS §6.6 and REQ-EXP-007: export rejects a target equal to the vault (canonicalized, symlink-aware); `write_atomic` resolves symlinks first (REQ-FMT-009); `storage::same_file_path`; tests in F011, F018, F021.

### R-13 — minor — `spec/vectors/`, `crypto-spec.md` §11, F007
The only Argon2id KAT uses the optional secret and associated data, which the production
path never uses; the production call shape (no K, no X, p = 4, m = 64 MiB) has no known
answer. F007's "independent recomputation" uses the same `hkdf`/`argon2` crates as the
code, so it only catches wiring errors, not a systematic one. XChaCha20-Poly1305's vector
comes from an expired Internet-Draft (the brief says "official published vectors"; the
README says so openly). No SHA-1/SHA-256, HMAC-SHA-1 or HChaCha20 vectors.
**Fix:** add an Argon2id vector without K/X from the reference implementation or the PHC
test suite (cite source; I could not fetch it from the permitted hosts), add RFC 8439 §2.8.2
as a ChaCha20-Poly1305 vector and the draft's A.3.1 HChaCha20 vector, RFC 2202 case 1–2 for
HMAC-SHA-1, and generate one end-to-end composition vector (fixed password, SK, salt,
nonces → expected file bytes) with an independent implementation (e.g. a short script using
libsodium/Python), recorded with its provenance, so layout and AD bytes are pinned.

Resolution: Partly fixed. Added from the permitted hosts: RFC 8439 §2.8.2 (`chacha20poly1305.json`), RFC 2202 cases 1–4 (`hmac-sha1.json`), draft-xchacha-03 §2.2.1 HChaCha20 (`hchacha20.json`; noted as not testable through the approved crates, informational). Extracted mechanically and checked against the fetched text. Rejected: an Argon2id vector without K/X and an end-to-end composition vector — no authoritative source is reachable and the planning environment has no independent implementation; nothing was invented. Recorded as OPEN-QUESTIONS #16, and F018/F007 re-derive keys and AD independently. The reviewer's note that the HChaCha20 vector is in A.3.1 is slightly off: it is in §2.2.1 of the draft.

### R-14 — minor — `crypto-spec.md` §3.1
NFKC output depends on the Unicode version of the `unicode-normalization` tables; a
dependency update that changes tables for newly assigned code points could change
`password_bytes` and lock a user out. No record of the normalization version exists in the
file. **Fix:** note it as accepted, or pin the crate version in `Cargo.lock` policy and add a
test with a few fixed normalizations (e.g. the two in F006 plus U+FB01 "ﬁ" → "fi",
U+00B5 → U+03BC) whose expected bytes are in the spec.

Resolution: Accepted and documented: CS §3.1 states the dependence on the `unicode-normalization` version in `Cargo.lock` and pins four fixed normalization results (spec'd expected bytes), tested in F006; OPEN-QUESTIONS #18.

### R-15 — minor — `requirements.md` REQ-LIF-008/009, `architecture.md` §2, F013
"Case-insensitive" and "lower-cased title" are undefined: `str::to_lowercase` (full Unicode
lowercase), simple case folding, or ASCII-only give different orderings and matches
(`İ`, `ß`, `Σ`). **Fix:** specify `str::to_lowercase()` on both sides and byte-wise
comparison of the results, then ID; add a non-ASCII test.

Resolution: Fixed. REQ-LIF-008/009 and architecture §2 define `str::to_lowercase()` with byte-wise comparison, then ID; F013 has a non-ASCII ordering/search test.

### R-16 — minor — `crypto-spec.md` §5.1, REQ-LIF-006
`revision` is `u64` starting at 1 and imports preserve arbitrary revisions (up to
`u64::MAX`, §8). `update` on revision `u64::MAX` overflows (panic in debug, wrap in
release). **Fix:** `update` returns `LimitExceeded` at `u64::MAX`; add a test via import.

Resolution: Fixed. CS §5.1, REQ-LIF-006 and architecture §2: `update` at revision `u64::MAX` returns `LimitExceeded`; tested via import in F018.

### R-17 — minor — `approved-deps.txt`, `OPEN-QUESTIONS.md` #1
- `bip39` (2.x) brings `bitcoin_hashes` (a second SHA-256 implementation) and, with default
  features, `unicode-normalization`/`serde/std`, to read a 2 048-entry constant. Acceptable,
  but the brief asks for as few dependencies as possible; vendoring the list as a data file
  is the alternative the spec already mentions. F016 says "default features off if
  available without them" — `alloc` pulls `unicode-normalization` anyway; state the exact
  feature set, and forbid the `rand` feature (REQ-SEC-007).
- `hex` is a 20-line function; consider dropping it.
- Add notes on features: `argon2` with `alloc` and `zeroize` (so its 64 MiB working memory
  is wiped); `chacha20poly1305` default features are sufficient; `argon2`'s `parallel`
  feature needs `rayon` (not approved), so p = 4 is computed sequentially — fine, but state it
  so a builder does not request rayon.
- Needed and present: argon2, chacha20poly1305, hkdf, sha2, sha1, hmac, zeroize,
  getrandom, serde, serde_json, unicode-normalization, rpassword, tempfile. No missing
  crate found. cargo-deny licence list covers the crates' licences (bitcoin_hashes CC0,
  unicode crates `Unicode-3.0`/MIT/Apache).

Resolution: Mostly fixed. `hex` removed from approved-deps (a small hex codec lives in the F004 base32 module); `bip39` notes: fewest features, never `rand`, feature set recorded in agent-notes (the exact feature list cannot be verified offline, so it is left to the builder under those constraints); `argon2` notes: `alloc`, `zeroize` if offered, not `parallel` (sequential lanes); `chacha20poly1305` defaults. Vendoring the word list was not adopted, to stay within the owner's earlier OPEN-QUESTIONS #1 decision.

### R-18 — minor — `architecture.md` §1 (workspace lints), `gate.sh`
Gate runs `clippy --all-targets -D warnings`. Enabling `clippy::unwrap_used`,
`indexing_slicing`, `panic` in `[workspace.lints]` applies to tests too ("for non-test code"
cannot be expressed there) and would fail every test that unwraps. **Fix:** say to use
`#![cfg_attr(not(test), deny(...))]` in each crate root, or `clippy.toml` with
`allow-unwrap-in-tests = true` etc.

Resolution: Fixed. Architecture §1 and F001: `#![cfg_attr(not(test), deny(clippy::unwrap_used, ...))]` in each crate root instead of `[workspace.lints]`; F001 acceptance checks tests may use unwrap.

### R-19 — minor — `features.json` dependencies
- F008 depends on F007 (keys); the item model needs only F002/F004. Harmless but orders
  work unnecessarily; F019 `--totp` needs `parse_totp_secret` from F017 (not a dependency of
  F019); either move `parse_totp_secret` into F004/F008 or add F017 to F019.
- F013 bundles six operations plus failure injection; likely fits a session, but split
  `list/search` out if the first attempt fails.
- F015/F016 acceptance rely on injecting a `RandomSource`, but the public signatures
  (`generate_password(o)`) take none. State an internal `generate_password_with(&mut dyn
  RandomSource, o)` that unit tests (not integration tests) use.
- F001 check: with zero dependencies every gate step is satisfiable (`cargo metadata`,
  empty `used` list handled by `|| true`, cargo-deny on an empty graph, forbid grep on
  `lib.rs`/`main.rs`). OK.

Resolution: Fixed. `parse_totp_secret`/`normalize_totp_secret` moved into F004 (F017 reuses them; F020 depends on F017/F004); F008 now depends on F003 and F004 instead of F007; `generate_*_with(&mut dyn RandomSource, ..)` declared `pub(crate)` for unit tests (architecture §2, F015/F016). F013 not split pre-emptively; the reviewer's fallback is noted for the driver if it fails. Because the CLI feature grew, F019 was split into F019/F020.

### R-20 — minor — ambiguities that change bytes or behaviour (not security-relevant)
- JSON serialization: key order, whitespace and escaping of the item plaintext and export
  payload are unspecified (`serde_json::to_vec` of a struct in the table's field order is
  the obvious choice; say so). Fixed key order also makes layout tests stable.
- `uniform(n)`: how a `u64` is assembled from OS bytes (endianness) is unspecified; only
  matters for stubbed tests (`from_be_bytes`, say so).
- Import: whether the payload `vault_id` must match, and whether the export password is
  subject to the 8-character minimum on *import* (should not, like unlock). `exported_ms`
  semantics. Number of items on import vs the 100 000 limit (see R-09).
- Secret key file: leading whitespace, BOM, a newline between groups; "32+ chars" in
  architecture §5 vs the exact 58-character form in CS §3.2. Say: trim ASCII whitespace at
  both ends, then `from_text` (which already ignores spaces and `-`).
- `update`: does `--url` append or replace? Which fields can be cleared? `--generate`
  on `add-login` stores a password the user never sees — say whether it is printed
  (it should be only with `--show-secrets`) or readable later via `get --show-secrets`.
- Passphrase "capitalize": ASCII upper-case of the first letter of each word.
- `Vault::set_clock` is public API (test hook); make it `#[doc(hidden)]` or `cfg(test)`/a
  non-default feature so a caller cannot back-date timestamps. The brief says "do not build
  hooks" for out-of-scope features; this one is for tests only, hence minor.

Resolution: Fixed item by item: JSON writing is compact fixed key order (CS §7); `uniform` uses `from_be_bytes`; import ignores payload `vault_id`, no password minimum on import, `exported_ms` = vault clock, item-count limit (CS §8, §9); key-file rule is trim ASCII whitespace then `from_text` (CS §3.2, architecture §5); `update --url` replaces, clear flags listed, `--generate` is not printed without `--show-secrets`; capitalize is ASCII upper-case of the first byte; `set_clock` is `#[doc(hidden)]` and only under `cfg(test)` or feature `test-hooks`.

### R-21 — minor — `architecture.md` §4 secrets
`Zeroizing<String>` zeroizes the final allocation only; `String` growth (push, reserve) and
`serde_json` output buffers leave copies. The spec already admits serde_json; extend the
admission to `String` growth and `Vec` reallocation, and require `with_capacity` for known
sizes and `Zeroizing<Vec<u8>>` for the serialized plaintext before encryption (the
serialization side of §4.5 only mentions parsing).

Resolution: Fixed. Architecture §4.5 admits `String`/`Vec` growth copies and requires `with_capacity` and a `Zeroizing<Vec<u8>>` for the serialized plaintext; REQ-SEC-001, CS §7 and the threat model residual risk 1 updated.

---

## Areas reviewed and found sound

- **Nonces:** every encryption (VK wrap, IK wrap, body, trailer, export) draws a fresh
  192-bit OS-random nonce; header rewrites (create, password change, rotation) and every
  save get new nonces; no counter or derived nonce anywhere. Volumes are far below the
  birthday bound.
- **Key separation:** MK wraps only VK; K_iw and K_fa are HKDF-Expand outputs with distinct
  labels from VK; IK per revision; export key from a separate password and salt. Labels are
  distinct and prefix-free.
- **Associated data:** all ADs are `label ‖ fixed-length fields` and I recomputed the stated
  lengths (25+82, 20+32, 44-byte item suffix) and every field offset in §5, §5.1 and §8;
  they are consistent (header 130, record fixed part 126, trailer 40, export header 74).
- **Swap/replay/rollback/truncation:** per-record AD (vault, item, revision, schema,
  format) plus the whole-file trailer keyed by K_fa closes swap, single-record rollback,
  deletion, insertion and truncation. Whole-file rollback is correctly declared out of
  scope. I found no unauthenticated byte that influences decryption (record_count and
  lengths are covered by the trailer hash).
- **KDF parameters / downgrade:** parameters, versions, flags are in the header AD of
  `wrapped_vk`; bounds are checked before Argon2; no path reads an older format. Defaults
  (64 MiB, t = 3, p = 4) are exactly RFC 9106 §4's second recommended option and within the
  brief's iOS ceiling.
- **Oracles:** structural errors precede any key use; every post-key failure is a single
  `Authentication`; wrong password and wrong secret key are indistinguishable.
- **Randomness:** OS CSPRNG only, failure is an error, `uniform(n)` rejection threshold
  `2^64 mod n` is correct, Fisher–Yates is specified.
- **`forbid(unsafe_code)`:** nothing in the spec requires `unsafe` (no mlock, atomic
  rename/fsync/0600 via std). The spec says so for mlock.
- **Coverage:** every REQ id in `requirements.md` appears in at least one feature (checked
  mechanically); every item of the brief's pilot scope maps to requirements; nothing from the
  brief's out-of-scope list is built (the `Clock`/`RandomSource` test seams are the only
  additions, see R-20).
- **F001 vs gate:** passes as specified (R-19).

## Test vector verification

Sources fetched on 2026-11-06 from `www.rfc-editor.org` (RFC 9106, 5869, 4231, 4226, 6238,
4648) and `datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03`. Method: the text was
extracted, spaces/colons/page headers removed, and each JSON hex value was searched for in
the source; table-shaped sources (TOTP, HOTP, base32) were compared row by row.

| file | result |
|---|---|
| `argon2id.json` | password, salt, secret, associated data, tag, m/t/p/version: identical to RFC 9106 §5.3 |
| `hkdf-sha256.json` | A.1, A.2, A.3: IKM, salt, info, PRK, OKM identical (empty salt/info in A.3 correct) |
| `xchacha20poly1305.json` | key, nonce, AAD, plaintext, ciphertext, tag identical to draft-03 A.1 |
| `hmac-sha2.json` | cases 1, 2, 3, 4, 6, 7: key (131 bytes for 6 and 7), data, HMAC-SHA-256 and -512 identical to RFC 4231; case 5 omission is as documented |
| `hotp.json` | secret, 10 HMAC-SHA-1 values, 10 truncated decimals and 10 HOTP values identical to RFC 4226 App. D |
| `totp.json` | all 18 rows (time, T hex, TOTP, mode) identical to the RFC 6238 App. B table (`diff` empty); the 32- and 64-byte seeds equal the RFC's Appendix A reference seeds (`seed32`, `seed64`) |
| `base32.json` | 7 rows identical to RFC 4648 §10 |

Differences found: **none**. Not verifiable / not provided: any Argon2id vector without K/X,
SHA-1/SHA-256 stand-alone, HMAC-SHA-1 beyond HOTP, HChaCha20 intermediate values, and all
onlypassword compositions (see R-13). The XChaCha20 vector is from an Internet-Draft, not an
RFC, as the spec states.

---

# Phase 2 revision (planner)

Scope: the owner appended "Phase 2: desktop app" to `spec/brief.md`; the pilot (F001–F023) is built and
frozen. This revision only extends the spec. No reviewer findings for phase 2 existed when it was written; the 21 findings
above (R-01…R-21) were already resolved and are untouched.

## What changed

- `requirements.md`: new groups `IDX` (3), `KFL` (3), `GUI` (31, including the negative non-negotiables REQ-GUI-070…077),
  `LOCK` (6), `CLIP` (6), `CFG` (8). Existing requirements are unchanged. Every brief scope item 1–9 and each non-negotiable maps to at
  least one requirement (open/create → GUI-001..003; lock → LOCK; browse → GUI-010..012; edit → GUI-020..023; secrets on screen →
  GUI-030..033, CLIP; TOTP → GUI-040/041; generator → GUI-050/051; maintenance → GUI-060..064; settings → CFG; key/plaintext in secret types →
  GUI-072; no logging → GUI-070; no network → GUI-071; unsafe/deps → GUI-073; portability → GUI-074; headless tests → GUI-075).
- `architecture.md`: new part 7 (`crates/onlypassword-desktop`): core additions, module layout, `AppState`/`Session`/`Action`, secrets in the UI
  (`SecretBuf`, `TextBuffer` adapter, masking, reveal set), idle timer, clipboard service, config module, error surface, portability rules,
  desktop test strategy. §§1–6 and the CLI are unchanged.
- `threat-model.md`: new part 7–9 (desktop assets/attackers, 16 threats with requirement IDs, plain out-of-scope list, residual risks 7–12).
- `approved-deps.txt`: added eframe, egui, egui_kittest, arboard, rfd, directories with feature restrictions; widened the comments of
  serde, serde_json, sha2, zeroize and tempfile to include the desktop crate; listed what the planner could not verify.
- `features.json`: F001–F023 byte-for-byte unchanged; F024–F037 appended (14 features): skeleton (cross-target gate), core index, core key
  file, config, session/open/create/lock, idle lock + settings, browse, clipboard, TOTP, edit, generator, maintenance, hardening, end-to-end.
  A mechanical check confirms that every REQ id in `requirements.md` appears in at least one feature and `depends_on` only names earlier ones.
- `OPEN-QUESTIONS.md`: items 19–30. `crypto-spec.md` and `spec/vectors/` are unchanged: the GUI needs no format change.

## Not resolved / for the reviewer to look at

- **Unverified crate details** (no registry access while planning): exact feature names of eframe, arboard and rfd, whether
  `default-features = false` yields a working Linux build, whether egui_kittest needs `accesskit`, whether the resolved graph passes
  cargo-deny, and whether arboard has "exclude from history" setters on each OS. F024/F031 tell the generator to check and record.
- **Cross-target `cargo check` of the GUI graph** (`rfd`, `arboard`, `eframe` for windows-msvc and apple-darwin) is assumed to work; if a crate
  fails to check there, the generator is told to raise a spec issue rather than add a dependency.
- **Core file helper duplication**: the CLI keeps its own key-file reader (pilot frozen); the owner may want a later refactor.
- **egui text caches** cannot be zeroized by the app (residual risk 8); only mitigated by clearing egui memory.
- **Blocking Argon2 and file dialogs** on the UI thread (residual risks 9, 10).
- F026's read-back comparison wants a constant-time helper in the core; if the core already has one the generator should reuse it.
