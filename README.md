# onlypassword

A personal, cross-platform password manager, built as a single Rust core with
thin native UIs planned on top. This repository holds the **pilot**: the core
library (`onlypassword-core`) and a small command-line tool (`onlypassword`)
that exercises it.

The code under `crates/` is written by an unattended agent pipeline, one feature
at a time, against a frozen specification in `spec/`. See
[How this repo is built](#how-this-repo-is-built).

## Status

All 23 pilot features have passed the gate and the evaluator, including the
end-to-end definition-of-done test (create a vault, add items, lock, unlock,
read back, change the master password, export, import into a fresh vault).

Out of scope for the pilot, by design: sync, networking, GUIs, biometric
unlock, OS keychain integration, browser extensions, passkeys, sharing, account
recovery, SQLite, FFI bindings and fuzzing infrastructure.

## Security model in one page

- **Two unlock factors.** The master password (NFKC-normalized, then Argon2id)
  and a random 256-bit *secret key* that lives only in a key file on the user's
  devices, never in the vault. A stolen vault file is useless without both.
- **Key hierarchy.** HKDF-SHA-256 combines the Argon2id output and the secret
  key into the master key. The master key wraps a random vault key. The vault
  key derives an item-key-wrapping key and a file-authentication key. Each item
  revision gets a fresh random item key.
- **Everything is authenticated.** XChaCha20-Poly1305 everywhere. The KDF
  parameters and header are associated data of the vault-key wrap. Each item
  record is bound to vault ID, item ID, revision, item schema and format
  version, so records cannot be swapped between items or vaults, rolled back,
  or reinterpreted. A trailer over the whole file catches deleted or replaced
  records.
- **No downgrade.** Unknown or older-than-supported format versions are errors.
- **Primitives only.** Argon2id (RFC 9106), HKDF-SHA-256 (RFC 5869),
  XChaCha20-Poly1305, and HMAC-SHA-1/256/512 for TOTP only. No public-key
  cryptography. Argon2id defaults to 64 MiB so a vault can later be unlocked
  inside an iOS AutoFill extension.
- **Hygiene.** `#![forbid(unsafe_code)]` in every crate. Secrets are zeroized
  on drop and never appear in `Debug`, logs or error messages. Parsers return
  errors on hostile input and never panic. Vault files are written atomically.

The authoritative details are in `spec/crypto-spec.md` and
`spec/threat-model.md`. The one documented gap: replacing the *entire* vault
file with an older copy that the same password and key unlock is not
detectable without external state.

## Building and testing

Requires a stable Rust toolchain. Argon2 is built optimized even in dev
profile, so tests stay fast.

```sh
cargo build --release
cargo test --workspace --all-features
```

The `--all-features` flag enables `insecure-fast-kdf` and `test-hooks` on the
core, which the integration tests need. Neither feature is ever enabled by the
CLI crate. Known-answer tests load their vectors from `spec/vectors/`.

The binary ends up at `target/release/onlypassword`.

## Using the CLI

Global options come before the command. `--vault <PATH>` and
`--secret-key-file <PATH>` are required for everything except `generate`.
Secrets are never passed as arguments. They are prompted with no echo, or, with
`--stdin`, read one per line from standard input for scripting.

```sh
export OP="onlypassword --vault ~/vault.op --secret-key-file ~/vault.key"

# Create a vault. Writes the key file first, then the vault; never overwrites.
$OP init

# Add items. Prompts: master password, then item password (and TOTP secret, notes,
# hidden field values if requested).
$OP add-login --title "Example" --username alice --url https://example.com --totp
$OP add-login --title "Generated" --username bob --generate
$OP add-note  --title "Recovery codes" --notes

# Read.
$OP list
$OP search example
$OP get <ID>                    # secrets shown as <hidden>
$OP get <ID> --show-secrets
$OP totp <ID>                   # current code and seconds remaining

# Change.
$OP update <ID> --new-password --url https://new.example.com
$OP delete <ID>

# Keys.
$OP passwd                      # change master password
$OP passwd --rotate             # also rotate the vault key, in one atomic write
$OP rotate-key                  # rotate the vault key only

# Backup and restore. The export is encrypted with its own password plus the
# vault's secret key. Restore into a fresh vault needs the old key file too.
$OP export --out backup.opx
onlypassword --vault ~/new.op --secret-key-file ~/new.key init
onlypassword --vault ~/new.op --secret-key-file ~/new.key \
  import --in backup.opx --source-secret-key-file ~/vault.key

# Generators need no vault.
onlypassword generate password --length 24 --exclude-ambiguous
onlypassword generate passphrase --words 6 --separator - --capitalize --digit
```

Item flags shared by `add-login`, `add-note` and `update`: `--title`,
`--username`, `--url` (repeatable), `--notes` or `--notes-file`, `--totp` with
`--totp-algorithm sha1|sha256|sha512`, `--totp-digits`, `--totp-period`,
`--field NAME=VALUE` (non-hidden), `--hidden-field NAME` (value prompted).
`update` leaves unmentioned fields unchanged and has `--clear-username`,
`--clear-urls`, `--clear-notes`, `--clear-totp`, `--clear-fields`.

Exit codes:

| code | meaning |
|---|---|
| 0 | success |
| 1 | error (not found, corrupt, unsupported version, I/O, ...) |
| 2 | usage error |
| 3 | authentication failed (wrong password, wrong key, or tampered data) |

Keep the key file backed up separately from the vault. There is no account
recovery: losing either the master password or the key file loses the vault.

## Repository layout

```
spec/            the target. brief.md is the owner's intent; the rest was produced
                 by the planner and frozen on approval (requirements, threat model,
                 crypto spec, architecture, features, approved deps, test vectors)
crates/
  onlypassword-core/   library: secrets, rng, base32, crypto, item model, file
                       format, sealing, storage, vault, export, generator, totp
  onlypassword-cli/    the `onlypassword` binary and its end-to-end tests
pipeline/        the harness: driver, container images, gate, prompts, state
agent-notes/     hand-off notes one agent session leaves for the next, plus
                 spec-issues.md (ambiguities found) and dep-requests.md
```

## How this repo is built

Claude agents build the code unattended inside a machine-enforced boundary.
The owner writes `spec/brief.md`; a planner expands it into the rest of
`spec/`, which the owner approves once and which is then frozen. For each
feature in `spec/features.json`:

1. A **generator** agent works in a private clone on `agent/<feature>`, in a
   container with no outbound network except an allowlisted proxy.
2. The **driver** on the host imports the commits and rejects any change to
   protected paths (`spec/`, `pipeline/`, `.claude/`, `.github/`, `CLAUDE.md`).
3. The **gate** (`pipeline/gate.sh`) checks: direct dependencies are in
   `spec/approved-deps.txt`, `cargo-deny` advisories/licenses/sources,
   `#![forbid(unsafe_code)]` in every crate root, no `#[ignore]`d tests,
   `cargo fmt`, `cargo clippy -D warnings`, and `cargo test`.
4. An **evaluator** agent with fresh context reads the diff against the spec
   and writes a verdict.
5. The driver merges into `main` and records the result in `pipeline/state/`.

`pipeline/README.md` has the setup and run commands, and `CLAUDE.md` has the
rules every agent follows. `pipeline/state/PROGRESS.md` is the per-feature log
with the evaluator's summary of each merge.

## License

No license file is present yet. All rights reserved until one is added.
