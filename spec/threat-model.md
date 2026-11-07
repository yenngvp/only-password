# Threat model

Scope: the pilot (Rust core and CLI) for one owner on one or more devices. No network,
no sync, no UI. Requirement IDs refer to `requirements.md`; "CS" is `crypto-spec.md`.

## 1. Assets

| ID | Asset | Where it lives |
|---|---|---|
| A1 | Item contents (passwords, notes, TOTP secrets, custom fields) | Encrypted in the vault file; plaintext only in memory while unlocked |
| A2 | Item metadata (titles, usernames, URLs) | Encrypted in the vault file (everything in the item plaintext) |
| A3 | Master password | The owner's head; briefly in memory during unlock |
| A4 | Secret key (256 bit) | The owner's devices (CLI: a key file) and the owner's written copy; never in the vault file or exports |
| A5 | Vault key, item keys, master key, subkeys | Memory only while unlocked; wrapped on disk |
| A6 | Integrity of the item set and of each item | Vault file |
| A7 | Export file contents | Export file, protected by a separate export password **and** the secret key |
| A8 | Generated passwords | Memory, then the owner's vault |

Visible to anyone holding the vault file (accepted): file size, number of records (record
count and each record's length, hence approximate item size), item IDs, revision numbers,
the vault ID, KDF parameters and salt, format version. Item titles and usernames are **not**
visible.

## 2. Attackers

| ID | Attacker | Capabilities | Cannot |
|---|---|---|---|
| ATK-1 | **Stolen vault data**: obtains the vault file or backup copies (cloud backup, stolen disk, lost laptop powered off) | Read and offline-attack the file, unlimited compute | Learn the secret key |
| ATK-2 | **Stolen file + weak password** | As ATK-1 and guesses passwords | Brute-force 256 bits of secret key |
| ATK-3 | **Active file tamperer**: can modify, truncate, swap, replay or delete bytes of the vault or export file at rest or in transit, and feed it to the owner's app | Hand-craft malformed or hostile files, including huge declared lengths and parameters | Forge an AEAD tag without the keys |
| ATK-4 | **Hostile import file**: a file the owner is tricked into importing | Same as ATK-3 for export files | Know the export password or the secret key |
| ATK-5 | **Local unprivileged user** on a shared machine | Read files the owner's permissions allow | Read 0600 files of another user |
| ATK-6 | **Observer of operating-system artefacts** (swap, crash dumps, shell history, process listings, env) | Read artefacts after the fact | Read live process memory |
| ATK-7 | **Crash or power loss** (not an attacker, a hazard) | Interrupt a write at any instant | — |

## 3. Trust boundaries

1. **Owner ↔ core**: the master password and secret key enter through function arguments;
   plaintext leaves only as return values the caller asked for.
2. **Core ↔ filesystem**: everything read from disk is untrusted until the AEAD tags
   verify; everything written is ciphertext, except header fields that are authenticated.
3. **Core ↔ OS random source**: trusted to be a CSPRNG; failure is fatal to the operation.
4. **CLI ↔ terminal/stdin**: prompts are read without echo; nothing secret crosses argv or
   the environment.
5. **Build ↔ dependencies**: only crates in `approved-deps.txt`, checked by cargo-deny.

## 4. Threats, mitigations, requirements

| ID | Threat | Mitigation | Requirements |
|---|---|---|---|
| T-OFFLINE | ATK-1/2: offline attack on the vault file | Master key needs both Argon2id(password) and the 256-bit secret key through HKDF; without the secret key the search space is ≥ 2^256 regardless of password strength; Argon2id memory-hard for the password half | REQ-KEY-001, -002, -003, -008 |
| T-WEAKPW | Weak or empty master password | Minimum length 8 (cheap sanity floor); the secret key carries the entropy | REQ-KEY-007 |
| T-KDFDOWN | ATK-3 lowers Argon2 cost in the header, or ATK-3 sets huge cost to exhaust the owner's device | Header authenticated through `wrapped_vk` AD; parameters bounds-checked *before* Argon2 runs; floor and ceiling in CS §10 | REQ-KEY-004, REQ-ENC-005, REQ-FMT-003 |
| T-SWAP | ATK-3 swaps item records between IDs or vaults | Per-record AD binds vault ID, item ID, revision, schema, format | REQ-ENC-002, REQ-ENC-003 |
| T-ROLLBACK-ITEM | ATK-3 replaces an item with an older valid version, or deletes or adds records | Revision bound in AD; file trailer over SHA-256 of all bytes, keyed by `K_fa` | REQ-ENC-002, REQ-ENC-004 |
| T-ROLLBACK-FILE | ATK-3 restores a complete older file copy | **Not mitigated** (needs external state). Out of scope; noted in OPEN-QUESTIONS | — |
| T-REINTERP | ATK-3 makes a reader parse bytes with a different meaning (old/new format, different schema, export as vault) | Versions and magic authenticated; strict equality on versions; unknown fields rejected; no fallback paths | REQ-FMT-002, -007, REQ-ITM-004, REQ-SEC-008 |
| T-NONCE | Nonce reuse destroying AEAD security | 192-bit random nonce per encryption, never derived | REQ-ENC-001 |
| T-KEYREUSE | One key compromise exposing everything | Per-item keys, subkeys by HKDF labels, VK separate from MK; rotation re-encrypts all | REQ-HIER-001..003, REQ-LIF-011 |
| T-PWCHANGE | Old password still works after change | New salt and re-wrap; old tag fails. **Not** mitigated: someone who knew the old password, has the secret key and holds a past header copy still knows `VK`; `passwd --rotate` (password change plus vault-key rotation in one atomic write) is the remedy | REQ-LIF-010, -013, -015, REQ-CLI-008 |
| T-PARSE | ATK-3/4: crafted files cause panic, out-of-memory or hang | Bounds-checked parsing, limits on counts and lengths checked before allocation, no `unsafe`, deterministic robustness tests | REQ-FMT-003, REQ-EXP-006, REQ-SEC-004, REQ-SEC-005 |
| T-IMPORT | ATK-4: hostile or partial import corrupts the vault | Export authenticated end to end; all-or-nothing, ID conflicts rejected; one atomic write | REQ-EXP-003, -004, REQ-LIF-012 |
| T-EXPLEAK | Export reveals keys, or is attackable with the password alone | Export contains no SK, VK or item keys; its key combines the export password with the secret key (the brief's two-secret property), Argon2id with the same floor as the vault, fresh KDF salt | REQ-EXP-001, -005, REQ-KEY-007 |
| T-OVERWRITE | Export or init clobbers the vault, a key file or a racing file | Export rejects the vault path (canonicalized); `init` writes and reads back the key file before creating the vault; vault creation uses `hard_link`, never `rename` | REQ-EXP-001, REQ-FMT-008, REQ-CLI-003 |
| T-CRASH | ATK-7: torn or half-written vault | Temp file + fsync + rename (create: `hard_link`) + directory fsync; temp removed on failure | REQ-FMT-004, -006, -008, REQ-LIF-012 |
| T-FILEPERM | ATK-5 reads the vault or key file | Vault created 0600; key file created 0600 exclusively (CLI) | REQ-FMT-005, REQ-CLI-003 |
| T-MEMORY | Secrets linger in memory after use | Zeroize on drop for all key/plaintext types; `lock` consumes the vault; residual limits below | REQ-SEC-001, REQ-LIF-003 |
| T-LOGLEAK | ATK-6: secrets in logs, errors, panics, Debug output, argv, environment | No secret in errors/Debug/logs; CLI takes secrets (including notes and hidden field values) only via no-echo prompt, stdin or a notes file; `get` hides password, notes, TOTP secret and hidden fields by default | REQ-SEC-002, -003, REQ-CLI-002, -005 |
| T-ORACLE | Error messages reveal whether password or secret key was wrong, or which byte was altered | Single `Authentication` error; no detail in messages | REQ-KEY-005 |
| T-RNG | Weak or biased randomness for keys, nonces, generated passwords | OS CSPRNG only, failure is an error, rejection sampling | REQ-GEN-003, -005, REQ-SEC-007 |
| T-SUPPLY | Malicious or vulnerable dependency | Allowlist, cargo-deny (advisories, licences, sources), few widely used crates | REQ-BLD-001 |
| T-HOMEMADE | Invented cryptography | Only the primitives of CS §2 in the compositions of CS §3–§8 | REQ-SEC-007, REQ-HIER-003 |
| T-TOTP | Wrong or non-RFC one-time codes locking the owner out | RFC 4226/6238 vectors as KATs; secret validation | REQ-TOT-001..005 |
| T-UNICODE | Password typed differently on two platforms fails to unlock | NFKC normalization before Argon2 | REQ-KEY-002 |
| T-ENTROPY | Generator produces predictable or biased passwords | OS RNG, unbiased `uniform`, Fisher–Yates shuffle | REQ-GEN-001..005 |

## 5. Out of scope (stated plainly)

- **Malware, a debugger, or a root/admin attacker on an unlocked device**, keyloggers,
  screen capture, clipboard sniffing: a process that can read memory or keystrokes while the
  vault is unlocked defeats any local password manager.
- **Cold-boot / memory forensics** and swap or hibernation files on the owner's machine:
  zeroization is best effort (see residual risks); the core does not `mlock` (that needs
  `unsafe`/platform code, forbidden here).
- **Whole-file rollback** to an older, valid copy of the vault (T-ROLLBACK-FILE).
- **Metadata visible in the file**: record count, record sizes, revisions, timing of file
  changes. Sizes are not padded.
- **Rubber-hose, coercion, loss of the secret key** (there is no recovery by design:
  REQ-KEY-008), loss of the master password, shoulder surfing.
- **Side channels** in the underlying crates (timing, cache) beyond what those crates
  guarantee.
- **Concurrent writers**: two processes writing the same vault at once; last atomic rename wins.
- **Network, sync, multi-device conflict, sharing, biometrics, OS keychain, browser
  integration, passkeys, FFI**: not built (brief).
- **Quantum attackers**: 256-bit symmetric keys give a 128-bit margin against Grover; no
  public-key crypto is used.
- **Weak user passwords**: only an 8-character floor is enforced; strength rests on the
  secret key.

## 6. Residual risks accepted

1. `serde_json`, `String` growth and `Vec` reallocation may leave plaintext copies in freed
   memory that are not zeroized, on parsing and on serialization (architecture.md §4.5).
2. The CLI's stdin mode and `--show-secrets` print secrets to the terminal by design.
3. The secret key file is only as safe as the owner's device account; stolen file + stolen
   key file + weak password lets ATK-2 attack the password offline.
4. The export is protected by the export password *and* the secret key; someone holding the
   export, the secret key (for example the same key file) and a weak export password can
   still attack the password offline. The owner is told to choose a strong one
   (OPEN-QUESTIONS #8).

---

# Phase 2 — desktop application

Sections 1–6 apply unchanged to the core and CLI. This part adds the desktop app
(`onlypassword-desktop`, architecture.md §7). The app is used by one person on Windows, macOS or
Linux, locally, with no network.

## 7. Desktop threats

### 7.1 Additional assets and attackers

| ID | Item | Note |
|---|---|---|
| A9 | The clipboard contents after a copy | Plaintext password or field value, readable by any process of the user's session while it lasts |
| A10 | What the window shows | Passwords, notes, TOTP codes, depending on what is revealed |
| A11 | The config file | `config.json`: timeouts, theme, last vault path; no secrets by construction |
| ATK-8 | **Passer-by or idle-machine observer**: the owner leaves the machine unlocked and unattended | Looks at the screen, uses the keyboard and mouse |
| ATK-9 | **Clipboard consumer**: clipboard managers, history features, cloud clipboard sync, other apps reading the clipboard | Read what is on the clipboard at any time while it is there |
| ATK-10 | **Hostile file chooser target**: a symlink or pre-existing file placed where the owner is persuaded to save or open | Make the app write over or read from an unexpected place |

### 7.2 Threats, mitigations, requirements

| ID | Threat | Mitigation | Requirements |
|---|---|---|---|
| T-CLIPLINGER | ATK-9: a copied password stays on the clipboard indefinitely | Timed clear (default 30 s, configurable 5–600 s) after the digest of the clipboard text still matches what the app copied; clipboard left alone if the user has since copied something else; clear on lock and on exit | REQ-CLIP-001..004, REQ-CFG-008 |
| T-CLIPHIST | ATK-9: clipboard history or cloud sync records the copy | Best effort: the entry is marked "sensitive / exclude from history" where the clipboard crate supports it (Windows, macOS, Linux managers that honour hints). **Not mitigated** where the platform or a manager ignores the hint (residual risk 7); an entry that reached a history cannot be recalled | REQ-CLIP-001 |
| T-CLIPLEAK | The app itself keeps the copied text, or reads the clipboard more than needed | Only a SHA-256 digest is retained; the clipboard is read once, at the deadline, only to compare; the copied text exists only as the argument of the backend call; the digest is dropped at lock | REQ-CLIP-001, -006, REQ-LOCK-003 |
| T-SCREEN | ATK-8: a password is visible on screen longer than needed | Masked by default with a fixed-length placeholder; reveal per field; re-mask on lock, on selection change and on leaving the item; the unlock screen shows no item titles | REQ-GUI-030..032, REQ-LOCK-001, -006 |
| T-IDLE | ATK-8: the owner walks away with the vault unlocked | Idle lock (default 300 s, 10 s–24 h), reset by any input, evaluated on every tick even if a modal or a native dialog was open; manual lock; the timer uses a monotonic clock | REQ-LOCK-001, -002, -005, -006 |
| T-LOCKMEM | Plaintext or keys remain in the app's state after a lock | `Session` (vault, secret key, rows, detail, draft) is dropped and zeroized on lock; form buffers are `SecretBuf`s emptied on submit/cancel/lock; the generated value and reveal set are cleared; `is_clean()` and a Debug sentinel scan are tested; egui memory is cleared | REQ-LOCK-003, -004, REQ-GUI-033, -072 |
| T-UICOPY | Secrets copied into long-lived plain strings by the UI toolkit | Core secret types and `SecretBuf` only; text editing through a `TextBuffer` adapter over the zeroizing buffer; no secret in widget ids, labels or tooltips. **Not fully mitigated**: egui's own caches (undo history, galley cache) may keep copies of edited or revealed text until cleared or evicted (residual risk 8) | REQ-GUI-030, -033, -072 |
| T-UILOG | ATK-6: field values reach logs, panics, `Debug` output or accessibility labels | No print/log macros in the crate (source-scan test); redacted `Debug` on `AppState`, `Session`, `Draft`, `SecretBuf`; user-facing messages come from a closed set of fixed strings; no `unwrap`/`expect`/indexing outside tests | REQ-GUI-070, -073, REQ-SEC-002, -003 |
| T-CFGFILE | ATK-5/ATK-3: the config file leaks secrets or is hostile (huge, malformed, symlinked, wrong types) | Struct with exactly five keys, nothing else is serializable into it; bounded read (4 KiB), strict parse, range-checked; invalid file means defaults plus a fixed notice and is never trusted; written 0600 atomically; no key-file path stored. The last vault path reveals only where a file lives | REQ-CFG-001..005, REQ-GUI-072 |
| T-FILEDIALOG | ATK-10: a save dialog target is a symlink or an existing file | The app passes the chosen path unchanged to the core: vault saves follow symlinks and replace the target (REQ-FMT-009); export refuses the vault itself, canonicalized (REQ-EXP-007); the secret-key file is created exclusively (an existing file or symlink fails, never overwritten, REQ-KFL-002); key files are read only through `keyfile::read` (bounded, parsed, never echoed); vault creation never replaces an existing file (REQ-FMT-008). An *export* to an existing path is replaced by the core's atomic write, as in the CLI (the OS dialog asks the user first) | REQ-GUI-002, -062, -064, REQ-KFL-001..003, REQ-EXP-007 |
| T-DIALOGBLOCK | A native dialog blocks the UI loop so the idle timer cannot fire | The timer is re-evaluated on the first tick after the dialog returns and locks before any other action; while a dialog is open the window is occupied by the dialog | REQ-LOCK-005 |
| T-GUIPARSE | A hostile vault, export or key file crashes the app | Same bounds-checked core parsers as the CLI; all errors become fixed messages; the app has no `unwrap`/`expect`/indexing outside tests and the state machine never panics on any action sequence (randomised action test) | REQ-SEC-004, REQ-GUI-073, -075 |
| T-GUIORACLE | The unlock screen tells whether the password or the key file was wrong | One `Authentication` message for both; structural errors (missing/unreadable key file, corrupt vault) are different, fixed messages that need no key | REQ-GUI-003, REQ-KEY-005 |
| T-GUINET | The app contacts a network (update check, telemetry, crash report) | No such code; no network crate in the dependency graph (denylist test of `Cargo.lock` and a source scan for `std::net`); cargo-deny sources limited to crates.io | REQ-GUI-071, REQ-BLD-001 |
| T-GUIPORT | A platform-specific build break or a platform path that was never exercised | `cfg`-gated platform code; the gate runs `cargo check` for `x86_64-pc-windows-msvc` and `aarch64-apple-darwin`; Linux path fully tested. Running on Windows and macOS is a manual step | REQ-GUI-074 |
| T-KDFTEST | Test-only fast KDF parameters leak into a release build | The desktop crate enables `insecure-fast-kdf` and `test-hooks` only in `[dev-dependencies]`; `AppDeps::kdf` defaults to `KdfParams::DEFAULT`; the real constructor never takes a smaller value | REQ-GUI-074, REQ-KEY-004 |

## 8. Out of scope for the desktop app (stated plainly)

- **Malware, a debugger or an administrator on the unlocked desktop**, keyloggers, input
  injection and anything else that runs as the owner while the vault is unlocked.
- **Screen capture, screen sharing and remote-desktop viewers** by other processes or the
  window manager, and shoulder surfing: masking and idle lock reduce exposure, nothing
  prevents capture of what the window shows.
- **Other processes reading the clipboard** during the copy window, and clipboard managers that
  ignore the "sensitive" hint.
- **OS keychain, biometrics, secure enclave / TPM** integration; no OS-level protection of the
  secret-key file beyond file permissions (0600 on Unix; on Windows the default ACL of the
  user's folder).
- **Swap, hibernation files and crash dumps**: no `mlock`, no `unsafe`; zeroization is best
  effort (section 6, residual risk 1).
- **Sync, networking, auto-update, installers, code signing, autofill, system tray, multiple
  windows, localization** (brief: out of scope for phase 2).
- **Accessibility tooling that reads the widget tree** (screen readers): masked fields expose
  only the placeholder, revealed fields expose what is shown.

## 9. Residual risks accepted (desktop)

7. The clipboard holds the plaintext for up to the clipboard timeout (30 s by default) and may be
   captured by history or sync features that ignore the sensitive hint.
8. egui and its text stack may keep copies of revealed or edited text (galley cache, edit state,
   undo history) beyond the point where the app's own buffers are zeroized; the app clears egui
   memory at lock and form submission but cannot zeroize what egui or the allocator keeps.
9. While a native file dialog is open the UI thread is blocked, so the idle lock fires only after it
   returns.
10. Unlock runs Argon2id on the UI thread (about a second with default parameters); the window is
    unresponsive meanwhile.
11. A TOTP code is shown in plain text while an item is open (like any authenticator); the TOTP
    *secret* is masked.
12. The secret key stays in memory, as a core `SecretKey`, for the whole unlocked session because
    export and password change need it; it is zeroized on lock.
