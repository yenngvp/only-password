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
