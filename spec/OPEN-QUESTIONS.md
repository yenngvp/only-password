# Open questions for the owner

Each item states the default already applied in the spec, and why. Change any of them by
giving feedback to the planner; nothing here blocks the build.

1. **Passphrase word list.** *Default:* the BIP-39 English list (2 048 words, 11 bits/word)
   through the `bip39` crate (CC0, ~19 M downloads); default 7 words ≈ 77 bits. *Why:* the
   EFF large list (7 776 words) could not be fetched from the allowed hosts, and the only
   crate carrying it, `eff-wordlist`, is AGPL-3.0, which `pipeline/deny.toml` rejects. The
   BIP-39 list is curated (unique 4-letter prefixes) but has fewer bits per word. Decide
   whether to accept it or to approve vendoring a different list as a data file later.
2. **Password normalization.** *Default:* NFKC, then UTF-8, before Argon2id; minimum 8
   Unicode scalar values. *Why:* the same password must unlock on macOS, iOS, Windows and
   Linux whatever form the keyboard produces. Cost: one extra crate
   (`unicode-normalization`, already pulled in by `bip39`). A length floor of 8 is only a
   sanity check; the secret key carries the entropy.
3. **Argon2id defaults.** *Default:* m = 64 MiB, t = 3, p = 4 (RFC 9106 second recommended
   option; the brief's ceiling for the default). Accepted range for creation and on files:
   m 19 MiB (19 456 KiB) to 256 MiB, t 2–16, p 1–16; tests use lower values only through
   `cfg(test)` or the non-default `insecure-fast-kdf` feature. *Why:* fits an iOS AutoFill extension; ceiling bounds the
   denial-of-service a hostile file can cause. Please confirm that p = 4 is acceptable on
   iOS extension memory/CPU limits (m is what dominates).
4. **Secret key text form and storage.** *Default:* `OPSK1-` plus 52 base32 characters in
   groups of four, no checksum; the CLI keeps it in a 0600 file given by `--secret-key-file`.
   *Why:* simplest standard encoding; a mistyped key is detected anyway by the AEAD failing
   (reported as an authentication failure). A checksum could be added in a future format
   version.
5. **Whole-file rollback is not detected.** *Default:* accept. *Why:* restoring an older
   complete copy of the vault cannot be detected without external state (a counter on
   another device or a server), which the pilot excludes. Single-record rollback, deletion
   and insertion *are* detected by the file trailer.
6. **No padding of record sizes.** *Default:* none. *Why:* keeps the format simple; leaks
   approximate item sizes and the item count to someone with the file. Padding could be a
   later format version.
7. **Rotating the vault key re-encrypts every item** (new item keys too) and keeps
   `vault_id` and the secret key. *Why:* otherwise an old VK plus an old file copy would still
   open unchanged item bodies. Rotating the *secret key* is not offered in the pilot (not in
   the brief).
8. **Export protection.** *Default:* the export key is derived from the export password
   **and the vault's secret key** (HKDF over `export_pw_key ‖ SK`, CS §8), so the export is
   useless without both, like the vault itself. *Why:* the brief says stolen vault data must
   be useless without both secrets, and an export holds the whole vault. Consequence: restoring
   an export needs the secret key of the vault it came from (CLI `--source-secret-key-file`);
   a fresh device still needs that key to unlock anything. *Alternative (owner decision, not
   applied):* a portable export protected by the password alone would contradict the brief's
   wording and make the export the weakest link; if wanted, the floor of the export password
   and Argon2 parameters would have to be raised.
9. **Import semantics.** *Default:* import adds items under their original IDs and revisions
   into any unlocked vault; any ID clash aborts the whole import (`Conflict`). No merge or
   overwrite. *Why:* simplest safe behaviour; merging belongs with sync.
10. **Item plaintext format is JSON** (strict schema, version 1) rather than a binary
    encoding. *Why:* one standard, widely used parser, human-checkable; strictness (unknown
    fields rejected, size limits) compensates. Known cost: `serde_json` may leave unzeroized
    copies of plaintext in freed memory (threat-model.md residual risks).
11. **Search scope.** *Default:* title, username and URLs only; never passwords, notes,
    TOTP secrets or custom fields. *Why:* avoids exposing secret material to search/UI code.
12. **TOTP secret length.** *Default:* accept 10 to 128 decoded bytes (80-bit secrets are
    common in the wild, though RFC 4226 asks for at least 128 bits); digits 6–8; period
    1–300 s; SHA-1/256/512. No `otpauth://` URI parsing in the pilot.
13. **CLI secret input.** *Default:* secrets only via no-echo prompt or `--stdin` lines;
    never argv or environment. `get` hides secrets unless `--show-secrets`. `init` writes the
    key to a file and does not print it unless asked.
14. **Concurrency.** *Default:* no file locking; last atomic rename wins. *Why:* single-user
    pilot; locking is a platform-specific complication.
15. **Official vectors.** Since the first revision RFC 8439 §2.8.2 (ChaCha20-Poly1305), the
    HChaCha20 vector of the draft (§2.2.1) and RFC 2202 cases 1–4 (HMAC-SHA-1) were added. The primitives have official vectors in `spec/vectors/` (Argon2id,
    HKDF, XChaCha20-Poly1305 from the CFRG draft, HMAC-SHA-2, HOTP, TOTP, base32). The XChaCha20
    vector comes from an Internet-Draft, not an RFC, because none is published. No official
    vectors exist for onlypassword's own compositions; they are covered by layout, round-trip
    and tamper tests instead.
16. **Missing vectors.** No published Argon2id vector without the secret/associated-data
    inputs and no end-to-end composition vector (fixed inputs → expected file bytes) could be
    obtained from the permitted hosts or generated independently. Layout and AD bytes are
    pinned by tests that rebuild them independently from the spec. Commission an independent
    implementation (e.g. a short libsodium/Python script) if a stronger pin is wanted.
17. **Password change does not revoke old knowledge.** `change_master_password` keeps the
    vault key; use `passwd --rotate` after a suspected password compromise (CS §6.5).
18. **Unicode tables.** NFKC output follows the `unicode-normalization` version in
    `Cargo.lock`; accepted, with a fixed-result test (CS §3.1).

## Phase 2 (desktop application)

Defaults applied unattended; each can be changed by giving feedback to the planner.

19. **GUI stack.** *Default:* `egui`/`eframe` with the `glow` renderer, one crate for Windows, macOS and
    Linux (owner decision in the brief). *Why:* the gate is cargo-only. Consequence: egui is immediate-mode and
    keeps text in its own caches (threat-model residual risk 8); native look and accessibility are
    weaker than SwiftUI/Tauri.
20. **Dependencies.** *Default:* eframe, egui, egui_kittest (dev), arboard, rfd (gtk3 on Linux), directories; `serde`,
    `serde_json`, `sha2`, `zeroize`, `tempfile` reused. `persistence`, `wgpu`, `image-data`, `xdg-portal`, `snapshot` are
    excluded. *Why:* fewest crates that cover clipboard, file dialogs, the OS config directory and headless UI
    tests. The planner could not verify exact feature names or the licence/advisory outcome (list in `approved-deps.txt`).
21. **Core additions.** *Default:* two small, own features on the core before the GUI: `Vault::index()` (cached
    summaries so search does not decrypt every record per keystroke) and key-file helpers
    (`keyfile::read`, `write_new`, `Vault::create_with_key_file`). *Why:* the pilot's key-file logic lives in the CLI crate;
    the desktop must not copy it. The CLI is deliberately not refactored onto them (brief: pilot untouched); two copies of the
    key-file reader exist until the owner decides otherwise. No change to `crypto-spec.md`, the vault format, the export
    format or `spec/vectors/`.
22. **Clipboard.** *Default:* 30 s, range 5–600 s, cleared only if the clipboard still holds the copied text
    (compared by SHA-256 digest; the text itself is not kept); also cleared at lock and at exit; marked "sensitive" where
    the crate allows. *Why:* clearing a different value the user copied later would be harmful; a digest avoids keeping plaintext.
    Clearing at lock goes beyond the brief and is cheap safety. Clipboard history that ignores the hint is out of scope.
23. **Idle timeout.** *Default:* 300 s, range 10 s–24 h; there is no "never". *Why:* an unlimited unlock would defeat the
    feature; the owner can still choose 24 h. Activity means any input event; the timer is monotonic.
24. **Config file.** *Default:* `config.json` via `directories::ProjectDirs::from("", "", "onlypassword")`, five keys, strict parse, 4 KiB cap; an
    invalid file means defaults plus a notice and is not rewritten until settings are saved. The key-file path is **not**
    remembered (brief: only the last vault path), so the owner picks the key file at each unlock.
25. **Secret key in memory.** *Default:* the unlocked session keeps the `SecretKey` (zeroized on lock) because
    export and password change need it; the owner is not asked for the key file again for those. Import asks for the
    source key file, as the CLI does.
26. **Blocking work.** *Default:* Argon2id and native dialogs run on the UI thread (the window freezes for about a second at unlock). *Why:* a worker
    thread complicates headless tests; acceptable for a personal app. Revisit if the freeze annoys.
27. **Key text not shown at creation.** *Default:* the new secret key is written to the chosen file and never displayed, matching the CLI's `init`. The owner
    must back up that file. A "show once" screen was left out because it would put the key on screen and in egui caches.
28. **Password change in the GUI.** *Default:* the change form offers "also rotate the vault key", on by default (the CLI needs `--rotate`). *Why:* T-PWCHANGE
    says rotation is the real remedy; the owner can untick it.
29. **Testing on Windows and macOS.** *Default:* the pipeline only runs `cargo check` for the two targets; nobody runs the app there. Linking, clipboard
    behaviour, dialogs and 0600/ACL behaviour on those systems need a human test before a release.
30. **Theme.** *Default:* System / Light / Dark; "System" follows what eframe reports and falls back to light.
