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
   option; the brief's ceiling for the default). Accepted range on files: m 8 MiB to
   256 MiB, t 1–16, p 1–16. *Why:* fits an iOS AutoFill extension; ceiling bounds the
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
8. **Export protection.** *Default:* export is protected by its own password (minimum 8
   characters, Argon2id with the same parameters), independent of master password and secret
   key, so it can be imported on a device that has neither. *Why:* the brief wants a
   portable backup. Consequence: the export is only as strong as that password and has no
   secret key. Alternative to consider: also require the secret key.
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
15. **Official vectors.** The primitives have official vectors in `spec/vectors/` (Argon2id,
    HKDF, XChaCha20-Poly1305 from the CFRG draft, HMAC-SHA-2, HOTP, TOTP, base32). The XChaCha20
    vector comes from an Internet-Draft, not an RFC, because none is published. No official
    vectors exist for onlypassword's own compositions; they are covered by layout, round-trip
    and tamper tests instead.
