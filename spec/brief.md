# onlypassword — owner's brief

This file is the owner's intent. Agents read it and never change it.

## Product

A password manager for one person, for use on Windows, macOS, Linux, iOS and
iPadOS. All cryptography and vault logic live in one shared Rust core; thin
native UIs come later (SwiftUI on Apple platforms, Tauri on Windows and Linux).

## Pilot scope: the Rust core only

Build a library crate, plus a small command-line tool that exercises it, covering:

1. **Unlock keys.** A master key derived from the master password with Argon2id,
   combined with a random 256-bit secret key that is stored only on the user's
   devices. Stolen vault data must be useless without both.
2. **Key hierarchy.** A random vault key wrapped by the master key; a random key
   per item wrapped by the vault key.
3. **Item encryption.** Authenticated encryption with every ciphertext bound to
   its item ID, version and format, so records cannot be swapped, rolled back or
   reinterpreted.
4. **Item model.** Logins (title, username, password, URLs, notes, TOTP secret,
   custom fields), secure notes, timestamps, and a versioned serialization.
5. **Vault file.** A single-file, versioned vault format with an authenticated
   header (including the key-derivation parameters), written atomically.
6. **Lifecycle.** Create vault, unlock, lock, add, read, update, delete, list
   and search items, change the master password, rotate the vault key.
7. **Password generator.** Random passwords and word-based passphrases with
   configurable rules, using the operating system's random source without bias.
8. **TOTP.** One-time codes per RFC 6238.
9. **Encrypted export and import.** A backup file in the core's own format that
   round-trips a whole vault.

## Out of scope for the pilot

Sync, any network code, user interfaces, biometric unlock, OS keychain
integration, browser extensions, passkeys, sharing, account recovery, SQLite,
FFI bindings, and fuzzing infrastructure. Do not build hooks for these.

## Non-negotiables

- Standard, published primitives only, combined in standard ways. No invented
  cryptography. Preferred set: Argon2id (RFC 9106), HKDF-SHA-256 (RFC 5869),
  XChaCha20-Poly1305, HMAC-SHA-1/SHA-256/SHA-512 for TOTP only.
- Symmetric cryptography with 256-bit keys throughout; no public-key
  cryptography in the pilot.
- Argon2id memory cost no higher than 64 MiB by default, so the same vault can
  later be unlocked inside an iOS AutoFill extension.
- No account recovery and no fallback to weaker or older formats. An unknown or
  older-than-supported format version is an error, never a downgrade.
- Everything that influences decryption is authenticated: parameters, versions,
  identifiers and metadata.
- `#![forbid(unsafe_code)]` in every crate. Secrets are zeroized on drop and
  never printed, logged or placed in error messages.
- Untrusted input (vault files, import files) never causes a panic.
- Known-answer tests use official published vectors, stored with their source.
- As few dependencies as possible, all from crates.io, all widely used.
- No real passwords or personal data anywhere in the repo.

## Definition of done for the pilot

Every feature in `spec/features.json` has passed the gate and the evaluator, and
an end-to-end test drives the command-line tool through: create a vault, add
items, lock, unlock, read them back, change the master password, export, and
import into a fresh vault.
