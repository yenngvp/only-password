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

## Phase 2: desktop app for Windows, macOS and Linux

The pilot above is complete (F001–F023). Phase 2 adds a native desktop
application on top of the core, built by the same pipeline. Nothing in the
pilot's scope, non-negotiables or definition of done is withdrawn.

### Stack (owner decision, supersedes the "Tauri" line above for desktop)

One codebase for all three desktop operating systems, in pure Rust, using
`egui`/`eframe` with the default `glow` renderer. Rationale: the pipeline's gate
is cargo-only (crates.io dependencies, `cargo-deny`, no Node or web toolchain),
and one Rust crate is the only way a single agent session can build and test a
GUI under it. SwiftUI remains the plan for iOS/iPadOS later and is out of scope
here. The app is the crate `crates/onlypassword-desktop`, binary
`onlypassword-desktop`. It depends on `onlypassword-core` only through its
public API; if the core lacks something the app needs, extend the core in its
own feature with the same rigor as the pilot.

### Scope

1. **Open and create.** Pick a vault file, enter the master password, pick the
   secret-key file; create a new vault (new secret key written to a file the
   user chooses, 0600 where the OS supports it). Wrong password or key is
   reported as one generic failure.
2. **Lock state.** Lock manually and automatically after an idle timeout
   (default 5 minutes, configurable). Locking drops every key and plaintext
   from memory; the window shows only the unlock screen.
3. **Browse.** Item list with incremental search over title, username and URL;
   detail view for logins and secure notes including custom and hidden fields.
4. **Edit.** Add, edit and delete logins and notes with every field the core's
   item model has (title, username, password, URLs, notes, TOTP secret, custom
   fields). Delete asks for confirmation.
5. **Secrets on screen.** Passwords and hidden fields are masked by default,
   revealed per field on request, and re-masked on lock. Copy to clipboard
   clears the clipboard after 30 seconds (configurable) if it still holds the
   copied value.
6. **TOTP.** Current code with a countdown for items that have a secret.
7. **Generator.** A panel for random passwords and passphrases with the core's
   rules, with "use this" into the item being edited.
8. **Maintenance.** Change master password, rotate the vault key, encrypted
   export and import, each with the same prompts and failure semantics as the
   CLI.
9. **Settings.** Idle timeout, clipboard timeout, theme; stored in a plain
   config file in the OS config directory that never holds secrets or vault
   paths' contents beyond the last-opened vault path.

### Out of scope for phase 2

Sync, networking, biometric or OS-keychain unlock, browser extensions,
autofill, system tray or background operation, auto-update, installers and code
signing (a release build per platform via `cargo build --release` is enough),
multiple windows, drag and drop, localization.

### Non-negotiables (in addition to the pilot's)

- Key material and plaintext live in the core's secret types; the UI layer holds
  them only as long as a screen shows them and zeroizes on lock.
- No logging of any field value. Errors shown to the user are the core's fixed
  messages.
- No network access of any kind; no telemetry; no crash reporting.
- `#![forbid(unsafe_code)]`; dependencies only from `crates.io`, as few as
  possible, licenses as allowed by `pipeline/deny.toml`.
- Portable: the gate builds and tests on Linux and must also pass `cargo check`
  for `x86_64-pc-windows-msvc` and `aarch64-apple-darwin`. Platform-specific
  code is `cfg`-gated and the Linux path is fully tested.
- UI logic is testable headlessly: every screen's main flows have tests that run
  under the gate without a display (`egui_kittest` or an equivalent harness
  over the app's state machine).

### Definition of done for phase 2

Every phase-2 feature in `spec/features.json` has passed the gate and the
evaluator, and a headless end-to-end test drives the application through:
create a vault, add items (a login with TOTP and custom fields, a note), lock,
unlock, read them back, change the master password, export, import into a fresh
vault, and confirms that after lock no plaintext remains in the application
state.

## Phase 3: commercial-grade UI, modelled on Apple's Passwords app

Phase 2 delivered a working but plain desktop UI. Phase 3 replaces its look and
layout with a polished, commercial-quality design that closely follows Apple's
Passwords app (macOS 15 / iOS 18), while keeping every phase-2 behaviour, test
and non-negotiable. The app state machine, core API and tests from phase 2 stay;
the views are rebuilt on top of them. No new functionality beyond what the
layout below needs.

### Layout: three columns in one window (minimum 900×600, resizable)

1. **Sidebar (left, ~200 px, slightly tinted background).** Vault name at the
   top. Category list with an icon and a count badge per row: *All*, *Logins*,
   *Notes*, *Codes* (items with a TOTP secret), *Security* (items whose password
   is weak or reused, computed locally). Selected row has a filled rounded
   highlight in the accent colour. Bottom of the sidebar: a lock button and a
   settings (gear) button.
2. **List column (middle, ~320 px).** A rounded pill search field at the top
   with a magnifier icon and a clear button. Under it, one row per item: a
   40 px rounded-square "site tile" showing the first letter of the title on a
   colour derived from the title, the title in medium weight, the username (or
   first line of a note) in secondary grey below. Rows are 56 px tall with a
   hairline separator; the selected row gets a rounded accent highlight with
   white text. A "+" toolbar button creates a new item (Login or Note via a
   small menu). Sorting is alphabetical, grouped under letter headers like
   Apple's list.
3. **Detail pane (right, flexible).** Empty state shows a centred large key
   glyph and "No Password Selected" in grey. With a selection: a header with a
   larger site tile, the title in a bold 22 pt heading, the primary URL under
   it, and an "Edit" button in the top-right. Below, grouped cards (rounded
   12 px corners, card background one step lighter/darker than the pane,
   hairline rows inside): *User Name / Password* (password shown as dots with
   a reveal eye and a copy button that appear on hover; "Copied" feedback),
   *Verification Code* (6-digit code in a monospaced large font grouped
   3 3, a circular countdown ring, copy on click), *Website(s)*, *Notes*,
   custom fields (hidden ones masked like passwords), and a footer line with
   "Modified <date>". Edit mode turns the same cards into inline editable
   fields with Cancel/Save in the header, a "Generate" button next to the
   password with the phase-2 generator in a popover, and a red "Delete
   Password…" at the bottom with a confirmation sheet.

### Visual language

- System look: follow the OS light/dark appearance by default (eframe's
  `system_theme`), with a manual override in settings. Accent colour
  #007AFF (light) / #0A84FF (dark). Backgrounds: window #FFFFFF / #1E1E1E,
  sidebar #F5F5F7 / #2A2A2C, cards #F2F2F7 / #2C2C2E, secondary text #8E8E93.
- Typography: a clean sans-serif via eframe's `system_fonts` feature when
  available, falling back to egui's bundled fonts; 13 pt body, 11 pt
  secondary, 22 pt titles. Monospaced for codes and revealed passwords.
- Rounded corners everywhere (8 px controls, 12 px cards), hairline
  separators at 1 px, no visible panel frames, generous 12 to 16 px padding.
- Icons: a consistent vector icon set from an approved crates.io crate (for
  example `egui-phosphor`), never emoji.
- Unlock and create screens: a centred card with the app icon, vault path
  picker, password field (masked, reveal eye), secret-key file picker and a
  single accent "Unlock" button; errors shown inline in red under the field.
- Motion: subtle hover states on rows and buttons; nothing blocking.

### Out of scope for phase 3

Passkeys, Wi-Fi, sharing groups, iCloud/sync, Safari integration, Recently
Deleted (no trash in the core), and any new core format. Pixel-exact copying of
Apple assets or fonts is not required and Apple trademarks and artwork must
not be embedded.

### Non-negotiables (in addition to phase 2's)

- Every phase-2 headless test keeps passing; the end-to-end test is extended
  to drive the new layout (sidebar category filter, list selection, detail
  reveal/copy, edit/save).
- The accessibility tree stays complete: every interactive control has a label
  so `egui_kittest` and screen readers can find it.
- Secrets handling, lock behaviour and clipboard rules are unchanged.

### Definition of done for phase 3

Every phase-3 feature has passed the gate and evaluator; the headless
end-to-end test exercises the three-column layout end to end; a screenshot
test or a documented manual checklist in `agent-notes/` describes what each
screen looks like.
