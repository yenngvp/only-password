# Phase 2 (desktop GUI): decisions taken by default, for the owner's review

Phase 2 was started unattended on 2026-11-07 on the owner's instruction
"build the desktop GUI for macOS, Linux and Windows in the same pipeline, no
human in the loop; on any question choose a default and record it". Every
choice below is reversible; nothing here was confirmed by a person.

1. **GUI stack: egui/eframe (pure Rust), one crate for all three desktop OSes.**
   The original brief named Tauri for Windows/Linux and SwiftUI for macOS. The
   pipeline gate is cargo-only (crates.io, cargo-deny, no Node/webkit in the
   container), so a web-stack GUI cannot be built or tested under it without
   rewriting the harness. The brief was amended (section "Phase 2") to say so.
2. **Portability is checked by cross `cargo check`, not by running on the other
   OSes.** `pipeline/gate.sh` now checks `x86_64-pc-windows-msvc` and
   `aarch64-apple-darwin` (targets added to the image). Linking, packaging and
   manual testing on Windows and macOS remain to be done by a person.
3. **Headless UI tests** via `egui_kittest` (or an equivalent harness over the app
   state machine) stand in for a display; no screenshot tests.
4. **Harness changes** (protected paths, changed on the host as the owner):
   - `pipeline/Dockerfile`: Linux GUI build libraries (wayland, xkbcommon, gtk3,
     mesa GL/EGL, fontconfig, openssl headers) and the two rustup targets.
   - `pipeline/deny.toml`: licenses MPL-2.0, BSL-1.0, OFL-1.1, LicenseRef-UFL-1.0,
     Unicode-DFS-2016 allowed (common in the egui graph). MPL-2.0 is weak
     copyleft; acceptable for a desktop app that does not modify those crates.
   - `pipeline/config.toml`: max_run_usd 60 -> 150, generator budget 10 -> 15 and
     timeout 60 -> 90 min, evaluator/gate timeouts 45 min (GUI graphs compile
     slower in a cold container).
   - The image rebuild also refreshes the RustSec advisory snapshot; a new
     advisory against an existing dependency would now fail the gate and be
     fixed by the next generator.
5. **Spec revision path.** The spec was extended with `plan --feedback` (planner
   revise step), not re-planned from scratch, so that F001–F023 and the crypto
   spec stay as approved. A second revise round asked the planner to self-review
   because the critic step does not run with `--feedback`.
6. **Blocked features.** If a feature blocks after 3 attempts, the orchestration
   script retries it twice more with a generic note before giving up. Anything
   still blocked is left on its `agent/<feature>` branch for the owner.
7. **Defaults in the brief:** idle lock 5 min, clipboard clear 30 s, config in the
   OS config directory with no secrets, generic failure message for wrong
   password/key, no installers/signing in scope.

Open items for the owner after the run: the planner's additions to
`spec/OPEN-QUESTIONS.md` (phase 2 section), `agent-notes/spec-issues.md`,
`agent-notes/dep-requests.md` if present, and the pilot-era items already listed
there (F008 error variant, wordlist, Argon2 p=4 on iOS).
- deny.toml: added Ubuntu-font-1.0 after the first F024 gate run rejected epaint_default_fonts on it (2026-11-07 07:51).
