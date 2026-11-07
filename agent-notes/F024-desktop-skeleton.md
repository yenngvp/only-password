# F024 desktop skeleton

Built `crates/onlypassword-desktop` (lib `onlypassword_desktop`, bin `onlypassword-desktop`): modules `app` (DesktopApp: eframe::App), `view` (heading `onlypassword` + label `Locked` in a CentralPanel), `state` (minimal `AppState`, `Screen::Open`). `main.rs` is the only `run_native` call site. Test: `tests/smoke.rs` (egui_kittest, headless, finds label `onlypassword`). Core/CLI untouched.

## Versions / features
- eframe 0.37.0, default-features = false, features glow, default_fonts, wayland, x11 (no persistence)
- egui 0.37.0, default-features = false
- egui_kittest 0.37.0 (dev, default features; no snapshot/wgpu/eframe)
- onlypassword-core: path in [dependencies]; dev-dependency adds insecure-fast-kdf and test-hooks.
- Cargo.lock updated and committed.

## Outcomes
- `cargo test -p onlypassword-desktop`: passes.
- **Licence (attempt 3): ok.** The gate's cargo-deny now reports `advisories ok, bans ok, licenses ok, sources ok` (the earlier Ubuntu-font-1.0 failure no longer occurs with the gate's deny.toml in /src; spec-issues.md item 1 is resolved).
- **GATE PASSED**; portability: `ok: x86_64-pc-windows-msvc`, `ok: aarch64-apple-darwin` (both targets installed, not skipped).
- advisories, bans, sources: ok.
- Note: no `default_fonts` => panic at text layout, so it cannot be dropped.
