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
- **Licence: FAILED** – `Ubuntu-font-1.0` (epaint_default_fonts) is not in pipeline/deny.toml. See spec-issues.md. Gate stops at cargo-deny, so **GATE PASSED was not reached** and the portability step (windows-msvc, aarch64-apple-darwin; both targets are installed) was **not run**. Next agent: after the owner fixes deny.toml, run the gate and fill in the cross-target result here.
- advisories, bans, sources: ok.
- Note: no `default_fonts` => panic at text layout, so it cannot be dropped.
