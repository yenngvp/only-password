# F029-desktop-idle-settings

Built: `state/` is now a directory module (`mod.rs`, `idle.rs` with IdleTimer, `settings.rs` with SettingsForm and the save logic). New `Screen::Settings`, `Action::{ShowSettings, CloseSettings, SaveSettings, Activity}`, `view::settings`, `view::apply_theme`/`effective_theme`, and `app::repaint_after`.

Choices the spec left open:
- `SaveSettings` carries no data: it reads `settings_form_mut()` (strings + theme), like the F028 forms. Strings that do not parse as u32 give `InvalidSetting`. The ranges are checked by `Config::validate`.
- Settings is reachable only from Unlock and Browse (ShowSettings is ignored elsewhere). Close and a successful save (also a failed write, with the ConfigWrite notice) return to the screen it came from. An invalid value stays on the screen with the notice.
- Idle check (`check_idle`) runs in `tick` and at the start of every `dispatch`, so an action queued after a long gap (even Activity) finds the vault locked. `expired` uses `>=`.
- The timer is touched at login and by `Action::Activity` only while a session exists.
- Theme: `view::show` calls `ctx.set_theme` every frame (System -> `ctx.system_theme()` or light).
- The eframe hook in this egui version is `App::ui`, not `update`; the activity dispatch, tick and `request_repaint_after(repaint_after(state))` live there.
- The clipboard timeout is stored and validated but has no consumer until the clipboard feature.
