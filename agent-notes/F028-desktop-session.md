# F028-desktop-session

Built in onlypassword-desktop: `secret_buf` (SecretBuf), `clock` (UiClock, SystemUiClock, ManualClock), `picker` (FilePicker, RfdPicker, ScriptedPicker), `state` (AppDeps without clipboard, AppState::new, Screen {Open, Create, Unlock, Browse}, Action, Session), views open/create/unlock/browse plus `view::secret_edit`. The app uses `AppState::new`; there is no `Default` any more. New deps: `zeroize` and `rfd` 0.17 (default-features off, `gtk3`). The gate passed, including the Windows and macOS checks.

Choices the spec left open:
- Form buffers live in the state (`open_form_mut()`, `create_form_mut()`). Actions carry no data: `SubmitOpen`/`SubmitCreate` read the forms. Open and Unlock share one form.
- Picker actions: BrowseVault/BrowseKeyFile (open form, pick dialogs), BrowseNewVault/BrowseNewKeyFile (create form, save dialogs). A cancelled dialog is silent. `PickerCancelled` is never set.
- After every submit the password buffers are cleared (the create paths are kept on failure). After Lock all buffers are cleared, the key path is dropped, and the vault path is kept so the unlock screen is usable.
- `take_wipe_request()` is a flag the state sets on submit, cancel and lock. `view::show` then calls `memory_mut(|m| m.data.clear())`. `forget_all_images` is not called (no images are used).
- SecretBuf growth and deletion build a fresh buffer and zeroize the old one, so no stale copy stays on the heap. The limit is 64 KiB; `push_str` returns false past it.
- Create reads the key file back with `keyfile::read` to fill the Session. If that fails, the vault is locked and the error is shown.
- `tick()` is a no-op until the idle-timer feature. The `clock` is only held in AppDeps for now.
- egui 0.37 `TextBuffer` also requires `type_id`. The adapter returns the TypeId of `SecretAdapter<'static>`.
- The smoke test now checks the Open screen. The "Locked" label is gone.
