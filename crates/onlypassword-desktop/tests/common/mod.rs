#![allow(dead_code)]
use std::path::{Path, PathBuf};

use onlypassword_core::crypto::kdf::KdfParams;
use onlypassword_core::{SecretString, Vault};
use onlypassword_desktop::clipboard::MemoryClipboard;
use onlypassword_desktop::clock::ManualClock;
use onlypassword_desktop::config::ConfigStore;
use onlypassword_desktop::picker::ScriptedPicker;
use onlypassword_desktop::state::{AppDeps, AppState};

pub const PW: &str = "pw-SENTINEL-correct horse";

pub struct Env {
    pub dir: tempfile::TempDir,
    pub picker: ScriptedPicker,
    pub clipboard: MemoryClipboard,
}

impl Env {
    pub fn new() -> Env {
        Env {
            dir: tempfile::tempdir().unwrap(),
            picker: ScriptedPicker::new(),
            clipboard: MemoryClipboard::new(),
        }
    }
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    pub fn config_dir(&self) -> PathBuf {
        self.path("cfg")
    }
    pub fn state(&self) -> AppState {
        self.state_with_clock().0
    }
    pub fn state_with_clock(&self) -> (AppState, ManualClock) {
        let clock = ManualClock::new();
        std::fs::create_dir_all(self.config_dir()).unwrap();
        let state = AppState::new(AppDeps {
            clock: Box::new(clock.clone()),
            clipboard: Box::new(self.clipboard.clone()),
            picker: Box::new(self.picker.clone()),
            config_store: Some(ConfigStore::new(self.config_dir())),
            kdf: KdfParams::FAST_FOR_TESTS,
        });
        (state, clock)
    }
    /// An unlocked state plus its clock.
    pub fn unlocked(&self) -> (AppState, ManualClock) {
        let (v, k) = self.make_vault("u.opw", "u.key");
        let (mut s, clock) = self.state_with_clock();
        fill_open(&mut s, &v, &k, PW);
        s.dispatch(onlypassword_desktop::state::Action::SubmitOpen);
        assert!(s.is_unlocked(), "{:?}", s.notice());
        (s, clock)
    }
    /// Make a vault and key file with the core directly.
    pub fn make_vault(&self, vault: &str, key: &str) -> (PathBuf, PathBuf) {
        let (v, k) = (self.path(vault), self.path(key));
        Vault::create_with_key_file(
            &v,
            &k,
            &SecretString::new(PW.to_owned()),
            KdfParams::FAST_FOR_TESTS,
        )
        .unwrap()
        .lock();
        (v, k)
    }
}

pub fn fill_open(state: &mut AppState, vault: &Path, key: &Path, pw: &str) {
    let f = state.open_form_mut();
    f.vault_path = vault.to_string_lossy().into_owned();
    f.key_path = key.to_string_lossy().into_owned();
    f.password.clear();
    f.password.push_str(pw);
}

pub fn fill_create(state: &mut AppState, vault: &Path, key: &Path, pw: &str, confirm: &str) {
    let f = state.create_form_mut();
    f.vault_path = vault.to_string_lossy().into_owned();
    f.key_path = key.to_string_lossy().into_owned();
    f.password.push_str(pw);
    f.confirm.push_str(confirm);
}
