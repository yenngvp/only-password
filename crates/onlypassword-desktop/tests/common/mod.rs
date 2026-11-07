#![allow(dead_code)]
use std::path::{Path, PathBuf};

use onlypassword_core::crypto::kdf::KdfParams;
use onlypassword_core::{SecretString, Vault};
use onlypassword_desktop::clock::ManualClock;
use onlypassword_desktop::config::ConfigStore;
use onlypassword_desktop::picker::ScriptedPicker;
use onlypassword_desktop::state::{AppDeps, AppState};

pub const PW: &str = "pw-SENTINEL-correct horse";

pub struct Env {
    pub dir: tempfile::TempDir,
    pub picker: ScriptedPicker,
}

impl Env {
    pub fn new() -> Env {
        Env {
            dir: tempfile::tempdir().unwrap(),
            picker: ScriptedPicker::new(),
        }
    }
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    pub fn config_dir(&self) -> PathBuf {
        self.path("cfg")
    }
    pub fn state(&self) -> AppState {
        std::fs::create_dir_all(self.config_dir()).unwrap();
        AppState::new(AppDeps {
            clock: Box::new(ManualClock::new()),
            picker: Box::new(self.picker.clone()),
            config_store: Some(ConfigStore::new(self.config_dir())),
            kdf: KdfParams::FAST_FOR_TESTS,
        })
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
