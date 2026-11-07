//! Application state machine (no egui here).

use std::fmt;
use std::path::{Path, PathBuf};

use onlypassword_core::crypto::kdf::KdfParams;
use onlypassword_core::crypto::keys::SecretKey;
use onlypassword_core::{keyfile, ItemId, SecretString, Vault};

pub mod browse;
pub mod edit;
pub use edit::{Draft, DraftField};
pub mod generator;
pub use generator::{GeneratorMode, GeneratorState};
pub mod idle;
pub mod maintenance;
pub use browse::{Detail, FieldRef, Row};
pub use maintenance::{MaintenanceForm, MaintenanceKind};
pub mod settings;
pub mod totp;
pub use totp::{totp_view, TotpView};

use onlypassword_core::{ItemKind, PassphraseOptions, PasswordOptions, TotpAlgorithm};
use std::time::Duration;

use crate::clipboard::{ClipboardBackend, ClipboardService};
use crate::clock::UiClock;
use crate::config::{Config, ConfigStore};
use crate::error::UiError;
use crate::picker::FilePicker;
use crate::secret_buf::SecretBuf;
use idle::IdleTimer;
use settings::SettingsForm;

/// Everything the state machine needs from the outside world.
pub struct AppDeps {
    pub clock: Box<dyn UiClock>,
    pub clipboard: Box<dyn ClipboardBackend>,
    pub picker: Box<dyn FilePicker>,
    pub config_store: Option<ConfigStore>,
    /// KDF cost for new vaults (`KdfParams::DEFAULT` in the real app).
    pub kdf: KdfParams,
}

/// `AppDeps` minus the clipboard backend, which the clipboard service owns.
struct Deps {
    clock: Box<dyn UiClock>,
    picker: Box<dyn FilePicker>,
    config_store: Option<ConfigStore>,
    kdf: KdfParams,
}

/// The screen currently shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    Open,
    Create,
    Unlock,
    Browse,
    Detail(ItemId),
    /// Add (`None`) or edit (`Some`) an item.
    Edit(Option<ItemId>),
    Settings,
    /// The standalone generator (from Browse).
    Generator,
    Maintenance(MaintenanceKind),
}

/// User intents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Unlock with the open/unlock form.
    SubmitOpen,
    /// Create with the create form.
    SubmitCreate,
    Lock,
    /// Leave the create form (or the open form back to unlock) and clear it.
    Cancel,
    ShowCreate,
    ShowOpen,
    BrowseVault,
    BrowseKeyFile,
    BrowseNewVault,
    BrowseNewKeyFile,
    /// Open the settings screen (from Unlock or Browse).
    ShowSettings,
    /// Leave the settings screen without saving.
    CloseSettings,
    /// Validate and save the settings form.
    SaveSettings,
    Search(String),
    Select(ItemId),
    ToggleReveal(FieldRef),
    /// Put a field of the open item on the clipboard.
    Copy(FieldRef),
    /// Leave the detail screen (or cancel an open draft).
    Back,
    /// Start a draft for a new item (from Browse).
    BeginAdd(ItemKind),
    /// Start a draft from the open item (from Detail).
    BeginEdit,
    SaveDraft,
    CancelDraft,
    RequestDelete,
    ConfirmDelete,
    CancelDelete,
    SetKind(ItemKind),
    SetTitle(String),
    SetUsername(String),
    SetUrl(usize, String),
    AddUrl,
    RemoveUrl(usize),
    SetTotpAlgorithm(TotpAlgorithm),
    SetTotpDigits(u8),
    SetTotpPeriod(u32),
    AddField,
    RemoveField(usize),
    SetFieldName(usize, String),
    SetFieldHidden(usize, bool),
    /// Show or hide one secret field of the draft form.
    ToggleDraftReveal(FieldRef),
    /// Open the standalone generator (from Browse).
    ShowGenerator,
    /// Close the generator screen or the edit screen's side panel.
    CloseGenerator,
    /// Show or hide the generator side panel of the edit screen.
    ToggleGeneratorPanel,
    SetGeneratorMode(GeneratorMode),
    SetPasswordOptions(PasswordOptions),
    SetPassphraseOptions(PassphraseOptions),
    GenerateNow,
    UseGenerated,
    CopyGenerated,
    DiscardGenerated,
    /// Show or hide the generated value.
    ToggleGeneratedReveal,
    /// Open a maintenance form (from Browse).
    ShowMaintenance(MaintenanceKind),
    SubmitChangePassword,
    SubmitRotate,
    SubmitExport,
    SubmitImport,
    CancelMaintenance,
    /// User input happened: restart the idle timer.
    Activity,
}

/// The unlocked state: vault and key (the key is needed by later features).
pub struct Session {
    pub vault: Vault,
    pub key: SecretKey,
    browse: browse::BrowseState,
}

/// Form buffers of the open and unlock screens.
#[derive(Default)]
pub struct OpenForm {
    pub vault_path: String,
    pub key_path: String,
    pub password: SecretBuf,
}

/// Form buffers of the create screen.
#[derive(Default)]
pub struct CreateForm {
    pub vault_path: String,
    pub key_path: String,
    pub password: SecretBuf,
    pub confirm: SecretBuf,
}

/// The whole UI state. No `Clone`; `Debug` is redacted.
pub struct AppState {
    deps: Deps,
    clipboard: ClipboardService,
    config: Config,
    screen: Screen,
    notice: Option<UiError>,
    session: Option<Session>,
    open: OpenForm,
    create: CreateForm,
    wipe_requested: bool,
    idle: IdleTimer,
    settings: SettingsForm,
    settings_return: Screen,
    maint: MaintenanceForm,
    info: Option<String>,
}

impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppState")
            .field("screen", &self.screen)
            .field("unlocked", &self.session.is_some())
            .field("has_notice", &self.notice.is_some())
            .finish()
    }
}

impl AppState {
    /// Load the config; start on Unlock if a last vault is known, else Open.
    pub fn new(deps: AppDeps) -> AppState {
        let AppDeps {
            clock,
            clipboard,
            picker,
            config_store,
            kdf,
        } = deps;
        let deps = Deps {
            clock,
            picker,
            config_store,
            kdf,
        };
        let (config, notice) = match &deps.config_store {
            Some(store) => store.load(),
            None => (Config::default(), None),
        };
        let mut open = OpenForm::default();
        let screen = match config.last_vault_path.as_deref().and_then(Path::to_str) {
            Some(p) => {
                open.vault_path = p.to_owned();
                Screen::Unlock
            }
            None => Screen::Open,
        };
        let idle = IdleTimer::new(
            Duration::from_secs(u64::from(config.idle_timeout_secs)),
            deps.clock.now(),
        );
        let settings = SettingsForm::from_config(&config);
        let clipboard = ClipboardService::new(
            clipboard,
            Duration::from_secs(u64::from(config.clipboard_clear_secs)),
        );
        AppState {
            clipboard,
            idle,
            settings,
            maint: MaintenanceForm::default(),
            info: None,
            settings_return: Screen::Unlock,
            deps,
            config,
            screen,
            notice,
            session: None,
            open,
            create: CreateForm::default(),
            wipe_requested: false,
        }
    }

    pub fn screen(&self) -> &Screen {
        &self.screen
    }

    /// The last fixed error message, cleared by the next action.
    pub fn notice(&self) -> Option<&UiError> {
        self.notice.as_ref()
    }

    /// True when nothing secret is held (REQ-LOCK-003).
    pub fn is_clean(&self) -> bool {
        self.session.is_none()
            && self.open.password.is_empty()
            && self.create.password.is_empty()
            && self.create.confirm.is_empty()
            && self.maint.buffers_empty()
            && self.info.is_none()
            && self.clipboard.is_clean()
            && matches!(
                self.screen,
                Screen::Open | Screen::Create | Screen::Unlock | Screen::Settings
            )
    }

    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn open_form_mut(&mut self) -> &mut OpenForm {
        &mut self.open
    }

    pub fn create_form_mut(&mut self) -> &mut CreateForm {
        &mut self.create
    }

    /// True once after a submit, cancel or lock: the view must then drop
    /// egui's cached text state.
    pub fn take_wipe_request(&mut self) -> bool {
        std::mem::take(&mut self.wipe_requested)
    }

    /// Timers. The idle lock comes first, before any other pending work.
    pub fn tick(&mut self) {
        self.check_idle();
        self.refresh_totp();
        if let Err(e) = self.clipboard.poll(self.deps.clock.now()) {
            self.notice = Some(e);
        }
    }

    /// Lock when the idle timeout has passed. The timer is armed only while
    /// a session exists.
    fn check_idle(&mut self) {
        if self.session.is_some() && self.idle.expired(self.deps.clock.now()) {
            self.lock_now();
        }
    }

    /// Called when the application closes.
    pub fn on_exit(&mut self) {
        self.lock_now();
    }

    pub fn dispatch(&mut self, action: Action) {
        // A late action after a long gap must not be applied to the vault.
        self.check_idle();
        self.notice = None;
        self.info = None;
        match action {
            Action::Activity => {
                if self.session.is_some() {
                    self.idle.touch(self.deps.clock.now());
                }
            }
            Action::Search(_)
            | Action::Select(_)
            | Action::ToggleReveal(_)
            | Action::Copy(_)
            | Action::Back => {
                // Navigating away from the edit form drops the draft.
                if matches!(self.screen, Screen::Edit(_)) {
                    self.drop_draft();
                    if action == Action::Back {
                        return;
                    }
                }
                self.browse_action(action)
            }
            Action::BeginAdd(_)
            | Action::BeginEdit
            | Action::SaveDraft
            | Action::CancelDraft
            | Action::RequestDelete
            | Action::ConfirmDelete
            | Action::CancelDelete
            | Action::SetKind(_)
            | Action::SetTitle(_)
            | Action::SetUsername(_)
            | Action::SetUrl(..)
            | Action::AddUrl
            | Action::RemoveUrl(_)
            | Action::SetTotpAlgorithm(_)
            | Action::SetTotpDigits(_)
            | Action::SetTotpPeriod(_)
            | Action::AddField
            | Action::RemoveField(_)
            | Action::SetFieldName(..)
            | Action::SetFieldHidden(..)
            | Action::ToggleDraftReveal(_) => self.edit_action(action),
            Action::ShowGenerator
            | Action::CloseGenerator
            | Action::ToggleGeneratorPanel
            | Action::SetGeneratorMode(_)
            | Action::SetPasswordOptions(_)
            | Action::SetPassphraseOptions(_)
            | Action::GenerateNow
            | Action::UseGenerated
            | Action::CopyGenerated
            | Action::DiscardGenerated
            | Action::ToggleGeneratedReveal => self.generator_action(action),
            Action::ShowMaintenance(_)
            | Action::SubmitChangePassword
            | Action::SubmitRotate
            | Action::SubmitExport
            | Action::SubmitImport
            | Action::CancelMaintenance => self.maintenance_action(action),
            Action::ShowSettings => {
                if matches!(self.screen, Screen::Maintenance(_)) {
                    self.reset_maintenance();
                }
                if matches!(self.screen, Screen::Edit(_)) {
                    self.drop_draft();
                }
                if self.screen == Screen::Generator {
                    self.generator_action(Action::DiscardGenerated);
                }
                self.show_settings()
            }
            Action::CloseSettings => self.close_settings(),
            Action::SaveSettings => self.save_settings(),
            Action::SubmitOpen => self.submit_open(),
            Action::SubmitCreate => self.submit_create(),
            Action::Lock => {
                if self.session.is_some() {
                    self.lock_now();
                } else {
                    self.wipe_idle_forms();
                }
            }
            Action::Cancel => self.cancel(),
            Action::ShowCreate => {
                if matches!(self.screen, Screen::Open | Screen::Unlock) {
                    self.clear_open_password();
                    self.screen = Screen::Create;
                }
            }
            Action::ShowOpen => {
                if self.screen == Screen::Unlock {
                    self.clear_open_password();
                    self.screen = Screen::Open;
                }
            }
            Action::BrowseVault => {
                if self.on_open_screen() {
                    if let Some(p) = self.deps.picker.pick_vault() {
                        self.open.vault_path = path_text(&p);
                    }
                }
            }
            Action::BrowseKeyFile => {
                if self.on_open_screen() {
                    if let Some(p) = self.deps.picker.pick_key_file() {
                        self.open.key_path = path_text(&p);
                    }
                }
            }
            Action::BrowseNewVault => {
                if self.screen == Screen::Create {
                    if let Some(p) = self.deps.picker.save_vault() {
                        self.create.vault_path = path_text(&p);
                    }
                }
            }
            Action::BrowseNewKeyFile => {
                if self.screen == Screen::Create {
                    if let Some(p) = self.deps.picker.save_key_file() {
                        self.create.key_path = path_text(&p);
                    }
                }
            }
        }
    }

    fn on_open_screen(&self) -> bool {
        matches!(self.screen, Screen::Open | Screen::Unlock)
    }

    fn clear_open_password(&mut self) {
        self.open.password.clear();
        self.wipe_requested = true;
    }

    fn cancel(&mut self) {
        match self.screen {
            Screen::Create => {
                self.create = CreateForm::default();
                self.screen = if self.open.vault_path.is_empty() {
                    Screen::Open
                } else {
                    Screen::Unlock
                };
                self.wipe_requested = true;
            }
            Screen::Open | Screen::Unlock => self.clear_open_password(),
            Screen::Browse
            | Screen::Detail(_)
            | Screen::Edit(_)
            | Screen::Settings
            | Screen::Generator
            | Screen::Maintenance(_) => {}
        }
    }

    fn submit_open(&mut self) {
        if !self.on_open_screen() {
            return;
        }
        let result = self.try_open();
        self.clear_open_password();
        match result {
            Ok(vault_path) => {
                self.open.key_path.clear();
                self.finish_login(vault_path);
            }
            Err(e) => self.notice = Some(e),
        }
    }

    fn try_open(&mut self) -> Result<PathBuf, UiError> {
        if self.open.vault_path.is_empty() || self.open.key_path.is_empty() {
            return Err(UiError::EmptyField);
        }
        let vault_path = PathBuf::from(&self.open.vault_path);
        let key = keyfile::read(Path::new(&self.open.key_path))?;
        let password = SecretString::new(self.open.password.expose().to_owned());
        let vault = Vault::unlock(&vault_path, &password, &key)?;
        self.session = Some(Session::new(vault, key));
        Ok(vault_path)
    }

    fn submit_create(&mut self) {
        if self.screen != Screen::Create {
            return;
        }
        let result = self.try_create();
        self.create.password.clear();
        self.create.confirm.clear();
        self.wipe_requested = true;
        match result {
            Ok(vault_path) => {
                self.create = CreateForm::default();
                self.finish_login(vault_path);
            }
            Err(e) => self.notice = Some(e),
        }
    }

    fn try_create(&mut self) -> Result<PathBuf, UiError> {
        let c = &self.create;
        if c.vault_path.is_empty() || c.key_path.is_empty() {
            return Err(UiError::EmptyField);
        }
        if c.password.expose() != c.confirm.expose() {
            return Err(UiError::PasswordMismatch);
        }
        let vault_path = PathBuf::from(&c.vault_path);
        let key_path = PathBuf::from(&c.key_path);
        let password = SecretString::new(c.password.expose().to_owned());
        let vault = Vault::create_with_key_file(&vault_path, &key_path, &password, self.deps.kdf)?;
        match keyfile::read(&key_path) {
            Ok(key) => {
                self.session = Some(Session::new(vault, key));
                Ok(vault_path)
            }
            Err(e) => {
                vault.lock();
                Err(e.into())
            }
        }
    }

    /// Enter the browse screen and remember the vault path (a save failure
    /// only sets the notice).
    fn finish_login(&mut self, vault_path: PathBuf) {
        self.open.vault_path = path_text(&vault_path);
        self.config.last_vault_path = Some(vault_path);
        self.screen = Screen::Browse;
        self.idle.touch(self.deps.clock.now());
        if let Some(store) = &self.deps.config_store {
            if let Err(e) = store.save(&self.config) {
                self.notice = Some(e);
            }
        }
    }

    /// Lock with no session: nothing to close, but typed secrets still go (REQ-LOCK-003).
    fn wipe_idle_forms(&mut self) {
        let _ = self.clipboard.clear_now();
        self.open.password.clear();
        self.create.password.clear();
        self.create.confirm.clear();
        self.maint.reset();
        self.info = None;
        self.wipe_requested = true;
    }

    fn lock_now(&mut self) {
        // A failed clear is dropped: the lock must not depend on the clipboard.
        let _ = self.clipboard.clear_now();
        if let Some(session) = self.session.take() {
            let Session { vault, key, .. } = session;
            vault.lock();
            drop(key);
        }
        self.open.password.clear();
        self.open.key_path.clear();
        self.create = CreateForm::default();
        self.maint.reset();
        self.info = None;
        self.notice = None;
        self.settings = SettingsForm::from_config(&self.config);
        self.screen = Screen::Unlock;
        self.wipe_requested = true;
    }
}

fn path_text(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}
