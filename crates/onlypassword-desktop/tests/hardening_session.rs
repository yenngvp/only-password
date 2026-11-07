//! Cross-cutting robustness: sentinel session, randomised actions, fixed error strings
//! (architecture.md 7.8; REQ-GUI-070..076, REQ-LOCK-003, REQ-SEC-004).

mod common;

use std::time::Duration;

use common::*;
use onlypassword_core::{Error, ItemKind, PassphraseOptions, PasswordOptions, TotpAlgorithm};
use onlypassword_desktop::error::UiError;
use onlypassword_desktop::state::{
    Action, AppState, FieldRef, GeneratorMode, MaintenanceKind, Screen,
};

const S_PW: &str = "pw-SENTINEL-item-password";
const S_NOTES: &str = "notes-SENTINEL-private";
const S_TOTP: &str = "JBSWY3DPEHPK3PXP";
const S_FIELD: &str = "field-SENTINEL-value";
const S_NEW: &str = "NEWPW-SENTINEL-brand new";
const S_EXP: &str = "EXPPW-SENTINEL-export pw";

fn config_text(env: &Env) -> String {
    std::fs::read_to_string(env.config_dir().join("config.json")).unwrap_or_default()
}

/// Everything a user or log could see, as one string.
fn visible(s: &AppState) -> String {
    format!(
        "{:?}|{}|{}",
        s,
        s.notice().map(|n| n.to_string()).unwrap_or_default(),
        s.info().unwrap_or_default()
    )
}

fn check(s: &AppState, env: &Env, sentinels: &[String], step: &str) {
    let v = visible(s);
    let cfg = config_text(env);
    for x in sentinels {
        assert!(
            !v.contains(x.as_str()),
            "sentinel in state/notice at {step}"
        );
        assert!(!cfg.contains(x.as_str()), "sentinel in config at {step}");
    }
}

#[test]
fn long_scripted_session_leaks_no_sentinel() {
    let env = Env::new();
    let (mut s, clock) = env.unlocked();
    let mut sent: Vec<String> = [S_PW, S_NOTES, S_TOTP, S_FIELD, S_NEW, S_EXP, PW]
        .iter()
        .map(|x| x.to_string())
        .collect();
    check(&s, &env, &sent, "open");

    // Add an item carrying every kind of secret.
    s.dispatch(Action::BeginAdd(ItemKind::Login));
    s.dispatch(Action::SetTitle("site".into()));
    s.dispatch(Action::SetUsername("someone".into()));
    s.dispatch(Action::AddField);
    s.dispatch(Action::SetFieldName(0, "pin".into()));
    s.dispatch(Action::SetFieldHidden(0, true));
    s.dispatch(Action::SetTotpAlgorithm(TotpAlgorithm::Sha1));
    {
        let d = s.draft_mut().expect("draft");
        d.password.push_str(S_PW);
        d.notes.push_str(S_NOTES);
        d.totp_secret.push_str(S_TOTP);
        d.fields[0].value.push_str(S_FIELD);
    }
    s.dispatch(Action::ToggleDraftReveal(FieldRef::Password));
    check(&s, &env, &sent, "draft");
    s.dispatch(Action::SaveDraft);
    assert!(s.notice().is_none(), "{:?}", s.notice());
    check(&s, &env, &sent, "saved");

    // Browse, reveal, copy.
    s.dispatch(Action::Search("site".into()));
    let id = s.rows().first().expect("row").id.clone();
    s.dispatch(Action::Select(id));
    for f in [
        FieldRef::Password,
        FieldRef::Notes,
        FieldRef::TotpSecret,
        FieldRef::Custom(0),
    ] {
        s.dispatch(Action::ToggleReveal(f));
    }
    s.tick();
    check(&s, &env, &sent, "revealed");
    s.dispatch(Action::Copy(FieldRef::Password));
    assert_eq!(env.clipboard.text().as_deref(), Some(S_PW));
    s.dispatch(Action::Copy(FieldRef::TotpCode));
    clock.advance(Duration::from_secs(31));
    s.tick();
    assert!(env.clipboard.text().is_none_or(|t| !t.contains("SENTINEL")));
    s.dispatch(Action::Copy(FieldRef::Password));
    check(&s, &env, &sent, "copied");

    // Edit.
    s.dispatch(Action::BeginEdit);
    s.dispatch(Action::SetTitle("site 2".into()));
    s.dispatch(Action::SaveDraft);
    check(&s, &env, &sent, "edited");

    // Generate (the value is a sentinel too).
    s.dispatch(Action::Back);
    s.dispatch(Action::ShowGenerator);
    s.dispatch(Action::SetGeneratorMode(GeneratorMode::Password));
    s.dispatch(Action::SetPasswordOptions(PasswordOptions::default()));
    s.dispatch(Action::GenerateNow);
    if let Some(v) = s.generator().and_then(|g| g.value()) {
        sent.push(v.expose().to_owned());
    }
    s.dispatch(Action::ToggleGeneratedReveal);
    s.dispatch(Action::CopyGenerated);
    s.dispatch(Action::SetGeneratorMode(GeneratorMode::Passphrase));
    s.dispatch(Action::SetPassphraseOptions(PassphraseOptions::default()));
    s.dispatch(Action::GenerateNow);
    if let Some(v) = s.generator().and_then(|g| g.value()) {
        sent.push(v.expose().to_owned());
    }
    check(&s, &env, &sent, "generated");
    s.dispatch(Action::CloseGenerator);

    // Export, import.
    let export = env.path("x.opwx");
    s.dispatch(Action::ShowMaintenance(MaintenanceKind::Export));
    {
        let f = s.maintenance_form_mut();
        f.new.push_str(S_EXP);
        f.confirm.push_str(S_EXP);
    }
    env.picker.push(Some(export.clone()));
    s.dispatch(Action::SubmitExport);
    assert!(s.notice().is_none(), "{:?}", s.notice());
    check(&s, &env, &sent, "exported");
    let key = env.path("u.key");
    s.dispatch(Action::ShowMaintenance(MaintenanceKind::Import));
    s.maintenance_form_mut().new.push_str(S_EXP);
    env.picker.push(Some(export));
    env.picker.push(Some(key));
    s.dispatch(Action::SubmitImport);
    check(&s, &env, &sent, "imported");
    // A failing submit puts only a fixed notice on screen.
    s.dispatch(Action::ShowMaintenance(MaintenanceKind::ChangePassword));
    {
        let f = s.maintenance_form_mut();
        f.current.push_str(S_NEW);
        f.new.push_str(S_EXP);
        f.confirm.push_str("other");
    }
    s.dispatch(Action::SubmitChangePassword);
    assert!(s.notice().is_some());
    check(&s, &env, &sent, "mismatch");

    // Change password.
    s.dispatch(Action::ShowMaintenance(MaintenanceKind::ChangePassword));
    {
        let f = s.maintenance_form_mut();
        f.current.push_str(PW);
        f.new.push_str(S_NEW);
        f.confirm.push_str(S_NEW);
    }
    s.dispatch(Action::SubmitChangePassword);
    assert!(s.notice().is_none(), "{:?}", s.notice());
    check(&s, &env, &sent, "changed");

    // Lock.
    s.dispatch(Action::Lock);
    assert!(s.is_clean());
    check(&s, &env, &sent, "locked");
    clock.advance(Duration::from_secs(600));
    s.tick();
    assert!(s.is_clean());
    if let Some(t) = env.clipboard.text() {
        for x in &sent {
            assert!(!t.contains(x.as_str()), "sentinel left on the clipboard");
        }
    }
}

// ---- seeded randomised actions ----

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn flag(&mut self) -> bool {
        self.next() & 1 == 1
    }
    fn text(&mut self) -> String {
        match self.below(7) {
            0 => String::new(),
            1 => "a".into(),
            2 => "site".into(),
            3 => "pw-SENTINEL-x".into(),
            4 => "ü€".into(),
            5 => "  ".into(),
            _ => "x".repeat(300),
        }
    }
    fn field(&mut self) -> FieldRef {
        match self.below(5) {
            0 => FieldRef::Password,
            1 => FieldRef::Notes,
            2 => FieldRef::TotpSecret,
            3 => FieldRef::TotpCode,
            _ => FieldRef::Custom(self.below(3)),
        }
    }
    fn kind(&mut self) -> ItemKind {
        [ItemKind::Login, ItemKind::Note][self.below(2)]
    }
}

fn random_action(r: &mut Rng, s: &AppState) -> Action {
    use Action::*;
    match r.below(66) {
        0 => SubmitOpen,
        1 => SubmitCreate,
        2 => Lock,
        3 => Cancel,
        4 => ShowCreate,
        5 => ShowOpen,
        6 => BrowseVault,
        7 => BrowseKeyFile,
        8 => BrowseNewVault,
        9 => BrowseNewKeyFile,
        10 => ShowSettings,
        11 => CloseSettings,
        12 => SaveSettings,
        13 => Search(r.text()),
        14 => {
            let rows = s.rows();
            if rows.is_empty() || r.flag() {
                Select(onlypassword_core::ItemId([r.next() as u8; 16]))
            } else {
                Select(rows[r.below(rows.len())].id.clone())
            }
        }
        15 => ToggleReveal(r.field()),
        16 => Copy(r.field()),
        17 => Back,
        18 => BeginAdd(r.kind()),
        19 => BeginEdit,
        20 => SaveDraft,
        21 => CancelDraft,
        22 => RequestDelete,
        23 => ConfirmDelete,
        24 => CancelDelete,
        25 => SetKind(r.kind()),
        26 => SetTitle(r.text()),
        27 => SetUsername(r.text()),
        28 => SetUrl(r.below(3), r.text()),
        29 => AddUrl,
        30 => RemoveUrl(r.below(3)),
        31 => SetTotpAlgorithm(
            [
                TotpAlgorithm::Sha1,
                TotpAlgorithm::Sha256,
                TotpAlgorithm::Sha512,
            ][r.below(3)],
        ),
        32 => SetTotpDigits([0, 6, 8, 255][r.below(4)]),
        33 => SetTotpPeriod([0, 30, 60, u32::MAX][r.below(4)]),
        34 => AddField,
        35 => RemoveField(r.below(3)),
        36 => SetFieldName(r.below(3), r.text()),
        37 => SetFieldHidden(r.below(3), r.flag()),
        38 => ToggleDraftReveal(r.field()),
        39 => ShowGenerator,
        40 => CloseGenerator,
        41 => ToggleGeneratorPanel,
        42 => SetGeneratorMode([GeneratorMode::Password, GeneratorMode::Passphrase][r.below(2)]),
        43 => SetPasswordOptions(PasswordOptions {
            length: [0, 1, 20, 100_000][r.below(4)],
            lower: r.flag(),
            upper: r.flag(),
            digits: r.flag(),
            symbols: r.flag(),
            exclude_ambiguous: r.flag(),
            require_each: r.flag(),
        }),
        44 => SetPassphraseOptions(PassphraseOptions {
            words: [0, 1, 6, 100_000][r.below(4)],
            separator: r.text(),
            capitalize: r.flag(),
            include_digit: r.flag(),
        }),
        45 => GenerateNow,
        46 => UseGenerated,
        47 => CopyGenerated,
        48 => DiscardGenerated,
        49 => ToggleGeneratedReveal,
        50 => ShowMaintenance(
            [
                MaintenanceKind::ChangePassword,
                MaintenanceKind::RotateKey,
                MaintenanceKind::Export,
                MaintenanceKind::Import,
            ][r.below(4)],
        ),
        51 => SubmitChangePassword,
        52 => SubmitRotate,
        53 => SubmitExport,
        54 => SubmitImport,
        55 => CancelMaintenance,
        _ => Activity,
    }
}

/// Type into the form buffers the way a user would, valid or not.
fn random_typing(
    r: &mut Rng,
    s: &mut AppState,
    env: &Env,
    vault: &std::path::Path,
    key: &std::path::Path,
) {
    match r.below(8) {
        0 => {
            let f = s.open_form_mut();
            f.vault_path = vault.to_string_lossy().into_owned();
            f.key_path = key.to_string_lossy().into_owned();
            f.password.push_str(if r.flag() { PW } else { "wrong" });
        }
        1 => {
            let f = s.create_form_mut();
            f.vault_path = env
                .path(&format!("n{}.opw", r.below(4)))
                .to_string_lossy()
                .into_owned();
            f.key_path = env
                .path(&format!("n{}.key", r.below(4)))
                .to_string_lossy()
                .into_owned();
            f.password.push_str("pw-SENTINEL-new");
            f.confirm
                .push_str(if r.flag() { "pw-SENTINEL-new" } else { "no" });
        }
        2 => {
            let f = s.maintenance_form_mut();
            f.current.push_str(if r.flag() { PW } else { "bad" });
            f.new.push_str("pw-SENTINEL-m");
            f.confirm
                .push_str(if r.flag() { "pw-SENTINEL-m" } else { "z" });
            f.confirmed = r.flag();
            f.rotate = r.flag();
        }
        3 => {
            if let Some(d) = s.draft_mut() {
                d.password.push_str(&r.text());
                d.notes.push_str(&r.text());
                d.totp_secret
                    .push_str(if r.flag() { "JBSWY3DPEHPK3PXP" } else { "!!" });
                if let Some(f) = d.fields.first_mut() {
                    f.value.push_str(&r.text());
                }
            }
        }
        4 => {
            let f = s.settings_form_mut();
            f.idle_timeout_secs =
                ["10", "0", "x", "99999999999", "300", "86400"][r.below(6)].into();
            f.clipboard_clear_secs = ["5", "0", "-1", "30", "3600"][r.below(5)].into();
        }
        5 => env.picker.push(Some(vault.to_path_buf())),
        6 => env.picker.push(Some(key.to_path_buf())),
        _ => env.picker.push(if r.flag() {
            None
        } else {
            Some(env.path(&format!("e{}.opwx", r.below(3))))
        }),
    }
}

fn run_random(seed: u64) {
    let env = Env::new();
    let (v, k) = env.make_vault("r.opw", "r.key");
    let (mut s, clock) = env.state_with_clock();
    let mut r = Rng(seed | 1);
    for _ in 0..2_000 {
        if r.below(3) == 0 {
            random_typing(&mut r, &mut s, &env, &v, &k);
        }
        let a = random_action(&mut r, &s);
        s.dispatch(a);
        match r.below(6) {
            0 => clock.advance(Duration::from_secs(r.below(40) as u64)),
            1 => clock.advance(Duration::from_secs(r.below(4000) as u64)),
            2 => s.tick(),
            _ => {}
        }
        let shown = visible(&s);
        assert!(!shown.contains("SENTINEL"), "seed {seed}: sentinel visible");
    }
    s.dispatch(Action::Lock);
    s.tick();
    assert!(
        s.is_clean(),
        "seed {seed}: not clean after lock; screen {:?}",
        s.screen()
    );
}

#[test]
fn random_actions_never_panic_seed_1() {
    run_random(0x1234_5678_9ABC_DEF1);
}
#[test]
fn random_actions_never_panic_seed_2() {
    run_random(0xDEAD_BEEF_CAFE_F00D);
}
#[test]
fn random_actions_never_panic_seed_3() {
    run_random(42);
}
#[test]
fn random_actions_never_panic_seed_4() {
    run_random(0x0BAD_5EED_0000_0007);
}

// ---- fixed Display strings ----

const FIXED_UI: &[&str] = &[
    "the passwords do not match",
    "a required field is empty",
    "nothing is selected",
    "confirmation is required",
    "the clipboard is not available",
    "the settings file is invalid; defaults are in use",
    "the settings could not be saved",
    "a setting is outside its allowed range",
    "cancelled",
];
const FIXED_CORE: &[&str] = &[
    "authentication failed",
    "data is corrupt",
    "unsupported version",
    "invalid input",
    "not found",
    "conflict",
    "limit exceeded",
    "random number generator failure",
    "i/o error",
];

#[test]
fn every_display_string_is_from_a_fixed_list() {
    let cores = [
        Error::Authentication,
        Error::Corrupt("/tmp/x {SENTINEL}"),
        Error::UnsupportedVersion,
        Error::InvalidInput("pw-SENTINEL"),
        Error::NotFound,
        Error::Conflict,
        Error::LimitExceeded,
        Error::Rng,
        Error::Io(std::io::ErrorKind::PermissionDenied),
    ];
    let ui = [
        UiError::PasswordMismatch,
        UiError::EmptyField,
        UiError::NoSelection,
        UiError::ConfirmationRequired,
        UiError::Clipboard,
        UiError::ConfigInvalid,
        UiError::ConfigWrite,
        UiError::InvalidSetting,
        UiError::PickerCancelled,
    ];
    let sentinels = [S_PW, S_NOTES, S_TOTP, S_FIELD, S_NEW, S_EXP, PW, "SENTINEL"];
    let mut shown: Vec<(String, &[&str])> = Vec::new();
    for e in &ui {
        shown.push((e.to_string(), FIXED_UI));
    }
    for e in cores {
        shown.push((e.to_string(), FIXED_CORE));
        shown.push((UiError::Core(e).to_string(), FIXED_CORE));
    }
    for (text, list) in shown {
        assert!(!text.is_empty());
        assert!(!text.contains('{') && !text.contains('}'), "{text}");
        // The core's own fixed text "i/o error" is the only string with a slash.
        assert!(!text.replace("i/o", "io").contains(['/', '\\']), "{text}");
        for x in sentinels {
            assert!(!text.contains(x), "{text}");
        }
        assert!(list.contains(&text.as_str()), "not in fixed list: {text}");
    }
    // The UI list has no duplicates, so each variant has its own message.
    let mut u = FIXED_UI.to_vec();
    u.sort();
    u.dedup();
    assert_eq!(u.len(), FIXED_UI.len());
    let _ = Screen::Open;
}
