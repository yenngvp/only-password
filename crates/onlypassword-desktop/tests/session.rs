mod common;

use common::*;
use onlypassword_core::Error;
use onlypassword_desktop::error::UiError;
use onlypassword_desktop::state::{Action, Screen};

fn core_msg(e: Error) -> String {
    UiError::Core(e).to_string()
}

#[test]
fn create_flow_writes_files_and_config() {
    let env = Env::new();
    let mut s = env.state();
    assert_eq!(s.screen(), &Screen::Open);
    s.dispatch(Action::ShowCreate);
    assert_eq!(s.screen(), &Screen::Create);
    let (v, k) = (env.path("v.opw"), env.path("v.key"));
    fill_create(&mut s, &v, &k, PW, PW);
    s.dispatch(Action::SubmitCreate);
    assert!(s.notice().is_none(), "{:?}", s.notice());
    assert_eq!(s.screen(), &Screen::Browse);
    assert!(v.exists() && k.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&k).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert!(s.create_form_mut().password.is_empty());
    assert!(s.create_form_mut().confirm.is_empty());
    let cfg = std::fs::read_to_string(env.config_dir().join("config.json")).unwrap();
    assert!(cfg.contains(v.to_str().unwrap()));
    assert!(!cfg.contains(k.to_str().unwrap()));
    assert!(!cfg.contains("v.key"));
    assert_eq!(s.config().last_vault_path.as_deref(), Some(v.as_path()));
}

#[test]
fn create_mismatch_touches_nothing_and_keeps_paths() {
    let env = Env::new();
    let mut s = env.state();
    s.dispatch(Action::ShowCreate);
    let (v, k) = (env.path("v.opw"), env.path("v.key"));
    fill_create(&mut s, &v, &k, PW, "something else");
    s.dispatch(Action::SubmitCreate);
    assert_eq!(s.notice(), Some(&UiError::PasswordMismatch));
    assert_eq!(s.screen(), &Screen::Create);
    assert!(!v.exists() && !k.exists());
    assert_eq!(s.create_form_mut().vault_path, v.to_string_lossy());
    assert_eq!(s.create_form_mut().key_path, k.to_string_lossy());
    assert!(s.create_form_mut().password.is_empty());
    assert!(s.create_form_mut().confirm.is_empty());
    assert!(!env.config_dir().join("config.json").exists());
}

#[test]
fn create_with_existing_key_file_overwrites_nothing() {
    let env = Env::new();
    let mut s = env.state();
    s.dispatch(Action::ShowCreate);
    let (v, k) = (env.path("v.opw"), env.path("v.key"));
    std::fs::write(&k, "precious").unwrap();
    fill_create(&mut s, &v, &k, PW, PW);
    s.dispatch(Action::SubmitCreate);
    let want = core_msg(Error::Io(std::io::ErrorKind::AlreadyExists));
    assert_eq!(s.notice().map(|e| e.to_string()), Some(want));
    assert_eq!(std::fs::read_to_string(&k).unwrap(), "precious");
    assert!(!v.exists());
    assert_eq!(s.screen(), &Screen::Create);
}

#[test]
fn lock_cleans_everything_and_is_idempotent() {
    let env = Env::new();
    let mut s = env.state();
    s.dispatch(Action::ShowCreate);
    fill_create(&mut s, &env.path("v.opw"), &env.path("v.key"), PW, PW);
    s.dispatch(Action::SubmitCreate);
    assert!(s.is_unlocked() && !s.is_clean());
    // Leave secrets in the buffers; lock must clear them.
    s.open_form_mut().password.push_str(PW);
    s.create_form_mut().password.push_str(PW);
    s.dispatch(Action::Lock);
    assert_eq!(s.screen(), &Screen::Unlock);
    assert!(s.is_clean());
    assert!(s.notice().is_none());
    let dbg = format!("{s:?}");
    assert!(!dbg.contains("SENTINEL") && !dbg.contains("key"), "{dbg}");
    assert!(s.open_form_mut().password.is_empty());
    s.dispatch(Action::Lock);
    assert_eq!(s.screen(), &Screen::Unlock);
    assert!(s.is_clean());
}

#[test]
fn open_flow_and_failure_messages() {
    let env = Env::new();
    let (v, k) = env.make_vault("a.opw", "a.key");
    let (_v2, k2) = env.make_vault("b.opw", "b.key");

    let mut s = env.state();
    // Correct credentials.
    fill_open(&mut s, &v, &k, PW);
    s.dispatch(Action::SubmitOpen);
    assert!(s.notice().is_none());
    assert_eq!(s.screen(), &Screen::Browse);
    assert!(s.open_form_mut().password.is_empty());
    s.dispatch(Action::Lock);
    assert_eq!(s.screen(), &Screen::Unlock);

    let auth = core_msg(Error::Authentication);
    // Wrong password.
    fill_open(&mut s, &v, &k, "wrong");
    s.dispatch(Action::SubmitOpen);
    assert_eq!(s.notice().map(|e| e.to_string()), Some(auth.clone()));
    assert_eq!(s.screen(), &Screen::Unlock);
    assert!(s.open_form_mut().password.is_empty());
    // Wrong key file.
    fill_open(&mut s, &v, &k2, PW);
    s.dispatch(Action::SubmitOpen);
    assert_eq!(s.notice().map(|e| e.to_string()), Some(auth.clone()));
    assert_eq!(s.screen(), &Screen::Unlock);

    // Missing key file.
    fill_open(&mut s, &v, &env.path("nokey"), PW);
    s.dispatch(Action::SubmitOpen);
    let missing_key = s.notice().map(|e| e.to_string()).unwrap();
    assert_ne!(missing_key, auth);
    assert_eq!(
        missing_key,
        core_msg(Error::Io(std::io::ErrorKind::NotFound))
    );
    assert!(s.open_form_mut().password.is_empty());

    // Malformed key file.
    let bad = env.path("bad.key");
    std::fs::write(&bad, "not a key\n").unwrap();
    fill_open(&mut s, &v, &bad, PW);
    s.dispatch(Action::SubmitOpen);
    let malformed = s.notice().map(|e| e.to_string()).unwrap();
    assert_ne!(malformed, auth);

    // Missing vault.
    fill_open(&mut s, &env.path("novault"), &k, PW);
    s.dispatch(Action::SubmitOpen);
    let nov = s.notice().map(|e| e.to_string()).unwrap();
    assert_eq!(nov, core_msg(Error::Io(std::io::ErrorKind::NotFound)));

    // Vault with a flipped byte (magic/header region).
    let mut bytes = std::fs::read(&v).unwrap();
    bytes[0] ^= 0x01;
    let flipped = env.path("flipped.opw");
    std::fs::write(&flipped, &bytes).unwrap();
    fill_open(&mut s, &flipped, &k, PW);
    s.dispatch(Action::SubmitOpen);
    let corrupt = s.notice().map(|e| e.to_string()).unwrap();
    assert_ne!(corrupt, auth);
    assert_eq!(s.screen(), &Screen::Unlock);

    // Empty fields.
    fill_open(&mut s, &v, &k, PW);
    s.open_form_mut().key_path.clear();
    s.dispatch(Action::SubmitOpen);
    assert_eq!(s.notice(), Some(&UiError::EmptyField));
    assert!(s.open_form_mut().password.is_empty());
}

#[test]
fn start_screen_follows_config_and_picker_cancel_is_silent() {
    let env = Env::new();
    let (v, k) = env.make_vault("a.opw", "a.key");
    let mut s = env.state();
    fill_open(&mut s, &v, &k, PW);
    s.dispatch(Action::SubmitOpen);
    assert_eq!(s.screen(), &Screen::Browse);
    s.on_exit();
    drop(s);

    let mut s2 = env.state();
    assert_eq!(s2.screen(), &Screen::Unlock);
    assert_eq!(s2.open_form_mut().vault_path, v.to_string_lossy());
    assert!(s2.open_form_mut().key_path.is_empty());

    // Cancelled picker: nothing changes, no notice. Then a real answer.
    env.picker.push(None);
    s2.dispatch(Action::BrowseKeyFile);
    assert!(s2.notice().is_none());
    assert!(s2.open_form_mut().key_path.is_empty());
    env.picker.push(Some(k.clone()));
    s2.dispatch(Action::BrowseKeyFile);
    assert_eq!(s2.open_form_mut().key_path, k.to_string_lossy());
}

#[test]
fn config_save_failure_only_sets_notice() {
    let env = Env::new();
    let (v, k) = env.make_vault("a.opw", "a.key");
    let mut s = env.state();
    // Break the config directory after the state loaded it.
    std::fs::remove_dir_all(env.config_dir()).unwrap();
    std::fs::write(env.config_dir(), "a file, not a dir").unwrap();
    fill_open(&mut s, &v, &k, PW);
    s.dispatch(Action::SubmitOpen);
    assert_eq!(s.screen(), &Screen::Browse);
    assert_eq!(s.notice(), Some(&UiError::ConfigWrite));
}

#[test]
fn random_actions_never_panic() {
    let env = Env::new();
    let (v, k) = env.make_vault("a.opw", "a.key");
    let mut s = env.state();
    let all = [
        Action::SubmitOpen,
        Action::SubmitCreate,
        Action::Lock,
        Action::Cancel,
        Action::ShowCreate,
        Action::ShowOpen,
        Action::BrowseVault,
        Action::BrowseKeyFile,
        Action::BrowseNewVault,
        Action::BrowseNewKeyFile,
    ];
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for i in 0..500 {
        let r = next();
        if r % 3 == 0 {
            fill_open(&mut s, &v, &k, if r % 2 == 0 { PW } else { "bad" });
        }
        if r % 5 == 0 {
            env.picker.push(Some(env.path(&format!("n{i}"))));
        }
        let a = all[(next() % all.len() as u64) as usize].clone();
        s.dispatch(a);
        s.tick();
        if s.is_clean() {
            assert!(!s.is_unlocked());
        }
    }
    s.on_exit();
    assert!(s.is_clean());
}
