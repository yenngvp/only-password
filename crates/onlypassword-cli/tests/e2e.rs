use onlypassword_core::{CustomField, Item, ItemId, SecretString, Vault};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const PW: &str = "correct horse battery";

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Env {
        Env {
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn vault(&self) -> PathBuf {
        self.dir.path().join("v.opv")
    }
    fn key(&self) -> PathBuf {
        self.dir.path().join("k.key")
    }
    fn globals(&self) -> Vec<OsString> {
        vec![
            "--vault".into(),
            self.vault().into(),
            "--secret-key-file".into(),
            self.key().into(),
            "--stdin".into(),
        ]
    }
    fn run(&self, args: &[&str], input: &str) -> Output {
        let mut a = self.globals();
        a.extend(args.iter().map(OsString::from));
        run_raw(&a, input)
    }
    fn init(&self) {
        let o = self.run(&["init"], &format!("{PW}\n{PW}\n"));
        assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    }
}

fn run_raw(args: &[OsString], input: &str) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_onlypassword"))
        .args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The process may exit before reading its input (usage errors).
    let _ = c.stdin.take().unwrap().write_all(input.as_bytes());
    c.wait_with_output().unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}
fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}
fn files(d: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(d)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    v.sort();
    v
}

#[test]
fn init_note_list_search_get_delete() {
    let e = Env::new();
    e.init();
    let notes = e.dir.path().join("n.txt");
    std::fs::write(&notes, "file notes body").unwrap();

    let o = e.run(
        &["add-note", "--title", "Alpha", "--notes"],
        &format!("{PW}\nprompt notes body\n"),
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    let id1 = out(&o).trim().to_string();
    assert_eq!(id1.len(), 32);
    assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));

    let o = e.run(
        &[
            "add-note",
            "--title",
            "Beta",
            "--notes-file",
            notes.to_str().unwrap(),
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    let id2 = out(&o).trim().to_string();
    assert_ne!(id1, id2);

    let o = e.run(&["list"], &format!("{PW}\n"));
    assert_eq!(code(&o), 0);
    let text = out(&o);
    let mut lines: Vec<&str> = text.lines().collect();
    lines.sort();
    let mut want = vec![
        format!("{id1}\tnote\tAlpha\t"),
        format!("{id2}\tnote\tBeta\t"),
    ];
    want.sort();
    assert_eq!(lines, want);

    let o = e.run(&["search", "alp"], &format!("{PW}\n"));
    assert_eq!(code(&o), 0);
    assert_eq!(out(&o), format!("{id1}\tnote\tAlpha\t\n"));

    let o = e.run(&["get", &id1], &format!("{PW}\n"));
    assert_eq!(code(&o), 0);
    assert!(out(&o).contains("title: Alpha"));
    assert!(out(&o).contains("<hidden>"));
    assert!(!out(&o).contains("prompt notes body"));
    let o = e.run(&["get", &id2, "--show-secrets"], &format!("{PW}\n"));
    assert!(out(&o).contains("file notes body"));

    let o = e.run(&["delete", &id1], &format!("{PW}\n"));
    assert_eq!(code(&o), 0, "{}", err(&o));
    let o = e.run(&["list"], &format!("{PW}\n"));
    assert_eq!(out(&o), format!("{id2}\tnote\tBeta\t\n"));
    let o = e.run(&["get", &id1], &format!("{PW}\n"));
    assert_eq!(code(&o), 1);
    let o = e.run(&["delete", &id1], &format!("{PW}\n"));
    assert_eq!(code(&o), 1);
    // well-formed but unknown id
    let o = e.run(&["get", &"0".repeat(32)], &format!("{PW}\n"));
    assert_eq!(code(&o), 1);
}

#[test]
fn get_hides_secrets_unless_shown() {
    let e = Env::new();
    e.init();
    let key = onlypassword_core::crypto::keys::SecretKey::from_key_file_text(
        &std::fs::read_to_string(e.key()).unwrap(),
    )
    .unwrap();
    let mut v = Vault::unlock(&e.vault(), &SecretString::new(PW.into()), &key).unwrap();
    let mut item = Item::new_login("Site");
    item.username = Some("someuser".into());
    item.password = Some(SecretString::new("PASSWORD-VALUE-1".into()));
    item.notes = SecretString::new("NOTES-VALUE-2".into());
    item.totp = Some(onlypassword_core::TotpConfig {
        secret: SecretString::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
        algorithm: onlypassword_core::TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
    });
    item.fields = vec![
        CustomField {
            name: "pin".into(),
            value: SecretString::new("HIDDEN-FIELD-4".into()),
            hidden: true,
        },
        CustomField {
            name: "shown".into(),
            value: SecretString::new("PLAIN-FIELD-5".into()),
            hidden: false,
        },
    ];
    let id: ItemId = v.add(&item).unwrap();
    let id = id.to_string();

    let o = e.run(&["get", &id], &format!("{PW}\n"));
    assert_eq!(code(&o), 0, "{}", err(&o));
    let t = out(&o);
    for secret in [
        "PASSWORD-VALUE-1",
        "NOTES-VALUE-2",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "HIDDEN-FIELD-4",
    ] {
        assert!(!t.contains(secret), "{secret} leaked");
        assert!(!err(&o).contains(secret));
    }
    assert_eq!(t.matches("<hidden>").count(), 4, "{t}");
    assert!(t.contains("PLAIN-FIELD-5"));
    assert!(t.contains("someuser"));

    let o = e.run(&["get", &id, "--show-secrets"], &format!("{PW}\n"));
    let t = out(&o);
    for secret in [
        "PASSWORD-VALUE-1",
        "NOTES-VALUE-2",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "HIDDEN-FIELD-4",
    ] {
        assert!(t.contains(secret), "{secret} missing");
    }
    assert!(!t.contains("<hidden>"));
}

#[test]
fn init_success_properties() {
    let e = Env::new();
    let o = e.run(&["init"], &format!("{PW}\n{PW}\n"));
    assert_eq!(code(&o), 0);
    let keytext = std::fs::read_to_string(e.key()).unwrap();
    let keytext = keytext.trim();
    assert!(keytext.starts_with("OPSK1-"));
    assert!(!out(&o).contains(keytext) && !err(&o).contains(keytext));
    assert!(out(&o).contains(e.vault().to_str().unwrap()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(e.key()).unwrap().permissions().mode();
        assert_eq!(m & 0o777, 0o600);
    }
    let key = onlypassword_core::crypto::keys::SecretKey::from_text(keytext).unwrap();
    assert!(Vault::unlock(&e.vault(), &SecretString::new(PW.into()), &key).is_ok());
    assert_eq!(files(e.dir.path()), vec!["k.key", "v.opv"]);
}

#[test]
fn init_print_secret_key() {
    let e = Env::new();
    let o = e.run(&["init", "--print-secret-key"], &format!("{PW}\n{PW}\n"));
    assert_eq!(code(&o), 0);
    let keytext = std::fs::read_to_string(e.key()).unwrap();
    assert!(out(&o).contains(keytext.trim()));
}

#[test]
fn init_failures_leave_nothing_behind() {
    let input = format!("{PW}\n{PW}\n");

    // existing key file is untouched, no vault created
    let e = Env::new();
    std::fs::write(e.key(), "precious").unwrap();
    let o = e.run(&["init"], &input);
    assert_eq!(code(&o), 1);
    assert_eq!(std::fs::read_to_string(e.key()).unwrap(), "precious");
    assert_eq!(files(e.dir.path()), vec!["k.key"]);

    // existing vault path is untouched, no key file created
    let e = Env::new();
    std::fs::write(e.vault(), "precious").unwrap();
    let o = e.run(&["init"], &input);
    assert_eq!(code(&o), 1);
    assert_eq!(std::fs::read_to_string(e.vault()).unwrap(), "precious");
    assert_eq!(files(e.dir.path()), vec!["v.opv"]);

    // missing key-file directory
    let e = Env::new();
    let a: Vec<OsString> = vec![
        "--vault".into(),
        e.vault().into(),
        "--secret-key-file".into(),
        e.dir.path().join("missing/k.key").into(),
        "--stdin".into(),
        "init".into(),
    ];
    let o = run_raw(&a, &input);
    assert_eq!(code(&o), 1);
    assert!(files(e.dir.path()).is_empty());

    // key file path == vault path
    let e = Env::new();
    let same = e.dir.path().join("same");
    let a: Vec<OsString> = vec![
        "--vault".into(),
        same.clone().into(),
        "--secret-key-file".into(),
        same.into(),
        "--stdin".into(),
        "init".into(),
    ];
    let o = run_raw(&a, &input);
    assert_eq!(code(&o), 1);
    assert!(files(e.dir.path()).is_empty());

    // short password: nothing is created
    let e = Env::new();
    let o = e.run(&["init"], "short\nshort\n");
    assert_eq!(code(&o), 1);
    assert!(files(e.dir.path()).is_empty());

    // mismatching confirmation: usage error, nothing created
    let o = e.run(&["init"], &format!("{PW}\nother password\n"));
    assert_eq!(code(&o), 2);
    assert!(files(e.dir.path()).is_empty());
}

#[cfg(unix)]
#[test]
fn init_vault_creation_failure_removes_key_file() {
    use std::os::unix::fs::PermissionsExt;
    let e = Env::new();
    let vdir = e.dir.path().join("ro");
    std::fs::create_dir(&vdir).unwrap();
    std::fs::set_permissions(&vdir, std::fs::Permissions::from_mode(0o500)).unwrap();
    // Running as root bypasses permissions; then there is no failure to test.
    if std::fs::File::create(vdir.join("probe")).is_ok() {
        return;
    }
    let a: Vec<OsString> = vec![
        "--vault".into(),
        vdir.join("v.opv").into(),
        "--secret-key-file".into(),
        e.key().into(),
        "--stdin".into(),
        "init".into(),
    ];
    let o = run_raw(&a, &format!("{PW}\n{PW}\n"));
    std::fs::set_permissions(&vdir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(code(&o), 1);
    assert_eq!(files(e.dir.path()), vec!["ro"]);
    assert!(files(&vdir).is_empty());
}

#[test]
fn error_exit_codes() {
    let e = Env::new();
    e.init();
    let o = e.run(&["list"], "wrong password!\n");
    assert_eq!(code(&o), 3);
    assert!(!err(&o).contains("wrong password"));
    assert_eq!(err(&o).trim().lines().count(), 1);

    // missing stdin line
    assert_eq!(code(&e.run(&["list"], "")), 2);
    // unknown flag / command
    assert_eq!(code(&e.run(&["list", "--bogus"], &format!("{PW}\n"))), 2);
    assert_eq!(code(&e.run(&["frobnicate"], &format!("{PW}\n"))), 2);
    // missing --vault / --secret-key-file
    let k: Vec<OsString> = vec!["--secret-key-file".into(), e.key().into(), "list".into()];
    assert_eq!(code(&run_raw(&k, "")), 2);
    let v: Vec<OsString> = vec!["--vault".into(), e.vault().into(), "list".into()];
    assert_eq!(code(&run_raw(&v, "")), 2);
}

#[test]
fn no_secret_arguments() {
    let e = Env::new();
    e.init();
    for args in [
        vec!["add-note", "--title", "t", "--password", "hunter22"],
        vec!["add-note", "--title", "t", "--notes=SECRET TEXT"],
        vec!["list", "--password=hunter22"],
        vec!["init", "--password", "hunter22"],
    ] {
        let o = e.run(&args, &format!("{PW}\nx\n"));
        assert_eq!(code(&o), 2, "{args:?}");
        assert!(!err(&o).contains("hunter22") && !err(&o).contains("SECRET TEXT"));
    }
    // env is not consulted either
    let mut c = Command::new(env!("CARGO_BIN_EXE_onlypassword"));
    c.args(e.globals())
        .arg("list")
        .env("ONLYPASSWORD_PASSWORD", PW)
        .env("PASSWORD", PW)
        .stdin(Stdio::null());
    assert_eq!(c.output().unwrap().status.code(), Some(2));
}

#[test]
fn key_file_forms() {
    let e = Env::new();
    e.init();
    let good = std::fs::read_to_string(e.key()).unwrap();
    let good = good.trim().to_string();
    let input = format!("{PW}\n");
    for form in [
        format!("{good}\r\n"),
        good.clone(),
        format!("  {good}  \n\n"),
    ] {
        std::fs::write(e.key(), form).unwrap();
        let o = e.run(&["list"], &input);
        assert_eq!(code(&o), 0, "{}", err(&o));
    }
    for bad in [
        format!("\u{feff}{good}\n"),
        "garbage garbage".to_string(),
        format!("{good}extra"),
    ] {
        std::fs::write(e.key(), &bad).unwrap();
        let o = e.run(&["list"], &input);
        assert_eq!(code(&o), 1);
        assert!(!err(&o).contains(&good) && !out(&o).contains(&good));
        assert!(!err(&o).contains("garbage"));
    }
}

#[test]
fn hostile_argv_does_not_panic() {
    let o = run_raw(&[], "");
    assert_eq!(code(&o), 2);
    let o = run_raw(&["".into()], "");
    assert_eq!(code(&o), 2);
    let o = run_raw(&["nonsense".into()], "");
    assert_eq!(code(&o), 2);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![b'x', 0xff, 0xc0]);
        for argv in [
            vec![bad.clone()],
            vec!["--vault".into(), bad.clone(), "list".into()],
            vec![
                "--vault".into(),
                "v".into(),
                "--secret-key-file".into(),
                "k".into(),
                "search".into(),
                bad.clone(),
            ],
            vec![
                "--vault".into(),
                "v".into(),
                "--secret-key-file".into(),
                "k".into(),
                "get".into(),
                bad.clone(),
            ],
        ] {
            let o = run_raw(&argv, "");
            assert_eq!(code(&o), 2, "{argv:?}");
        }
    }
}

#[test]
fn notes_file_problems_exit_1() {
    let e = Env::new();
    e.init();
    let big = e.dir.path().join("big.txt");
    std::fs::write(&big, vec![b'a'; 65_537]).unwrap();
    let bin = e.dir.path().join("bin.txt");
    std::fs::write(&bin, [0xff, 0xfe]).unwrap();
    for f in [big, bin, e.dir.path().join("absent.txt")] {
        let o = e.run(
            &[
                "add-note",
                "--title",
                "t",
                "--notes-file",
                f.to_str().unwrap(),
            ],
            &format!("{PW}\n"),
        );
        assert_eq!(code(&o), 1);
    }
    // exactly one of --notes / --notes-file
    assert_eq!(
        code(&e.run(&["add-note", "--title", "t"], &format!("{PW}\n"))),
        2
    );
}
