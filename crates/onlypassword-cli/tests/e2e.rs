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

// ---- F020: add-login and update ----

const TOTP_PASTED: &str = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
const TOTP_CANON: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn open(e: &Env) -> Vault {
    let key = onlypassword_core::crypto::keys::SecretKey::from_key_file_text(
        &std::fs::read_to_string(e.key()).unwrap(),
    )
    .unwrap();
    Vault::unlock(&e.vault(), &SecretString::new(PW.into()), &key).unwrap()
}

/// Runs a command and asserts no secret value appears anywhere in its argv.
fn run_checked(e: &Env, args: &[&str], input: &str, secrets: &[&str]) -> Output {
    for a in args {
        for s in secrets {
            assert!(!a.contains(s), "secret {s} found in argv");
        }
    }
    e.run(args, input)
}

const SECRETS: [&str; 6] = [
    "LOGIN-PW-1",
    "NOTES-TEXT-2",
    "HIDDEN-ONE-3",
    "HIDDEN-TWO-4",
    "gezd gnbv",
    "NOTES-FILE-5",
];

#[test]
fn add_login_full_item() {
    let e = Env::new();
    e.init();
    let input =
        format!("{PW}\nLOGIN-PW-1\n{TOTP_PASTED}\nNOTES-TEXT-2\nHIDDEN-ONE-3\nHIDDEN-TWO-4\n");
    let o = run_checked(
        &e,
        &[
            "add-login",
            "--title",
            "Site",
            "--username",
            "alice",
            "--url",
            "https://a.example",
            "--url",
            "https://b.example",
            "--totp",
            "--totp-digits",
            "8",
            "--totp-period",
            "30",
            "--totp-algorithm",
            "sha1",
            "--field",
            "pub=PLAIN=eq",
            "--hidden-field",
            "pin",
            "--notes",
            "--hidden-field",
            "cvv",
        ],
        &input,
        &SECRETS,
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    let id = out(&o).trim().to_string();
    assert_eq!(id.len(), 32);

    let o = e.run(&["get", &id, "--show-secrets"], &format!("{PW}\n"));
    let t = out(&o);
    for want in [
        "username: alice",
        "password: LOGIN-PW-1",
        "url: https://a.example",
        "url: https://b.example",
        "notes: NOTES-TEXT-2",
        "field pub: PLAIN=eq",
        "field pin: HIDDEN-ONE-3",
        "field cvv: HIDDEN-TWO-4",
    ] {
        assert!(t.contains(want), "missing {want} in {t}");
    }
    // Core library view: exact stored values and prompt order.
    let stored = open(&e).get(&id.parse().unwrap()).unwrap();
    let totp = stored.item.totp.unwrap();
    assert_eq!(totp.secret.expose(), TOTP_CANON);
    assert_eq!(totp.digits, 8);
    assert_eq!(totp.period, 30);
    assert_eq!(totp.algorithm, onlypassword_core::TotpAlgorithm::Sha1);
    let f: Vec<_> = stored
        .item
        .fields
        .iter()
        .map(|f| (f.name.as_str(), f.value.expose(), f.hidden))
        .collect();
    assert_eq!(
        f,
        vec![
            ("pub", "PLAIN=eq", false),
            ("pin", "HIDDEN-ONE-3", true),
            ("cvv", "HIDDEN-TWO-4", true)
        ]
    );
    assert_eq!(stored.item.urls.len(), 2);
}

#[test]
fn add_login_defaults_usage_and_generate() {
    let e = Env::new();
    e.init();
    let o = e.run(
        &["add-login", "--title", "A", "--totp"],
        &format!("{PW}\nLOGIN-PW-1\n{TOTP_CANON}\n"),
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    let id = out(&o).trim().to_string();
    let t = open(&e)
        .get(&id.parse().unwrap())
        .unwrap()
        .item
        .totp
        .unwrap();
    assert_eq!(
        (t.algorithm, t.digits, t.period),
        (onlypassword_core::TotpAlgorithm::Sha1, 6, 30)
    );

    for bad in [
        vec!["add-login", "--title", "A", "--totp-digits", "8"],
        vec!["add-login", "--title", "A", "--totp-period", "30"],
        vec!["add-login", "--title", "A", "--totp-algorithm", "sha1"],
    ] {
        let o = e.run(&bad, &format!("{PW}\nx\n"));
        assert_eq!(code(&o), 2, "{bad:?}");
    }
    assert_eq!(open(&e).list().unwrap().len(), 1);

    // --generate: no password prompt, not printed without --show-secrets.
    let o = e.run(
        &["add-login", "--title", "G", "--generate"],
        &format!("{PW}\n"),
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    let gid = out(&o).trim().to_string();
    assert_eq!(gid.len(), 32, "only the id is printed: {}", out(&o));
    let o = e.run(&["get", &gid, "--show-secrets"], &format!("{PW}\n"));
    let line = out(&o)
        .lines()
        .find(|l| l.starts_with("password: "))
        .unwrap()
        .to_string();
    let pw = line.trim_start_matches("password: ");
    assert_eq!(pw.len(), 20);
    let o = e.run(&["get", &gid], &format!("{PW}\n"));
    assert!(!out(&o).contains(pw));
    let o = e.run(
        &["add-login", "--title", "G2", "--generate", "--show-secrets"],
        &format!("{PW}\n"),
    );
    assert!(out(&o).contains("password: "));
}

#[test]
fn update_semantics() {
    let e = Env::new();
    e.init();
    let input = format!("{PW}\nLOGIN-PW-1\n{TOTP_PASTED}\nNOTES-TEXT-2\nHIDDEN-ONE-3\n");
    let o = e.run(
        &[
            "add-login",
            "--title",
            "Site",
            "--username",
            "alice",
            "--url",
            "https://a",
            "--url",
            "https://b",
            "--totp",
            "--totp-digits",
            "7",
            "--notes",
            "--hidden-field",
            "pin",
            "--field",
            "k=v",
        ],
        &input,
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    let id = out(&o).trim().to_string();
    let get = |e: &Env| open(e).get(&id.parse().unwrap()).unwrap();

    // Title only: everything else unchanged.
    let o = e.run(&["update", &id, "--title", "Site2"], &format!("{PW}\n"));
    assert_eq!(code(&o), 0, "{}", err(&o));
    let s = get(&e);
    assert_eq!(s.item.title, "Site2");
    assert_eq!(s.revision, 2);
    assert_eq!(s.item.username.as_deref(), Some("alice"));
    assert_eq!(s.item.urls, ["https://a", "https://b"]);
    assert_eq!(s.item.password.as_ref().unwrap().expose(), "LOGIN-PW-1");
    assert_eq!(s.item.notes.expose(), "NOTES-TEXT-2");
    assert_eq!(s.item.fields.len(), 2);
    assert_eq!(s.item.totp.as_ref().unwrap().digits, 7);

    // --url replaces the list; --field replaces the field list; new password prompt.
    let o = run_checked(
        &e,
        &[
            "update",
            &id,
            "--url",
            "https://c",
            "--field",
            "only=1",
            "--new-password",
        ],
        &format!("{PW}\nNEW-PW-9\n"),
        &["NEW-PW-9"],
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    let s = get(&e);
    assert_eq!(s.item.urls, ["https://c"]);
    assert_eq!(s.item.fields.len(), 1);
    assert_eq!(s.item.fields[0].name, "only");
    assert_eq!(s.item.password.as_ref().unwrap().expose(), "NEW-PW-9");
    assert_eq!(s.item.notes.expose(), "NOTES-TEXT-2");

    // --totp replaces the whole configuration (defaults for unspecified parameters).
    let o = e.run(
        &["update", &id, "--totp", "--hidden-field", "h"],
        &format!("{PW}\n{TOTP_PASTED}\nH-VAL\n"),
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    let s = get(&e);
    let t = s.item.totp.unwrap();
    assert_eq!((t.digits, t.period), (6, 30));
    assert_eq!(s.item.fields[0].value.expose(), "H-VAL");

    // --notes-file replaces notes.
    let nf = e.dir.path().join("n.txt");
    std::fs::write(&nf, "NOTES-FILE-5").unwrap();
    let o = e.run(
        &["update", &id, "--notes-file", nf.to_str().unwrap()],
        &format!("{PW}\n"),
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert_eq!(get(&e).item.notes.expose(), "NOTES-FILE-5");

    // Clear flag plus a setter for the same field: usage error, nothing changed.
    let rev = get(&e).revision;
    for bad in [
        vec!["update", &id, "--clear-urls", "--url", "u"],
        vec!["update", &id, "--clear-fields", "--field", "a=b"],
        vec!["update", &id, "--clear-username", "--username", "u"],
        vec!["update", &id, "--clear-notes", "--notes"],
        vec!["update", &id, "--clear-totp", "--totp"],
    ] {
        let o = e.run(&bad, &format!("{PW}\nx\nx\n"));
        assert_eq!(code(&o), 2, "{bad:?}");
    }
    assert_eq!(get(&e).revision, rev);

    // Each clear flag clears.
    let o = e.run(
        &[
            "update",
            &id,
            "--clear-username",
            "--clear-urls",
            "--clear-notes",
            "--clear-totp",
            "--clear-fields",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    let s = get(&e);
    assert!(s.item.username.is_none() && s.item.urls.is_empty() && s.item.totp.is_none());
    assert!(s.item.notes.expose().is_empty() && s.item.fields.is_empty());
    assert_eq!(s.item.password.as_ref().unwrap().expose(), "NEW-PW-9");

    // Unknown id.
    let o = e.run(
        &["update", &"0".repeat(32), "--title", "x"],
        &format!("{PW}\n"),
    );
    assert_eq!(code(&o), 1);
}

#[test]
fn update_note_with_login_flag_fails_unchanged() {
    let e = Env::new();
    e.init();
    let o = e.run(
        &["add-note", "--title", "N", "--notes"],
        &format!("{PW}\nbody\n"),
    );
    let id = out(&o).trim().to_string();
    let rev = open(&e).get(&id.parse().unwrap()).unwrap().revision;
    for args in [
        vec!["update", &id, "--username", "bob"],
        vec!["update", &id, "--url", "https://x"],
        vec!["update", &id, "--new-password"],
    ] {
        let o = e.run(&args, &format!("{PW}\nPW\n"));
        assert_eq!(code(&o), 1, "{args:?}: {}", err(&o));
    }
    let o = e.run(&["update", &id, "--totp"], &format!("{PW}\n{TOTP_CANON}\n"));
    assert_eq!(code(&o), 1);
    let s = open(&e).get(&id.parse().unwrap()).unwrap();
    assert_eq!(s.revision, rev);
    assert!(s.item.username.is_none() && s.item.password.is_none());
    // A permitted update still works.
    let o = e.run(&["update", &id, "--title", "N2"], &format!("{PW}\n"));
    assert_eq!(code(&o), 0);
}

#[test]
fn invalid_totp_secret_stores_nothing() {
    let e = Env::new();
    e.init();
    let o = e.run(
        &["add-login", "--title", "Bad", "--totp"],
        &format!("{PW}\nLOGIN-PW-1\nnot base32 !!!\n"),
    );
    assert_eq!(code(&o), 1);
    assert!(!err(&o).contains("not base32"));
    assert!(open(&e).list().unwrap().is_empty());

    // Update with an invalid secret leaves the item alone.
    let o = e.run(
        &["add-login", "--title", "Ok", "--generate"],
        &format!("{PW}\n"),
    );
    let id = out(&o).trim().to_string();
    let o = e.run(&["update", &id, "--totp"], &format!("{PW}\nAAAA\n"));
    assert_eq!(code(&o), 1);
    let s = open(&e).get(&id.parse().unwrap()).unwrap();
    assert!(s.item.totp.is_none());
    assert_eq!(s.revision, 1);
}
