//! Definition-of-done scenario (brief.md): drives the real `onlypassword` binary with the
//! default KDF parameters through create, add, lock, unlock, read back, change the master
//! password, export and import into a fresh vault. All values are obviously fake.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const PW: &str = "correct-horse-test-only";
const NEW_PW: &str = "new-staple-test-only-2";
const XPW: &str = "export-battery-test-only";
const LOGIN_PW: &str = "fake-login-secret-test-only";
const TOTP_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const HIDDEN: &str = "fake-hidden-value-test-only";

struct Vault {
    vault: PathBuf,
    key: PathBuf,
}

/// Every invocation's captured output, with whether secrets may legitimately appear in it.
struct Log(Vec<(String, bool)>);

fn run_raw(args: &[OsString], input: &str) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_onlypassword"))
        .args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
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
    o.status.code().expect("terminated by signal")
}

impl Vault {
    fn new(dir: &Path, name: &str) -> Vault {
        Vault {
            vault: dir.join(format!("{name}.opv")),
            key: dir.join(format!("{name}.key")),
        }
    }
    fn run_with(
        &self,
        log: &mut Log,
        vault: &Path,
        key: &Path,
        args: &[&str],
        input: &str,
    ) -> Output {
        let mut a: Vec<OsString> = vec![
            "--vault".into(),
            vault.into(),
            "--secret-key-file".into(),
            key.into(),
            "--stdin".into(),
        ];
        a.extend(args.iter().map(OsString::from));
        let o = run_raw(&a, input);
        let secrets_ok = args.contains(&"--show-secrets") || args.first() == Some(&"generate");
        log.0.push((format!("{}{}", out(&o), err(&o)), secrets_ok));
        o
    }
    fn run(&self, log: &mut Log, args: &[&str], input: &str) -> Output {
        self.run_with(log, &self.vault, &self.key, args, input)
    }
    fn ok(&self, log: &mut Log, args: &[&str], input: &str) -> String {
        let o = self.run(log, args, input);
        assert_eq!(code(&o), 0, "{args:?}: {}", err(&o));
        out(&o)
    }
    /// `list` output followed by `get --show-secrets` for every item (sorted by id).
    fn dump(&self, log: &mut Log, pw: &str) -> String {
        let list = self.ok(log, &["list"], &format!("{pw}\n"));
        let mut ids: Vec<&str> = list
            .lines()
            .map(|l| l.split('\t').next().unwrap())
            .collect();
        ids.sort();
        let mut all = list.clone();
        for id in ids {
            all.push_str(&self.ok(log, &["get", id, "--show-secrets"], &format!("{pw}\n")));
        }
        all
    }
}

#[test]
fn definition_of_done_scenario() {
    let dir = tempfile::tempdir().unwrap();
    let mut log = Log(Vec::new());
    let a = Vault::new(dir.path(), "first");

    // 1. create vault
    a.ok(&mut log, &["init"], &format!("{PW}\n{PW}\n"));
    let key_text = std::fs::read_to_string(&a.key).unwrap().trim().to_string();
    assert!(key_text.len() >= 20);
    assert!(a.vault.exists());

    // 2. add items
    let login = a
        .ok(
            &mut log,
            &[
                "add-login",
                "--title",
                "Fake Site",
                "--username",
                "alice-test",
                "--url",
                "https://example.invalid",
                "--notes",
                "--totp",
                "--totp-digits",
                "8",
                "--field",
                "region=eu-test",
                "--hidden-field",
                "pin",
            ],
            &format!("{PW}\n{LOGIN_PW}\n{TOTP_SECRET}\nlogin notes test\n{HIDDEN}\n"),
        )
        .trim()
        .to_string();
    let generated = a
        .ok(
            &mut log,
            &[
                "add-login",
                "--title",
                "Generated",
                "--username",
                "bob-test",
                "--generate",
            ],
            &format!("{PW}\n"),
        )
        .trim()
        .to_string();
    let note = a
        .ok(
            &mut log,
            &["add-note", "--title", "Memo", "--notes"],
            &format!("{PW}\nfake memo body test-only\n"),
        )
        .trim()
        .to_string();
    assert_eq!(
        [&login, &generated, &note]
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );

    // 3./4. lock (each process exit locks) and unlock again; 5. read every item back
    let before = a.dump(&mut log, PW);
    let shown = a.ok(
        &mut log,
        &["get", &login, "--show-secrets"],
        &format!("{PW}\n"),
    );
    for want in [
        "Fake Site",
        "alice-test",
        "https://example.invalid",
        LOGIN_PW,
        TOTP_SECRET,
        "login notes test",
        "region",
        "eu-test",
        "pin",
        HIDDEN,
    ] {
        assert!(shown.contains(want), "login missing {want:?}: {shown}");
    }
    let hidden_view = a.ok(&mut log, &["get", &login], &format!("{PW}\n"));
    for secret in [LOGIN_PW, TOTP_SECRET, HIDDEN, "login notes test"] {
        assert!(!hidden_view.contains(secret), "plain get leaked {secret}");
    }
    let gshown = a.ok(
        &mut log,
        &["get", &generated, "--show-secrets"],
        &format!("{PW}\n"),
    );
    assert!(gshown.contains("Generated") && gshown.contains("bob-test"));
    let nshown = a.ok(
        &mut log,
        &["get", &note, "--show-secrets"],
        &format!("{PW}\n"),
    );
    assert!(nshown.contains("Memo") && nshown.contains("fake memo body test-only"));
    assert_eq!(
        a.ok(&mut log, &["list"], &format!("{PW}\n"))
            .lines()
            .count(),
        3
    );

    // 6. change master password with --rotate: old fails with 3, new works, content identical
    a.ok(
        &mut log,
        &["passwd", "--rotate"],
        &format!("{PW}\n{NEW_PW}\n{NEW_PW}\n"),
    );
    let o = a.run(&mut log, &["list"], &format!("{PW}\n"));
    assert_eq!(code(&o), 3, "{}", err(&o));
    assert_eq!(out(&o), "");
    let after = a.dump(&mut log, NEW_PW);
    assert_eq!(after, before);

    // negative end states: wrong secret key exits 3; a tampered vault byte exits non-zero
    let other = Vault::new(dir.path(), "other");
    other.ok(&mut log, &["init"], &format!("{PW}\n{PW}\n"));
    let o = a.run_with(
        &mut log,
        &a.vault,
        &other.key,
        &["list"],
        &format!("{NEW_PW}\n"),
    );
    assert_eq!(code(&o), 3, "{}", err(&o));
    assert_eq!(out(&o), "");
    let original = std::fs::read(&a.vault).unwrap();
    for pos in [original.len() / 2, original.len() - 1] {
        let mut bad = original.clone();
        bad[pos] ^= 0x01;
        let tampered = dir.path().join(format!("tampered{pos}.opv"));
        std::fs::write(&tampered, &bad).unwrap();
        let o = a.run_with(
            &mut log,
            &tampered,
            &a.key,
            &["list"],
            &format!("{NEW_PW}\n"),
        );
        assert_ne!(code(&o), 0, "tampered vault accepted at byte {pos}");
        assert_eq!(out(&o), "", "stdout must be empty for a tampered vault");
        let o = a.run_with(
            &mut log,
            &tampered,
            &a.key,
            &["get", &login, "--show-secrets"],
            &format!("{NEW_PW}\n"),
        );
        assert_ne!(code(&o), 0);
        assert!(!out(&o).contains(LOGIN_PW) && out(&o).is_empty());
    }
    assert_eq!(
        original,
        std::fs::read(&a.vault).unwrap(),
        "original vault untouched"
    );

    // 7. export
    let exp = dir.path().join("backup.opx");
    let exp_s = exp.to_str().unwrap();
    a.ok(
        &mut log,
        &["export", "--out", exp_s],
        &format!("{NEW_PW}\n{XPW}\n{XPW}\n"),
    );
    assert!(exp.metadata().unwrap().len() > 0);

    // 8. import into a fresh vault with a new key file
    let b = Vault::new(dir.path(), "second");
    b.ok(&mut log, &["init"], &format!("{NEW_PW}\n{NEW_PW}\n"));
    let b_key_text = std::fs::read_to_string(&b.key).unwrap().trim().to_string();
    assert_ne!(key_text, b_key_text);
    // the fresh vault's own key file is the wrong source key: exit 3
    let o = b.run(
        &mut log,
        &[
            "import",
            "--in",
            exp_s,
            "--source-secret-key-file",
            b.key.to_str().unwrap(),
        ],
        &format!("{NEW_PW}\n{XPW}\n"),
    );
    assert_eq!(code(&o), 3, "{}", err(&o));
    assert_eq!(b.ok(&mut log, &["list"], &format!("{NEW_PW}\n")), "");
    // the first vault's key file works
    b.ok(
        &mut log,
        &[
            "import",
            "--in",
            exp_s,
            "--source-secret-key-file",
            a.key.to_str().unwrap(),
        ],
        &format!("{NEW_PW}\n{XPW}\n"),
    );
    let imported = b.dump(&mut log, NEW_PW);
    assert_eq!(
        imported, after,
        "list and get --show-secrets must match the first vault"
    );
    assert_eq!(imported, before);

    // no secret appears in any capture except get --show-secrets and generate
    let secrets = [
        PW,
        NEW_PW,
        XPW,
        key_text.as_str(),
        b_key_text.as_str(),
        LOGIN_PW,
        TOTP_SECRET,
        HIDDEN,
    ];
    for (text, ok) in &log.0 {
        if *ok {
            continue;
        }
        for s in secrets {
            assert!(
                !text.contains(s),
                "secret leaked in captured output: {text}"
            );
        }
    }
    // the generated password only ever shows up under --show-secrets
    let gen_pw = gshown
        .lines()
        .find_map(|l| l.strip_prefix("password: "))
        .expect("generated password shown by --show-secrets")
        .trim()
        .to_string();
    assert!(gen_pw.len() >= 8);
    for (text, ok) in &log.0 {
        assert!(*ok || !text.contains(&gen_pw));
    }
}
