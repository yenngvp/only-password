//! End-to-end tests of passwd, rotate-key, export, import, totp and generate.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const PW: &str = "correct horse battery";
const NEW_PW: &str = "another long passphrase";
const XPW: &str = "export password one";

struct Env {
    dir: tempfile::TempDir,
    name: &'static str,
}

impl Env {
    fn new(name: &'static str) -> Env {
        Env {
            dir: tempfile::tempdir().unwrap(),
            name,
        }
    }
    fn vault(&self) -> PathBuf {
        self.dir.path().join(format!("{}.opv", self.name))
    }
    fn key(&self) -> PathBuf {
        self.dir.path().join(format!("{}.key", self.name))
    }
    fn run(&self, args: &[&str], input: &str) -> Output {
        let mut a: Vec<OsString> = vec![
            "--vault".into(),
            self.vault().into(),
            "--secret-key-file".into(),
            self.key().into(),
            "--stdin".into(),
        ];
        a.extend(args.iter().map(OsString::from));
        run_raw(&a, input)
    }
    fn init(&self) {
        let o = self.run(&["init"], &format!("{PW}\n{PW}\n"));
        assert_eq!(code(&o), 0, "{}", err(&o));
    }
    fn add(&self, args: &[&str], input: &str) -> String {
        let o = self.run(args, input);
        assert_eq!(code(&o), 0, "{}", err(&o));
        out(&o).trim().to_string()
    }
    /// list output plus `get --show-secrets` of every item, with the given password.
    fn dump(&self, pw: &str) -> String {
        let o = self.run(&["list"], &format!("{pw}\n"));
        assert_eq!(code(&o), 0, "{}", err(&o));
        let list = out(&o);
        let mut all = list.clone();
        let mut ids: Vec<&str> = list
            .lines()
            .map(|l| l.split('\t').next().unwrap())
            .collect();
        ids.sort();
        for id in ids {
            let o = self.run(&["get", id, "--show-secrets"], &format!("{pw}\n"));
            assert_eq!(code(&o), 0, "{}", err(&o));
            all.push_str(&out(&o));
        }
        all
    }
    fn populate(&self) -> String {
        self.init();
        let login = self.add(
            &[
                "add-login",
                "--title",
                "Site",
                "--username",
                "u1",
                "--notes",
                "--totp",
                "--totp-digits",
                "8",
                "--hidden-field",
                "pin",
            ],
            &format!("{PW}\nSITE-PASSWORD\nGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\nsome notes\n1234\n"),
        );
        self.add(
            &["add-note", "--title", "Memo", "--notes"],
            &format!("{PW}\nmemo body\n"),
        );
        login
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

#[test]
fn passwd_changes_password() {
    let e = Env::new("a");
    e.populate();
    let before = e.dump(PW);
    let file_before = std::fs::read(e.vault()).unwrap();
    let o = e.run(&["passwd"], &format!("{PW}\n{NEW_PW}\n{NEW_PW}\n"));
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(out(&o).contains("NOT rotated"), "{}", out(&o));
    assert_eq!(e.dump(NEW_PW), before);
    let o = e.run(&["list"], &format!("{PW}\n"));
    assert_eq!(code(&o), 3);
    // records are unchanged byte for byte without --rotate: only the header differs
    let file_after = std::fs::read(e.vault()).unwrap();
    assert_eq!(file_before.len(), file_after.len());
    assert_ne!(file_before, file_after);
    assert_eq!(
        file_before[130..file_before.len() - 40],
        file_after[130..file_after.len() - 40]
    );
}

#[test]
fn passwd_wrong_current_or_mismatch_changes_nothing() {
    let e = Env::new("a");
    e.populate();
    let file_before = std::fs::read(e.vault()).unwrap();
    let o = e.run(
        &["passwd"],
        &format!("wrong password!!\n{NEW_PW}\n{NEW_PW}\n"),
    );
    assert_eq!(code(&o), 3);
    let o = e.run(&["passwd"], &format!("{PW}\n{NEW_PW}\nsomething else 12\n"));
    assert_eq!(code(&o), 2);
    let o = e.run(&["passwd"], &format!("{PW}\nshort\nshort\n"));
    assert_eq!(code(&o), 1);
    assert_eq!(file_before, std::fs::read(e.vault()).unwrap());
}

#[test]
fn passwd_rotate_reseals_every_record() {
    let e = Env::new("a");
    e.populate();
    let before = e.dump(PW);
    let file_before = std::fs::read(e.vault()).unwrap();
    let o = e.run(
        &["passwd", "--rotate"],
        &format!("{PW}\n{NEW_PW}\n{NEW_PW}\n"),
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(!out(&o).contains("NOT"));
    assert_eq!(e.dump(NEW_PW), before);
    assert_eq!(code(&e.run(&["list"], &format!("{PW}\n"))), 3);
    let file_after = std::fs::read(e.vault()).unwrap();
    assert_all_bodies_differ(&file_before, &file_after);
}

#[test]
fn rotate_key_keeps_content() {
    let e = Env::new("a");
    e.populate();
    let before = e.dump(PW);
    let file_before = std::fs::read(e.vault()).unwrap();
    let o = e.run(&["rotate-key"], &format!("{PW}\n"));
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert_eq!(e.dump(PW), before);
    let file_after = std::fs::read(e.vault()).unwrap();
    assert_all_bodies_differ(&file_before, &file_after);
    let o = e.run(&["rotate-key"], "wrong password!!\n");
    assert_eq!(code(&o), 3);
}

#[test]
fn export_import_roundtrip() {
    let src = Env::new("src");
    src.populate();
    let want = src.dump(PW);
    let exp = src.dir.path().join("x.opx");
    let exp_s = exp.to_str().unwrap();
    let o = src.run(
        &["export", "--out", exp_s],
        &format!("{PW}\n{XPW}\n{XPW}\n"),
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    let first = std::fs::read(&exp).unwrap();

    // fresh vault with its own key file
    let dst = Env::new("dst");
    dst.init();
    let src_key = src.key();
    let src_key_s = src_key.to_str().unwrap();
    let args = [
        "import",
        "--in",
        exp_s,
        "--source-secret-key-file",
        src_key_s,
    ];
    // wrong export password: exit 3, nothing changed
    let empty = std::fs::read(dst.vault()).unwrap();
    let o = dst.run(&args, &format!("{PW}\nwrong export pw\n"));
    assert_eq!(code(&o), 3);
    assert_eq!(empty, std::fs::read(dst.vault()).unwrap());
    // the new vault's own key is the wrong source key: exit 3, nothing changed
    let own = dst.key();
    let o = dst.run(
        &[
            "import",
            "--in",
            exp_s,
            "--source-secret-key-file",
            own.to_str().unwrap(),
        ],
        &format!("{PW}\n{XPW}\n"),
    );
    assert_eq!(code(&o), 3);
    assert_eq!(empty, std::fs::read(dst.vault()).unwrap());
    assert_eq!(out(&dst.run(&["list"], &format!("{PW}\n"))), "");
    // correct import
    let o = dst.run(&args, &format!("{PW}\n{XPW}\n"));
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert_eq!(dst.dump(PW), want);
    // importing again conflicts and changes nothing
    let full = std::fs::read(dst.vault()).unwrap();
    let o = dst.run(&args, &format!("{PW}\n{XPW}\n"));
    assert_eq!(code(&o), 1);
    assert_eq!(full, std::fs::read(dst.vault()).unwrap());

    // export over an existing file replaces it
    let o = src.run(
        &["export", "--out", exp_s],
        &format!("{PW}\n{XPW}\n{XPW}\n"),
    );
    assert_eq!(code(&o), 0, "{}", err(&o));
    let second = std::fs::read(&exp).unwrap();
    assert_ne!(first, second);
    assert_eq!(
        std::fs::read_dir(src.dir.path()).unwrap().count(),
        3,
        "no temp leftovers"
    );
}

#[test]
fn failed_export_leaves_old_file_intact() {
    let e = Env::new("a");
    e.populate();
    let exp = e.dir.path().join("x.opx");
    std::fs::write(&exp, b"OLD EXPORT CONTENT").unwrap();
    let exp_s = exp.to_str().unwrap();
    // wrong master password
    let o = e.run(
        &["export", "--out", exp_s],
        &format!("wrong password!!\n{XPW}\n{XPW}\n"),
    );
    assert_eq!(code(&o), 3);
    // mismatched confirmation
    let o = e.run(
        &["export", "--out", exp_s],
        &format!("{PW}\n{XPW}\nnot the same one\n"),
    );
    assert_eq!(code(&o), 2);
    // too short export password
    let o = e.run(
        &["export", "--out", exp_s],
        &format!("{PW}\nshort\nshort\n"),
    );
    assert_eq!(code(&o), 1);
    assert_eq!(std::fs::read(&exp).unwrap(), b"OLD EXPORT CONTENT");
    assert_eq!(std::fs::read_dir(e.dir.path()).unwrap().count(), 3);
}

#[test]
fn export_to_vault_path_is_usage_error() {
    let e = Env::new("a");
    e.populate();
    let before = std::fs::read(e.vault()).unwrap();
    let v = e.vault();
    let o = e.run(
        &["export", "--out", v.to_str().unwrap()],
        &format!("{PW}\n{XPW}\n{XPW}\n"),
    );
    assert_eq!(code(&o), 2, "{}", err(&o));
    assert_eq!(before, std::fs::read(e.vault()).unwrap());
    // a different spelling of the same path
    let dotted = e.dir.path().join(".").join("a.opv");
    let o = e.run(
        &["export", "--out", dotted.to_str().unwrap()],
        &format!("{PW}\n{XPW}\n{XPW}\n"),
    );
    assert_eq!(code(&o), 2);
    assert_eq!(before, std::fs::read(e.vault()).unwrap());
}

#[test]
fn totp_matches_rfc6238_vector() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/totp.json");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let vec = v["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["mode"] == "SHA1" && x["time"] == 59)
        .unwrap();
    let want = vec["totp"].as_str().unwrap();
    assert_eq!(want.len(), 8);
    // secret_hex -> base32 is the seed named in the criteria
    assert_eq!(
        vec["secret_hex"],
        "3132333435363738393031323334353637383930"
    );
    let e = Env::new("a");
    e.init();
    let id = e.add(
        &[
            "add-login",
            "--title",
            "T",
            "--totp",
            "--totp-digits",
            "8",
            "--totp-period",
            "30",
        ],
        &format!("{PW}\nLOGINPW\nGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n"),
    );
    let o = e.run(&["totp", &id, "--time", "59"], &format!("{PW}\n"));
    assert_eq!(code(&o), 0, "{}", err(&o));
    let t = out(&o);
    let mut lines = t.lines();
    assert_eq!(lines.next().unwrap(), want);
    assert!(lines.next().unwrap().starts_with("1 "), "{t}");
    let o = e.run(&["totp", &id, "--time", "60"], &format!("{PW}\n"));
    assert!(out(&o).lines().nth(1).unwrap().starts_with("30 "));
    // system clock: a code of 8 digits and 1..=30 seconds remaining
    let o = e.run(&["totp", &id], &format!("{PW}\n"));
    assert_eq!(code(&o), 0);
    let t = out(&o);
    let mut l = t.lines();
    assert!(l.next().unwrap().chars().all(|c| c.is_ascii_digit()));
    let secs: u64 = l
        .next()
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=30).contains(&secs));
}

#[test]
fn totp_errors() {
    let e = Env::new("a");
    let note_id = {
        e.init();
        e.add(
            &["add-note", "--title", "N", "--notes"],
            &format!("{PW}\nbody\n"),
        )
    };
    let o = e.run(&["totp", &note_id], &format!("{PW}\n"));
    assert_eq!(code(&o), 1);
    let o = e.run(&["totp", &"0".repeat(32)], &format!("{PW}\n"));
    assert_eq!(code(&o), 1);
    let o = e.run(&["totp", &note_id, "--time", "abc"], &format!("{PW}\n"));
    assert_eq!(code(&o), 2);
    let o = e.run(&["totp", &note_id], "wrong password!!\n");
    assert_eq!(code(&o), 3);
}

fn generate(args: &[&str]) -> Output {
    let mut a: Vec<OsString> = vec!["generate".into()];
    a.extend(args.iter().map(OsString::from));
    run_raw(&a, "")
}

#[test]
fn generate_password_and_passphrase() {
    let o = generate(&["password", "--length", "32", "--no-symbols"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let t = out(&o);
    let pw = t.trim_end_matches('\n');
    assert_eq!(pw.len(), 32);
    assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()), "{pw}");

    let o = generate(&["password"]);
    assert_eq!(out(&o).trim_end().len(), 20);
    let o = generate(&[
        "password",
        "--no-lower",
        "--no-upper",
        "--no-symbols",
        "--length",
        "12",
    ]);
    assert!(out(&o).trim_end().chars().all(|c| c.is_ascii_digit()));
    let o = generate(&["password", "--exclude-ambiguous", "--length", "200"]);
    assert!(!out(&o).trim_end().chars().any(|c| "0Oo1lI".contains(c)));

    let o = generate(&["passphrase", "--words", "5", "--separator", "."]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let t = out(&o);
    let words: Vec<&str> = t.trim_end().split('.').collect();
    assert_eq!(words.len(), 5);
    assert!(words
        .iter()
        .all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase())));
    let o = generate(&["passphrase", "--capitalize", "--digit"]);
    let t = out(&o);
    let words: Vec<&str> = t.trim_end().split('-').collect();
    assert_eq!(words.len(), 7);
    assert!(words
        .iter()
        .all(|w| w.chars().next().unwrap().is_ascii_uppercase()));
    assert_eq!(t.chars().filter(|c| c.is_ascii_digit()).count(), 1);
}

#[test]
fn generate_invalid_values_exit_2() {
    for bad in [
        vec!["password", "--length", "3"],
        vec!["password", "--length", "257"],
        vec!["password", "--length", "x"],
        vec![
            "password",
            "--no-lower",
            "--no-upper",
            "--no-digits",
            "--no-symbols",
        ],
        vec!["password", "--bogus"],
        vec!["password", "--length=20"],
        vec!["passphrase", "--words", "2"],
        vec!["passphrase", "--words", "25"],
        vec!["passphrase", "--separator", "123456789"],
        vec!["passphrase", "--separator", "é"],
        vec!["passphrase", "--bogus"],
        vec!["other"],
        vec![],
    ] {
        let o = generate(&bad);
        assert_eq!(code(&o), 2, "{bad:?}: {}", err(&o));
        assert_eq!(out(&o), "");
    }
}

#[test]
fn advanced_usage_errors() {
    let e = Env::new("a");
    e.init();
    for bad in [
        vec!["passwd", "--bogus"],
        vec!["passwd", "--rotate", "--rotate"],
        vec!["rotate-key", "x"],
        vec!["export"],
        vec!["import", "--in", "f"],
        vec!["import", "--source-secret-key-file", "k"],
        vec!["totp"],
        vec!["generate-x"],
    ] {
        let o = e.run(&bad, "");
        assert_eq!(code(&o), 2, "{bad:?}");
    }
}

/// Record bodies (ciphertext ‖ tag) of a vault file, per crypto-spec §5: record_count at 130,
/// then `u32 record_len ‖ record`, whose body_ct starts at record offset 126.
fn bodies(file: &[u8]) -> Vec<Vec<u8>> {
    let n = u32::from_be_bytes(file[130..134].try_into().unwrap()) as usize;
    let mut pos = 134;
    let mut v = Vec::new();
    for _ in 0..n {
        let len = u32::from_be_bytes(file[pos..pos + 4].try_into().unwrap()) as usize;
        v.push(file[pos + 4 + 126..pos + 4 + len].to_vec());
        pos += 4 + len;
    }
    v
}

fn assert_all_bodies_differ(before: &[u8], after: &[u8]) {
    let (b, a) = (bodies(before), bodies(after));
    assert_eq!(b.len(), 2);
    assert_eq!(b.len(), a.len());
    for (x, y) in b.iter().zip(&a) {
        assert_ne!(x, y);
    }
}
