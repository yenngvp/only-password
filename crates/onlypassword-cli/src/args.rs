//! Hand-written argument parser. Nothing secret is ever an argument: only exact flag
//! spellings are known, and every other argument (including `--flag=value`) is a usage error.

use crate::error::CliError;
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq)]
pub struct Global {
    pub vault: PathBuf,
    pub key_file: PathBuf,
    pub stdin: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Init { print_secret_key: bool },
    AddNote { title: String, notes: NotesSource },
    AddLogin { flags: ItemFlags },
    Update { id: String, flags: ItemFlags },
    Get { id: String, show_secrets: bool },
    List,
    Search { query: String },
    Delete { id: String },
}

#[derive(Debug, PartialEq, Eq)]
pub enum NotesSource {
    Prompt,
    File(PathBuf),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Alg {
    Sha1,
    Sha256,
    Sha512,
}

/// A custom field from the command line; `value` is `None` for `--hidden-field` (prompted).
#[derive(Debug, PartialEq, Eq)]
pub struct FieldSpec {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TotpFlags {
    pub algorithm: Alg,
    pub digits: u8,
    pub period: u32,
}

/// Item flags shared by `add-login` and `update` (architecture.md section 5).
/// Nothing here is secret: secrets are prompt switches.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ItemFlags {
    pub title: Option<String>,
    pub username: Option<String>,
    pub urls: Vec<String>,
    pub notes: Option<NotesSource>,
    pub generate: bool,
    pub show_secrets: bool,
    pub new_password: bool,
    pub totp: Option<TotpFlags>,
    /// In command-line order.
    pub fields: Vec<FieldSpec>,
    pub clear_username: bool,
    pub clear_urls: bool,
    pub clear_notes: bool,
    pub clear_totp: bool,
    pub clear_fields: bool,
}

type Res<T> = Result<T, CliError>;

fn usage<T>(m: &'static str) -> Res<T> {
    Err(CliError::Usage(m))
}

struct Args {
    it: std::vec::IntoIter<OsString>,
}

impl Args {
    fn next(&mut self) -> Option<OsString> {
        self.it.next()
    }
    fn value(&mut self) -> Res<OsString> {
        self.it.next().ok_or(CliError::Usage("missing flag value"))
    }
    fn text(&mut self) -> Res<String> {
        text(self.value()?)
    }
}

fn text(s: OsString) -> Res<String> {
    s.into_string()
        .map_err(|_| CliError::Usage("argument is not valid UTF-8"))
}

fn set_once<T>(slot: &mut Option<T>, v: T) -> Res<()> {
    if slot.is_some() {
        return usage("flag given twice");
    }
    *slot = Some(v);
    Ok(())
}

fn positional(a: &mut Args, what: &'static str) -> Res<String> {
    // A positional starting with `--` is treated as an unknown flag, not a value.
    let v = text(a.next().ok_or(CliError::Usage(what))?)?;
    if v.starts_with("--") {
        return usage("unknown flag");
    }
    Ok(v)
}

fn no_more(a: &mut Args) -> Res<()> {
    match a.next() {
        None => Ok(()),
        Some(_) => usage("unexpected argument"),
    }
}

fn switch(slot: &mut bool) -> Res<()> {
    if *slot {
        return usage("flag given twice");
    }
    *slot = true;
    Ok(())
}

fn item_flags(a: &mut Args, update: bool) -> Res<ItemFlags> {
    let mut f = ItemFlags::default();
    let mut totp = false;
    let mut alg = None;
    let mut digits = None;
    let mut period = None;
    let mut notes_prompt = false;
    let mut notes_file = None;
    while let Some(arg) = a.next() {
        match arg.to_str() {
            Some("--title") => set_once(&mut f.title, a.text()?)?,
            Some("--username") => set_once(&mut f.username, a.text()?)?,
            Some("--url") => f.urls.push(a.text()?),
            Some("--notes") => switch(&mut notes_prompt)?,
            Some("--notes-file") => set_once(&mut notes_file, PathBuf::from(a.value()?))?,
            Some("--generate") if !update => switch(&mut f.generate)?,
            Some("--show-secrets") if !update => switch(&mut f.show_secrets)?,
            Some("--new-password") if update => switch(&mut f.new_password)?,
            Some("--totp") => switch(&mut totp)?,
            Some("--totp-algorithm") => {
                let v = match a.text()?.as_str() {
                    "sha1" => Alg::Sha1,
                    "sha256" => Alg::Sha256,
                    "sha512" => Alg::Sha512,
                    _ => return usage("--totp-algorithm must be sha1, sha256 or sha512"),
                };
                set_once(&mut alg, v)?
            }
            Some("--totp-digits") => {
                let v = a.text()?.parse::<u8>().ok().filter(|d| (6..=8).contains(d));
                set_once(
                    &mut digits,
                    v.ok_or(CliError::Usage("--totp-digits must be 6..8"))?,
                )?
            }
            Some("--totp-period") => {
                let v = a
                    .text()?
                    .parse::<u32>()
                    .ok()
                    .filter(|p| (1..=300).contains(p));
                set_once(
                    &mut period,
                    v.ok_or(CliError::Usage("--totp-period must be 1..300"))?,
                )?
            }
            Some("--field") => {
                let kv = a.text()?;
                let Some((n, v)) = kv.split_once('=') else {
                    return usage("--field needs NAME=VALUE");
                };
                f.fields.push(FieldSpec {
                    name: n.to_string(),
                    value: Some(v.to_string()),
                });
            }
            Some("--hidden-field") => f.fields.push(FieldSpec {
                name: a.text()?,
                value: None,
            }),
            Some("--clear-username") if update => switch(&mut f.clear_username)?,
            Some("--clear-urls") if update => switch(&mut f.clear_urls)?,
            Some("--clear-notes") if update => switch(&mut f.clear_notes)?,
            Some("--clear-totp") if update => switch(&mut f.clear_totp)?,
            Some("--clear-fields") if update => switch(&mut f.clear_fields)?,
            _ => return usage("unknown flag or argument"),
        }
    }
    f.notes = match (notes_prompt, notes_file) {
        (true, Some(_)) => return usage("--notes and --notes-file are mutually exclusive"),
        (true, None) => Some(NotesSource::Prompt),
        (false, Some(p)) => Some(NotesSource::File(p)),
        (false, None) => None,
    };
    if !totp && (alg.is_some() || digits.is_some() || period.is_some()) {
        return usage("--totp-algorithm, --totp-digits and --totp-period need --totp");
    }
    if totp {
        f.totp = Some(TotpFlags {
            algorithm: alg.unwrap_or(Alg::Sha1),
            digits: digits.unwrap_or(6),
            period: period.unwrap_or(30),
        });
    }
    if (f.clear_username && f.username.is_some())
        || (f.clear_urls && !f.urls.is_empty())
        || (f.clear_notes && f.notes.is_some())
        || (f.clear_totp && f.totp.is_some())
        || (f.clear_fields && !f.fields.is_empty())
    {
        return usage("a --clear flag conflicts with a setter for the same field");
    }
    if !update && f.title.is_none() {
        return usage("add-login needs --title");
    }
    Ok(f)
}

pub fn parse(argv: Vec<OsString>) -> Res<(Global, Command)> {
    let mut a = Args {
        it: argv.into_iter(),
    };
    let mut vault = None;
    let mut key_file = None;
    let mut stdin = false;
    let cmd_name = loop {
        let Some(arg) = a.next() else {
            return usage("missing command");
        };
        match arg.to_str() {
            Some("--vault") => set_once(&mut vault, PathBuf::from(a.value()?))?,
            Some("--secret-key-file") => set_once(&mut key_file, PathBuf::from(a.value()?))?,
            Some("--stdin") => {
                if stdin {
                    return usage("flag given twice");
                }
                stdin = true;
            }
            Some(s) if s.starts_with('-') => return usage("unknown flag"),
            Some(s) => break s.to_string(),
            None => return usage("argument is not valid UTF-8"),
        }
    };
    let cmd = match cmd_name.as_str() {
        "init" => {
            let mut print_secret_key = false;
            while let Some(arg) = a.next() {
                match arg.to_str() {
                    Some("--print-secret-key") if !print_secret_key => print_secret_key = true,
                    _ => return usage("unknown flag or argument"),
                }
            }
            Command::Init { print_secret_key }
        }
        "add-note" => {
            let mut title = None;
            let mut prompt = false;
            let mut file = None;
            while let Some(arg) = a.next() {
                match arg.to_str() {
                    Some("--title") => set_once(&mut title, a.text()?)?,
                    Some("--notes") => {
                        if prompt {
                            return usage("flag given twice");
                        }
                        prompt = true;
                    }
                    Some("--notes-file") => set_once(&mut file, PathBuf::from(a.value()?))?,
                    _ => return usage("unknown flag or argument"),
                }
            }
            let Some(title) = title else {
                return usage("add-note needs --title");
            };
            let notes = match (prompt, file) {
                (true, None) => NotesSource::Prompt,
                (false, Some(f)) => NotesSource::File(f),
                _ => return usage("add-note needs exactly one of --notes, --notes-file"),
            };
            Command::AddNote { title, notes }
        }
        "add-login" => Command::AddLogin {
            flags: item_flags(&mut a, false)?,
        },
        "update" => {
            let id = positional(&mut a, "update needs an item id")?;
            Command::Update {
                id,
                flags: item_flags(&mut a, true)?,
            }
        }
        "get" => {
            let mut show_secrets = false;
            let mut id = None;
            while let Some(arg) = a.next() {
                match arg.to_str() {
                    Some("--show-secrets") if !show_secrets => show_secrets = true,
                    Some(s) if !s.starts_with('-') && id.is_none() => id = Some(s.to_string()),
                    _ => return usage("unknown flag or argument"),
                }
            }
            let Some(id) = id else {
                return usage("get needs an item id");
            };
            Command::Get { id, show_secrets }
        }
        "list" => {
            no_more(&mut a)?;
            Command::List
        }
        "search" => {
            let query = positional(&mut a, "search needs a query")?;
            no_more(&mut a)?;
            Command::Search { query }
        }
        "delete" => {
            let id = positional(&mut a, "delete needs an item id")?;
            no_more(&mut a)?;
            Command::Delete { id }
        }
        _ => return usage("unknown command"),
    };
    let global = Global {
        vault: vault.ok_or(CliError::Usage("--vault is required"))?,
        key_file: key_file.ok_or(CliError::Usage("--secret-key-file is required"))?,
        stdin,
    };
    Ok((global, cmd))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &[&str]) -> Res<(Global, Command)> {
        parse(v.iter().map(OsString::from).collect())
    }

    const G: [&str; 4] = ["--vault", "v", "--secret-key-file", "k"];

    fn with(rest: &[&str]) -> Vec<String> {
        G.iter().chain(rest).map(|s| s.to_string()).collect()
    }

    fn pr(rest: &[&str]) -> Res<(Global, Command)> {
        let v = with(rest);
        p(&v.iter().map(String::as_str).collect::<Vec<_>>())
    }

    #[test]
    fn parses_commands() {
        assert_eq!(
            pr(&["--stdin", "list"]).map(|x| (x.0.stdin, x.1)),
            Ok((true, Command::List))
        );
        assert!(matches!(
            pr(&["add-note", "--title", "t", "--notes"]),
            Ok((
                _,
                Command::AddNote {
                    notes: NotesSource::Prompt,
                    ..
                }
            ))
        ));
        assert!(matches!(
            pr(&["get", "abc", "--show-secrets"]),
            Ok((
                _,
                Command::Get {
                    show_secrets: true,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn rejects_bad_usage() {
        for bad in [
            vec!["init", "--password"],
            vec!["init", "--password=x"],
            vec!["add-note", "--title", "t", "--notes=TEXT"],
            vec!["add-note", "--title", "t"],
            vec!["add-note", "--title", "t", "--notes", "--notes-file", "f"],
            vec!["add-note", "--notes"],
            vec!["get"],
            vec!["get", "a", "b"],
            vec!["list", "x"],
            vec!["search"],
            vec!["delete", "--x"],
            vec!["nope"],
            vec!["add-login"],
            vec!["add-login", "--title", "t", "--totp-digits", "8"],
            vec!["add-login", "--title", "t", "--totp", "--totp-digits", "9"],
            vec!["add-login", "--title", "t", "--new-password"],
            vec!["add-login", "--title", "t", "--clear-urls"],
            vec!["add-login", "--title", "t", "--notes", "--notes-file", "f"],
            vec!["add-login", "--title", "t", "--field", "novalue"],
            vec!["update", "id", "--generate"],
            vec!["update", "id", "--clear-urls", "--url", "u"],
            vec!["update", "id", "--clear-fields", "--hidden-field", "x"],
            vec!["update", "id", "--clear-totp", "--totp"],
            vec!["update", "id", "--clear-notes", "--notes-file", "f"],
            vec!["update", "id", "--clear-username", "--username", "u"],
            vec!["update"],
            vec![],
            vec!["--bogus", "list"],
        ] {
            assert!(
                matches!(pr(&bad), Err(CliError::Usage(_))),
                "{bad:?} must be a usage error"
            );
        }
        assert!(matches!(p(&["list"]), Err(CliError::Usage(_))));
        assert!(matches!(
            p(&["--vault", "v", "list"]),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(p(&[]), Err(CliError::Usage(_))));
    }

    #[cfg(unix)]
    #[test]
    fn invalid_utf8_is_usage_error() {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![0x66, 0xff, 0xfe]);
        for argv in [
            vec![bad.clone()],
            vec![
                OsString::from("--vault"),
                bad.clone(),
                OsString::from("list"),
            ],
            vec![
                OsString::from("--vault"),
                OsString::from("v"),
                OsString::from("--secret-key-file"),
                OsString::from("k"),
                OsString::from("search"),
                bad.clone(),
            ],
        ] {
            assert!(matches!(parse(argv), Err(CliError::Usage(_))));
        }
    }
}
