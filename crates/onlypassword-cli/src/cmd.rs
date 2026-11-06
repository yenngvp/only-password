//! Command execution.

use crate::args::{self, Command, Global, NotesSource};
use crate::error::CliError;
use crate::keyfile;
use crate::prompt::Prompter;
use onlypassword_core::crypto::kdf::{self, KdfParams};
use onlypassword_core::crypto::keys::SecretKey;
use onlypassword_core::{storage, Item, ItemId, ItemKind, SecretString, Vault};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

/// Notes limit (bytes) for `--notes-file`, architecture.md §5.
const MAX_NOTES_FILE: u64 = 65_536;
const HIDDEN: &str = "<hidden>";

type Res<T> = Result<T, CliError>;

pub fn run(argv: Vec<OsString>) -> Res<()> {
    let (g, cmd) = args::parse(argv)?;
    let mut prompter = Prompter::new(g.stdin);
    match cmd {
        Command::Init { print_secret_key } => init(&g, &mut prompter, print_secret_key),
        Command::AddNote { title, notes } => {
            let notes_file = match notes {
                NotesSource::File(p) => Some(read_notes_file(&p)?),
                NotesSource::Prompt => None,
            };
            let mut vault = unlock(&g, &mut prompter)?;
            let notes = match notes_file {
                Some(n) => n,
                None => prompter.read("Notes")?,
            };
            let id = vault.add(&Item::new_note(title, notes))?;
            out(&format!("{id}\n"))
        }
        Command::Get { id, show_secrets } => {
            let id: ItemId = id.parse()?;
            let vault = unlock(&g, &mut prompter)?;
            let stored = vault.get(&id)?;
            out(&render_item(&stored.id, &stored.item, show_secrets))
        }
        Command::List => {
            let vault = unlock(&g, &mut prompter)?;
            out(&render_summaries(&vault.list()?))
        }
        Command::Search { query } => {
            let vault = unlock(&g, &mut prompter)?;
            out(&render_summaries(&vault.search(&query)?))
        }
        Command::Delete { id } => {
            let id: ItemId = id.parse()?;
            let mut vault = unlock(&g, &mut prompter)?;
            vault.delete(&id)?;
            out(&format!("deleted {id}\n"))
        }
    }
}

fn out(s: &str) -> Res<()> {
    let mut o = std::io::stdout().lock();
    o.write_all(s.as_bytes())
        .and_then(|_| o.flush())
        .map_err(|_| CliError::Failure("cannot write to standard output"))
}

fn unlock(g: &Global, p: &mut Prompter) -> Res<Vault> {
    let key = keyfile::read(&g.key_file)?;
    let pw = p.read("Master password")?;
    Ok(Vault::unlock(&g.vault, &pw, &key)?)
}

fn read_notes_file(path: &Path) -> Res<SecretString> {
    const BAD: CliError = CliError::Failure("cannot read notes file");
    let f = std::fs::File::open(path).map_err(|_| BAD)?;
    let mut buf = Zeroizing::new(Vec::new());
    f.take(MAX_NOTES_FILE + 1)
        .read_to_end(&mut buf)
        .map_err(|_| BAD)?;
    if buf.len() as u64 > MAX_NOTES_FILE {
        return Err(CliError::Failure("notes file is larger than 65536 bytes"));
    }
    let s = std::str::from_utf8(&buf)
        .map_err(|_| CliError::Failure("notes file is not valid UTF-8"))?;
    Ok(SecretString::new(s.to_string()))
}

/// Replace control characters so item metadata cannot forge lines, columns or
/// terminal escape sequences.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn kind_name(k: ItemKind) -> &'static str {
    match k {
        ItemKind::Login => "login",
        ItemKind::Note => "note",
    }
}

fn render_summaries(items: &[onlypassword_core::ItemSummary]) -> String {
    let mut s = String::new();
    for i in items {
        s.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            i.id,
            kind_name(i.kind),
            clean(&i.title),
            clean(i.username.as_deref().unwrap_or(""))
        ));
    }
    s
}

fn render_item(id: &ItemId, item: &Item, show: bool) -> String {
    let secret = |v: &str| -> String {
        if show {
            v.to_string()
        } else {
            HIDDEN.to_string()
        }
    };
    let mut s = format!(
        "id: {id}\nkind: {}\ntitle: {}\n",
        kind_name(item.kind),
        clean(&item.title)
    );
    if let Some(u) = &item.username {
        s.push_str(&format!("username: {}\n", clean(u)));
    }
    if let Some(p) = &item.password {
        s.push_str(&format!("password: {}\n", secret(p.expose())));
    }
    for u in &item.urls {
        s.push_str(&format!("url: {}\n", clean(u)));
    }
    if !item.notes.expose().is_empty() {
        s.push_str(&format!("notes: {}\n", secret(item.notes.expose())));
    }
    if let Some(t) = &item.totp {
        s.push_str(&format!("totp secret: {}\n", secret(t.secret.expose())));
        s.push_str(&format!(
            "totp algorithm: {:?}\ntotp digits: {}\ntotp period: {}\n",
            t.algorithm, t.digits, t.period
        ));
    }
    for f in &item.fields {
        let v = if f.hidden {
            secret(f.value.expose())
        } else {
            clean(f.value.expose())
        };
        s.push_str(&format!("field {}: {v}\n", clean(&f.name)));
    }
    s
}

fn exists(p: &Path) -> bool {
    // symlink_metadata: a dangling symlink counts as existing.
    std::fs::symlink_metadata(p).is_ok()
}

fn init(g: &Global, p: &mut Prompter, print_secret_key: bool) -> Res<()> {
    // 1. password, confirmation and length check; no disk access yet.
    let pw = p.read_confirmed("Master password")?;
    kdf::check_new_password(pw.expose())?;
    // 2. neither path exists, and they differ.
    if g.vault == g.key_file || storage::same_file_path(&g.vault, &g.key_file).unwrap_or(true) {
        return Err(CliError::Failure(
            "vault and key file must be different paths",
        ));
    }
    if exists(&g.key_file) {
        return Err(CliError::Failure("key file already exists"));
    }
    if exists(&g.vault) {
        return Err(CliError::Failure("vault already exists"));
    }
    // 3. key.
    let key = SecretKey::generate()?;
    // 4-5. key file, exclusive, 0600, synced; read back and compare.
    create_key_file(&g.key_file, &key)?;
    let result = (|| -> Res<()> {
        let back = keyfile::read(&g.key_file)?;
        if !ct_eq(back.expose(), key.expose()) {
            return Err(CliError::Failure("key file read-back mismatch"));
        }
        // 6. the vault, only now.
        Vault::create_with_key(&g.vault, &pw, KdfParams::DEFAULT, &key)?;
        Ok(())
    })();
    if let Err(e) = result {
        // 7. never leave a key file without its vault (best effort).
        let _ = std::fs::remove_file(&g.key_file);
        return Err(e);
    }
    let mut msg = format!(
        "vault: {}\nkey file: {}\nKeep the key file safe and backed up: without it and the master password the vault cannot be opened.\n",
        g.vault.display(),
        g.key_file.display()
    );
    if print_secret_key {
        msg.push_str(&format!("secret key: {}\n", key.to_text().expose()));
    }
    out(&msg)
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Step 4. On any failure after the file was created, the file is removed again.
fn create_key_file(path: &Path, key: &SecretKey) -> Res<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|_| CliError::Failure("cannot create key file"))?;
    let text = Zeroizing::new(format!("{}\n", key.to_text().expose()));
    let written = f
        .write_all(text.as_bytes())
        .and_then(|_| f.flush())
        .and_then(|_| f.sync_all());
    if written.is_err() {
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(CliError::Failure("cannot write key file"));
    }
    Ok(())
}
