//! Secret-key files: bounded reading, exclusive creation, and guided vault creation
//! (architecture.md 7.1 and the `init` order of section 5).

use crate::crypto::kdf::{self, KdfParams};
use crate::crypto::keys::SecretKey;
use crate::secret::SecretString;
use crate::vault::Vault;
use crate::{storage, Error, Result};
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

/// A key file is 58 characters plus whitespace; anything larger is not one.
const MAX_KEY_FILE: u64 = 4096;

/// Constant-time equality of two 32-byte secrets (REQ-SEC-009).
pub fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Read a key from any reader: at most `MAX_KEY_FILE + 1` bytes are consumed.
pub(crate) fn read_from<R: Read>(r: R) -> Result<SecretKey> {
    let mut buf = Zeroizing::new(Vec::new());
    r.take(MAX_KEY_FILE + 1)
        .read_to_end(&mut buf)
        .map_err(|e| Error::Io(e.kind()))?;
    if buf.len() as u64 > MAX_KEY_FILE {
        return Err(Error::InvalidInput("key file too large"));
    }
    let text = std::str::from_utf8(&buf).map_err(|_| Error::InvalidInput("key file not UTF-8"))?;
    SecretKey::from_key_file_text(text)
}

/// Read a secret key file (at most 4 096 bytes, ASCII whitespace trimmed).
pub fn read(path: &Path) -> Result<SecretKey> {
    let f = std::fs::File::open(path).map_err(|e| Error::Io(e.kind()))?;
    read_from(f)
}

/// Create a new key file with `create_new` (mode 0600 on Unix), write the key text and a
/// newline, and `sync_all`. The file is removed again if writing or syncing fails.
pub fn write_new(path: &Path, key: &SecretKey) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| Error::Io(e.kind()))?;
    let text = key.to_text();
    let mut line = Zeroizing::new(Vec::with_capacity(text.expose().len() + 1));
    line.extend_from_slice(text.expose().as_bytes());
    line.push(b'\n');
    let res = f.write_all(&line).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = res {
        let _ = std::fs::remove_file(path);
        return Err(Error::Io(e.kind()));
    }
    Ok(())
}

fn exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::Io(e.kind())),
    }
}

impl Vault {
    /// Create a key file and a new vault that it opens; returns the unlocked vault.
    /// Nothing is left behind on failure and no existing file is touched.
    pub fn create_with_key_file(
        vault_path: &Path,
        key_path: &Path,
        password: &SecretString,
        params: KdfParams,
    ) -> Result<Vault> {
        // Step 1 (password) and step 2 (paths), before any disk write.
        kdf::check_new_password(password.expose())?;
        if exists(key_path)? || exists(vault_path)? {
            return Err(Error::Io(std::io::ErrorKind::AlreadyExists));
        }
        if storage::same_file_path(key_path, vault_path)? {
            return Err(Error::InvalidInput("key file and vault path are the same"));
        }
        // Steps 3-4.
        let key = SecretKey::generate()?;
        write_new(key_path, &key)?;
        // Steps 5-7; the key file we created is removed on any failure.
        let result = (|| {
            let back = read(key_path)?;
            if !ct_eq(back.expose(), key.expose()) {
                return Err(Error::Corrupt("key file read-back mismatch"));
            }
            Vault::create_with_key(vault_path, password, params, &key)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(key_path);
        }
        result
    }
}

#[cfg(test)]
mod tests;
