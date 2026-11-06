//! Reading and creating the key file.

use crate::error::CliError;
use onlypassword_core::crypto::keys::SecretKey;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

/// A key file is 58 characters plus whitespace; anything larger is not one.
const MAX_KEY_FILE: u64 = 4096;

const BAD: CliError = CliError::Failure("key file is not a valid secret key");

pub fn read(path: &Path) -> Result<SecretKey, CliError> {
    let f = std::fs::File::open(path).map_err(|_| CliError::Failure("cannot read key file"))?;
    let mut buf = Zeroizing::new(Vec::new());
    f.take(MAX_KEY_FILE + 1)
        .read_to_end(&mut buf)
        .map_err(|_| CliError::Failure("cannot read key file"))?;
    if buf.len() as u64 > MAX_KEY_FILE {
        return Err(BAD);
    }
    let text = std::str::from_utf8(&buf).map_err(|_| BAD)?;
    SecretKey::from_key_file_text(text).map_err(|_| BAD)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_bytes(b: &[u8]) -> Result<SecretKey, CliError> {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("k");
        std::fs::write(&p, b).unwrap();
        read(&p)
    }

    #[test]
    fn accepts_whitespace_forms_and_rejects_garbage() {
        let k = SecretKey::generate().unwrap();
        let t = k.to_text();
        let t = t.expose();
        for form in [
            t.to_string(),
            format!("{t}\n"),
            format!("{t}\r\n"),
            format!("  {t} \t\n"),
        ] {
            let got = read_bytes(form.as_bytes()).unwrap();
            assert_eq!(got.expose(), k.expose());
        }
        assert!(read_bytes(format!("\u{feff}{t}").as_bytes()).is_err());
        assert!(read_bytes(b"garbage").is_err());
        assert!(read_bytes(b"\xff\xfe").is_err());
        assert!(read_bytes(&vec![b'A'; 5000]).is_err());
        assert!(read_bytes(b"").is_err());
        assert!(read(Path::new("/nonexistent/k")).is_err());
    }
}
