//! Prompts: a no-echo terminal read, or with `--stdin` one line per prompt.

use crate::error::CliError;
use onlypassword_core::SecretString;
use std::io::{BufRead, Read};
use zeroize::Zeroizing;

/// Longest accepted prompt line (bytes). Bounds memory on hostile input.
const MAX_LINE: u64 = 1 << 20;

pub struct Prompter {
    stdin: bool,
}

impl Prompter {
    pub fn new(stdin: bool) -> Self {
        Prompter { stdin }
    }

    /// One secret line. With `--stdin`: EOF before any byte is a usage error.
    pub fn read(&mut self, label: &str) -> Result<SecretString, CliError> {
        if self.stdin {
            let stdin = std::io::stdin();
            read_line(&mut stdin.lock())
        } else {
            let line = rpassword::prompt_password(format!("{label}: "))
                .map_err(|_| CliError::Failure("cannot read from the terminal"))?;
            Ok(SecretString::new(line))
        }
    }

    /// Read twice and require equality. Interactive: re-ask on mismatch.
    /// `--stdin`: two lines, mismatch is a usage error.
    pub fn read_confirmed(&mut self, label: &str) -> Result<SecretString, CliError> {
        loop {
            let a = self.read(label)?;
            let b = self.read(&format!("Confirm {label}"))?;
            if same(a.expose(), b.expose()) {
                return Ok(a);
            }
            if self.stdin {
                return Err(CliError::Usage("entries do not match"));
            }
            eprintln!("Entries do not match, try again.");
        }
    }
}

fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

pub fn read_line<R: BufRead>(r: &mut R) -> Result<SecretString, CliError> {
    let mut buf = Zeroizing::new(Vec::new());
    let n = r
        .by_ref()
        .take(MAX_LINE)
        .read_until(b'\n', &mut buf)
        .map_err(|_| CliError::Failure("cannot read standard input"))?;
    if n == 0 {
        return Err(CliError::Usage("missing input line on standard input"));
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    } else if n as u64 >= MAX_LINE {
        return Err(CliError::Usage("input line too long"));
    }
    let s = std::str::from_utf8(&buf)
        .map_err(|_| CliError::Usage("input line is not valid UTF-8"))?
        .to_string();
    Ok(SecretString::new(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rl(b: &[u8]) -> Result<String, CliError> {
        read_line(&mut &b[..]).map(|s| s.expose().to_string())
    }

    #[test]
    fn lines() {
        assert_eq!(rl(b"abc\n").unwrap(), "abc");
        assert_eq!(rl(b"abc\r\nxyz\n").unwrap(), "abc");
        assert_eq!(rl(b"abc").unwrap(), "abc");
        assert_eq!(rl(b"\n").unwrap(), "");
        assert_eq!(rl(b"a\rb\n").unwrap(), "a\rb");
        assert!(matches!(rl(b""), Err(CliError::Usage(_))));
        assert!(matches!(rl(b"\xff\n"), Err(CliError::Usage(_))));
    }

    #[test]
    fn consumes_one_line_at_a_time() {
        let mut r = &b"one\ntwo\n"[..];
        assert_eq!(read_line(&mut r).unwrap().expose(), "one");
        assert_eq!(read_line(&mut r).unwrap().expose(), "two");
        assert!(read_line(&mut r).is_err());
    }

    #[test]
    fn too_long_line() {
        let long = vec![b'a'; MAX_LINE as usize + 5];
        assert!(matches!(rl(&long), Err(CliError::Usage(_))));
    }

    #[test]
    fn compare() {
        assert!(same("ab", "ab"));
        assert!(!same("ab", "ac"));
        assert!(!same("ab", "abc"));
    }
}
