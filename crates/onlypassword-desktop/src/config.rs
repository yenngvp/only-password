//! Persistent, non-secret user settings (`<dir>/config.json`).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::UiError;

const FILE_NAME: &str = "config.json";
const TMP_NAME: &str = "config.json.tmp";
const MAX_BYTES: u64 = 4096;
const VERSION: u32 = 1;

/// Colour theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    System,
    Light,
    Dark,
}

/// User settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub idle_timeout_secs: u32,
    pub clipboard_clear_secs: u32,
    pub theme: Theme,
    pub last_vault_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            idle_timeout_secs: 300,
            clipboard_clear_secs: 30,
            theme: Theme::System,
            last_vault_path: None,
        }
    }
}

impl Config {
    /// Range check (idle 10..=86400, clipboard 5..=600).
    pub fn validate(&self) -> Result<(), UiError> {
        if (10..=86_400).contains(&self.idle_timeout_secs)
            && (5..=600).contains(&self.clipboard_clear_secs)
        {
            Ok(())
        } else {
            Err(UiError::InvalidSetting)
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ThemeRepr {
    System,
    Light,
    Dark,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    version: u32,
    idle_timeout_secs: u32,
    clipboard_clear_secs: u32,
    theme: ThemeRepr,
    last_vault_path: Option<String>,
}

impl ConfigFile {
    fn from_config(c: &Config) -> Self {
        ConfigFile {
            version: VERSION,
            idle_timeout_secs: c.idle_timeout_secs,
            clipboard_clear_secs: c.clipboard_clear_secs,
            theme: match c.theme {
                Theme::System => ThemeRepr::System,
                Theme::Light => ThemeRepr::Light,
                Theme::Dark => ThemeRepr::Dark,
            },
            last_vault_path: c
                .last_vault_path
                .as_deref()
                .and_then(Path::to_str)
                .map(str::to_owned),
        }
    }

    fn into_config(self) -> Config {
        Config {
            idle_timeout_secs: self.idle_timeout_secs,
            clipboard_clear_secs: self.clipboard_clear_secs,
            theme: match self.theme {
                ThemeRepr::System => Theme::System,
                ThemeRepr::Light => Theme::Light,
                ThemeRepr::Dark => Theme::Dark,
            },
            last_vault_path: self.last_vault_path.map(PathBuf::from),
        }
    }
}

/// Reads and writes `config.json` inside one directory.
#[derive(Debug, Clone)]
pub struct ConfigStore {
    dir: PathBuf,
}

impl ConfigStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        ConfigStore { dir: dir.into() }
    }

    /// The OS per-user config directory, or `None` if the OS has no home.
    pub fn platform_default() -> Option<ConfigStore> {
        directories::ProjectDirs::from("", "", "onlypassword")
            .map(|d| ConfigStore::new(d.config_dir().to_path_buf()))
    }

    fn path(&self) -> PathBuf {
        self.dir.join(FILE_NAME)
    }

    fn tmp_path(&self) -> PathBuf {
        self.dir.join(TMP_NAME)
    }

    /// Never writes. A missing file gives the defaults and no notice; any
    /// other problem gives the defaults and `ConfigInvalid`.
    pub fn load(&self) -> (Config, Option<UiError>) {
        match self.try_load() {
            Ok(Some(c)) => (c, None),
            Ok(None) => (Config::default(), None),
            Err(e) => (Config::default(), Some(e)),
        }
    }

    fn try_load(&self) -> Result<Option<Config>, UiError> {
        let file = match File::open(self.path()) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(UiError::ConfigInvalid),
        };
        let mut buf = Vec::new();
        file.take(MAX_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|_| UiError::ConfigInvalid)?;
        if buf.len() as u64 > MAX_BYTES {
            return Err(UiError::ConfigInvalid);
        }
        let text = std::str::from_utf8(&buf).map_err(|_| UiError::ConfigInvalid)?;
        let parsed: ConfigFile = serde_json::from_str(text).map_err(|_| UiError::ConfigInvalid)?;
        if parsed.version != VERSION {
            return Err(UiError::ConfigInvalid);
        }
        let config = parsed.into_config();
        config.validate().map_err(|_| UiError::ConfigInvalid)?;
        Ok(Some(config))
    }

    /// Validates, then writes atomically (temporary file + rename).
    pub fn save(&self, config: &Config) -> Result<(), UiError> {
        config.validate()?;
        let json = serde_json::to_vec_pretty(&ConfigFile::from_config(config))
            .map_err(|_| UiError::ConfigWrite)?;
        let tmp = self.tmp_path();
        let result = self
            .write_tmp(&tmp, &json)
            .and_then(|()| fs::rename(&tmp, self.path()));
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
            return Err(UiError::ConfigWrite);
        }
        Ok(())
    }

    fn write_tmp(&self, tmp: &Path, data: &[u8]) -> std::io::Result<()> {
        // A stale temporary file could have looser permissions; start fresh.
        let _ = fs::remove_file(tmp);
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(tmp)?;
        f.write_all(data)?;
        f.sync_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, ConfigStore) {
        let d = tempfile::tempdir().unwrap();
        let s = ConfigStore::new(d.path());
        (d, s)
    }

    fn valid_json(idle: u32, clip: u32) -> String {
        format!(
            r#"{{"version":1,"idle_timeout_secs":{idle},"clipboard_clear_secs":{clip},"theme":"dark","last_vault_path":null}}"#
        )
    }

    #[test]
    fn defaults() {
        let c = Config::default();
        assert_eq!(
            (
                c.idle_timeout_secs,
                c.clipboard_clear_secs,
                c.theme,
                c.last_vault_path
            ),
            (300, 30, Theme::System, None)
        );
    }

    #[test]
    fn missing_file_gives_defaults_no_notice() {
        let (_d, s) = store();
        assert_eq!(s.load(), (Config::default(), None));
    }

    #[test]
    fn round_trips() {
        let (d, s) = store();
        for theme in [Theme::System, Theme::Light, Theme::Dark] {
            for p in [None, Some(d.path().join("v.opw"))] {
                let c = Config {
                    idle_timeout_secs: 10,
                    clipboard_clear_secs: 600,
                    theme,
                    last_vault_path: p,
                };
                s.save(&c).unwrap();
                assert_eq!(s.load(), (c, None));
            }
        }
        assert!(!d.path().join(TMP_NAME).exists());
    }

    #[test]
    fn bad_files_give_defaults_and_are_not_rewritten() {
        let big = format!(
            "{}{}",
            valid_json(300, 30),
            " ".repeat(5000 - valid_json(300, 30).len())
        );
        assert_eq!(big.len(), 5000);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", vec![]),
            ("utf8", vec![0xff, 0xfe, 0xfd]),
            ("malformed", b"{\"version\":1,".to_vec()),
            ("types", br#"{"version":1,"idle_timeout_secs":"300","clipboard_clear_secs":30,"theme":"dark","last_vault_path":null}"#.to_vec()),
            ("unknown", br#"{"version":1,"idle_timeout_secs":300,"clipboard_clear_secs":30,"theme":"dark","last_vault_path":null,"x":1}"#.to_vec()),
            ("version2", valid_json(300, 30).replace("\"version\":1", "\"version\":2").into_bytes()),
            ("idle9", valid_json(9, 30).into_bytes()),
            ("idle86401", valid_json(86401, 30).into_bytes()),
            ("clip4", valid_json(300, 4).into_bytes()),
            ("clip601", valid_json(300, 601).into_bytes()),
            ("big", big.into_bytes()),
            ("negative", valid_json(300, 30).replace("300", "-300").into_bytes()),
            ("badtheme", valid_json(300, 30).replace("dark", "pink").into_bytes()),
        ];
        for (name, bytes) in cases {
            let (d, s) = store();
            fs::write(d.path().join(FILE_NAME), &bytes).unwrap();
            assert_eq!(
                s.load(),
                (Config::default(), Some(UiError::ConfigInvalid)),
                "{name}"
            );
            assert_eq!(fs::read(d.path().join(FILE_NAME)).unwrap(), bytes, "{name}");
        }
        // control: the same shape, valid, loads
        let (d, s) = store();
        fs::write(d.path().join(FILE_NAME), valid_json(10, 5)).unwrap();
        let (c, n) = s.load();
        assert!(n.is_none());
        assert_eq!((c.idle_timeout_secs, c.theme), (10, Theme::Dark));
    }

    #[test]
    fn exactly_4096_bytes_is_accepted() {
        let (d, s) = store();
        let j = valid_json(300, 30);
        let padded = format!("{j}{}", " ".repeat(4096 - j.len()));
        fs::write(d.path().join(FILE_NAME), padded).unwrap();
        assert!(s.load().1.is_none());
    }

    #[test]
    fn directory_in_place_of_file() {
        let (d, s) = store();
        fs::create_dir(d.path().join(FILE_NAME)).unwrap();
        assert_eq!(s.load(), (Config::default(), Some(UiError::ConfigInvalid)));
        assert!(d.path().join(FILE_NAME).is_dir());
    }

    #[test]
    fn saved_keys_are_exactly_the_five() {
        let (d, s) = store();
        s.save(&Config {
            last_vault_path: Some("/a/b".into()),
            ..Config::default()
        })
        .unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&fs::read(d.path().join(FILE_NAME)).unwrap()).unwrap();
        let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        let mut want = vec![
            "version",
            "idle_timeout_secs",
            "clipboard_clear_secs",
            "theme",
            "last_vault_path",
        ];
        want.sort();
        assert_eq!(keys, want);
        assert_eq!(v["version"], 1);
    }

    #[test]
    fn save_rejects_out_of_range_without_touching_disk() {
        let (d, s) = store();
        for (i, c) in [(9, 30), (86401, 30), (300, 4), (300, 601)] {
            let cfg = Config {
                idle_timeout_secs: i,
                clipboard_clear_secs: c,
                ..Config::default()
            };
            assert_eq!(s.save(&cfg), Err(UiError::InvalidSetting));
        }
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[test]
    fn missing_directory_is_config_write() {
        let (d, _) = store();
        let s = ConfigStore::new(d.path().join("nope"));
        assert_eq!(s.save(&Config::default()), Err(UiError::ConfigWrite));
    }

    #[cfg(unix)]
    #[test]
    fn unix_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let (d, s) = store();
        s.save(&Config::default()).unwrap();
        let m = fs::metadata(d.path().join(FILE_NAME))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(m & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn read_only_directory_keeps_old_file_and_leaves_no_tmp() {
        use std::os::unix::fs::PermissionsExt;
        let (d, s) = store();
        s.save(&Config::default()).unwrap();
        let before = fs::read(d.path().join(FILE_NAME)).unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o500)).unwrap();
        // root ignores directory permissions; the test is only meaningful otherwise
        let writable = File::create(d.path().join("probe")).is_ok();
        let r = s.save(&Config {
            theme: Theme::Dark,
            ..Config::default()
        });
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        if writable {
            let _ = fs::remove_file(d.path().join("probe"));
            return;
        }
        assert_eq!(r, Err(UiError::ConfigWrite));
        assert_eq!(fs::read(d.path().join(FILE_NAME)).unwrap(), before);
        assert!(!d.path().join(TMP_NAME).exists());
    }

    #[test]
    fn rename_failure_removes_tmp() {
        let (d, s) = store();
        // a non-empty directory at config.json makes the rename fail
        fs::create_dir(d.path().join(FILE_NAME)).unwrap();
        fs::write(d.path().join(FILE_NAME).join("x"), b"x").unwrap();
        assert_eq!(s.save(&Config::default()), Err(UiError::ConfigWrite));
        assert!(!d.path().join(TMP_NAME).exists());
    }
}
