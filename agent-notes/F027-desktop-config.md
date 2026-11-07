# F027-desktop-config

Built `error` (UiError, Display literals, From<core::Error>) and `config` (Theme, Config, ConfigStore) in onlypassword-desktop.
Deps added: directories 6, serde (derive), serde_json, tempfile (dev). zeroize not needed.

Choices the spec left open:
- Secs fields are `u32`; theme is stored as lowercase "system"/"light"/"dark".
- Config JSON is pretty-printed; a non-UTF-8 last_vault_path is stored as null.
- load: only NotFound on open is "no notice"; every other I/O problem (incl. a directory) is ConfigInvalid. Exactly 4096 bytes is accepted, 4097 read -> rejected.
- save removes any stale config.json.tmp before create_new (so mode 0600 always applies).
- The read-only-directory test skips its assertions when run as root (root ignores dir modes).
- UiError Display strings are my own wording (spec only fixes that they are literals).
