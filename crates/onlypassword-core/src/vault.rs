//! Vault lifecycle: create, unlock, lock (CS §6.6, §9).

use crate::crypto::kdf::{self, KdfParams};
use crate::crypto::keys::{FileAuthKey, ItemWrapKey, MasterKey, SecretKey, VaultKey};
use crate::format::{VaultFile, MAX_VAULT_FILE};
use crate::secret::SecretString;
use crate::{rng, seal, storage, Result};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Source of wall-clock time in milliseconds since the Unix epoch.
pub trait Clock {
    fn now_ms(&self) -> u64;
}

/// The default clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

/// The unlocked vault. There is no locked `Vault` value. Key fields zeroize on drop
/// (each key type is `ZeroizeOnDrop`); `Debug` is redacted.
#[allow(dead_code)] // item operations (later features) use these fields
pub struct Vault {
    path: PathBuf,
    file: VaultFile,
    vk: VaultKey,
    k_iw: ItemWrapKey,
    k_fa: FileAuthKey,
    clock: Box<dyn Clock>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Vault { .. }")
    }
}

type CreateHook<'a> = &'a dyn Fn(&Path) -> Result<()>;

impl Vault {
    /// Generate a secret key, then [`Vault::create_with_key`].
    pub fn create(
        path: &Path,
        password: &SecretString,
        params: KdfParams,
    ) -> Result<(Vault, SecretKey)> {
        let key = SecretKey::generate()?;
        let v = Self::create_with_key(path, password, params, &key)?;
        Ok((v, key))
    }

    /// Write a new empty vault via `storage::create_new_atomic`; never replaces an existing file.
    pub fn create_with_key(
        path: &Path,
        password: &SecretString,
        params: KdfParams,
        key: &SecretKey,
    ) -> Result<Vault> {
        kdf::check_new_password(password.expose())?;
        Self::create_inner(path, password, params, key, &|_| Ok(()))
    }

    /// Creation without the password-length check, with a hook between temp write and link.
    fn create_inner(
        path: &Path,
        password: &SecretString,
        params: KdfParams,
        key: &SecretKey,
        hook: CreateHook<'_>,
    ) -> Result<Vault> {
        params.validate()?;
        let salt = rng::random_array::<16>()?;
        let vault_id = rng::random_array::<16>()?;
        let pw = kdf::normalize_password(password.expose());
        let mk = MasterKey::derive(pw.expose(), &salt, &params, key)?;
        let vk = VaultKey::generate()?;
        let header = seal::wrap_vk(&mk, &vk, vault_id, params, salt)?;
        let img = seal::build_image(&header, Vec::new(), &vk)?;
        storage::create_new_atomic_with(path, &img, hook)?;
        let file = VaultFile::parse(&img)?;
        Self::from_parts(path, file, vk)
    }

    fn from_parts(path: &Path, file: VaultFile, vk: VaultKey) -> Result<Vault> {
        Ok(Vault {
            path: path.to_path_buf(),
            k_iw: vk.item_wrap_key()?,
            k_fa: vk.file_auth_key()?,
            file,
            vk,
            clock: Box::new(SystemClock),
        })
    }

    /// CS §9 order: read, parse, derive MK, unwrap VK, verify trailer. No password minimum.
    /// A wrong password and a wrong secret key both give `Error::Authentication`.
    pub fn unlock(path: &Path, password: &SecretString, key: &SecretKey) -> Result<Vault> {
        let bytes = storage::read_bounded(path, MAX_VAULT_FILE as u64)?;
        let parsed = VaultFile::parse(&bytes)?;
        let h = &parsed.header;
        let pw = kdf::normalize_password(password.expose());
        let mk = MasterKey::derive(pw.expose(), &h.kdf_salt, &h.kdf, key)?;
        let opened = seal::open_vault(&bytes, &mk)?;
        let vk = VaultKey::from_secret(crate::secret::SecretBytes::new(
            *opened.vault_key().expose(),
        ));
        Self::from_parts(path, opened.file.clone(), vk)
    }

    /// Consumes the vault; all key material is zeroized when it is dropped.
    pub fn lock(self) {
        drop(self);
    }

    /// The KDF parameters stored in the vault header.
    pub fn kdf_params(&self) -> KdfParams {
        self.file.header.kdf
    }

    #[doc(hidden)]
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn set_clock(&mut self, clock: Box<dyn Clock>) {
        self.clock = clock;
    }
}

#[cfg(test)]
mod tests;
