//! Vault lifecycle: create, unlock, lock (CS §6.6, §9).

use crate::crypto::kdf::{self, KdfParams};
use crate::crypto::keys::{ItemWrapKey, MasterKey, SecretKey, VaultKey};
use crate::format::{Record, VaultFile, MAX_RECORDS, MAX_VAULT_FILE};
use crate::item::{Item, ItemId, ItemKind};
use crate::secret::SecretString;
use crate::{rng, seal, storage, Error, Result};
mod export;
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
pub struct Vault {
    path: PathBuf,
    file: VaultFile,
    vk: VaultKey,
    k_iw: ItemWrapKey,
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

/// A decrypted item together with its stored metadata.
#[derive(Debug)]
pub struct StoredItem {
    pub id: ItemId,
    pub item: Item,
    pub revision: u64,
    pub created_ms: u64,
    pub updated_ms: u64,
}

/// What `list` and `search` expose: no password, notes, TOTP secret or field values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSummary {
    pub id: ItemId,
    pub kind: ItemKind,
    pub title: String,
    pub username: Option<String>,
    pub urls: Vec<String>,
    pub revision: u64,
    pub updated_ms: u64,
}

#[cfg(not(test))]
fn max_records() -> usize {
    MAX_RECORDS as usize
}
#[cfg(not(test))]
fn max_image() -> usize {
    MAX_VAULT_FILE
}
#[cfg(test)]
thread_local! {
    static LIMITS: std::cell::Cell<(usize, usize)> =
        const { std::cell::Cell::new((MAX_RECORDS as usize, MAX_VAULT_FILE)) };
}
#[cfg(test)]
thread_local! {
    static FAIL_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
fn max_records() -> usize {
    LIMITS.with(|l| l.get().0)
}
#[cfg(test)]
fn max_image() -> usize {
    LIMITS.with(|l| l.get().1)
}

impl Vault {
    fn index_of(&self, id: &ItemId) -> std::result::Result<usize, usize> {
        self.file.records.binary_search_by(|r| r.item_id.cmp(&id.0))
    }

    fn open_at(&self, rec: &Record) -> Result<StoredItem> {
        let (item, created_ms, updated_ms) =
            seal::open_record(&self.k_iw, &self.file.header.vault_id, rec)?;
        Ok(StoredItem {
            id: ItemId(rec.item_id),
            item,
            revision: rec.revision,
            created_ms,
            updated_ms,
        })
    }

    /// Atomic write of a prepared image; tests can inject a failure here.
    fn persist(&self, img: &[u8]) -> Result<()> {
        #[cfg(test)]
        if FAIL_WRITE.with(|f| f.get()) {
            return Err(Error::Io(std::io::ErrorKind::Other));
        }
        storage::write_atomic(&self.path, img)
    }

    /// Build the complete new image, check limits, write atomically, then update memory.
    fn commit(&mut self, records: Vec<Record>) -> Result<()> {
        if records.len() > max_records() {
            return Err(Error::LimitExceeded);
        }
        let img = seal::build_image(&self.file.header, records, &self.vk)?;
        if img.len() > max_image() {
            return Err(Error::LimitExceeded);
        }
        let parsed = VaultFile::parse(&img)?;
        self.persist(&img)?;
        self.file = parsed;
        Ok(())
    }

    /// Add an item; returns its new random id (revision 1, created = updated = now).
    pub fn add(&mut self, item: &Item) -> Result<ItemId> {
        item.validate()?;
        let mut id = ItemId::generate()?;
        while self.index_of(&id).is_ok() {
            id = ItemId::generate()?;
        }
        let pos = self.index_of(&id).unwrap_or_else(|p| p);
        let now = self.clock.now_ms();
        let rec = seal::seal_item(
            &self.k_iw,
            &self.file.header.vault_id,
            &id,
            1,
            item,
            now,
            now,
        )?;
        let mut records = self.file.records.clone();
        records.insert(pos, rec);
        self.commit(records)?;
        Ok(id)
    }

    pub fn get(&self, id: &ItemId) -> Result<StoredItem> {
        let i = self.index_of(id).map_err(|_| Error::NotFound)?;
        let rec = self.file.records.get(i).ok_or(Error::NotFound)?;
        self.open_at(rec)
    }

    /// Replace the item's content: revision + 1, new item key and nonces.
    pub fn update(&mut self, id: &ItemId, item: &Item) -> Result<()> {
        let i = self.index_of(id).map_err(|_| Error::NotFound)?;
        item.validate()?;
        let old = self.file.records.get(i).ok_or(Error::NotFound)?;
        let revision = old.revision.checked_add(1).ok_or(Error::LimitExceeded)?;
        let created_ms = self.open_at(old)?.created_ms;
        let updated_ms = self.clock.now_ms().max(created_ms);
        let rec = seal::seal_item(
            &self.k_iw,
            &self.file.header.vault_id,
            id,
            revision,
            item,
            created_ms,
            updated_ms,
        )?;
        let mut records = self.file.records.clone();
        *records.get_mut(i).ok_or(Error::NotFound)? = rec;
        self.commit(records)
    }

    pub fn delete(&mut self, id: &ItemId) -> Result<()> {
        let i = self.index_of(id).map_err(|_| Error::NotFound)?;
        let mut records = self.file.records.clone();
        records.remove(i);
        self.commit(records)
    }

    fn summaries(&self, query: Option<&str>) -> Result<Vec<ItemSummary>> {
        let q = query.map(str::to_lowercase);
        let mut out = Vec::new();
        for rec in &self.file.records {
            let s = self.open_at(rec)?;
            let it = &s.item;
            if let Some(q) = &q {
                let hit = it.title.to_lowercase().contains(q.as_str())
                    || it
                        .username
                        .as_ref()
                        .is_some_and(|u| u.to_lowercase().contains(q.as_str()))
                    || it
                        .urls
                        .iter()
                        .any(|u| u.to_lowercase().contains(q.as_str()));
                if !hit {
                    continue;
                }
            }
            out.push(ItemSummary {
                id: s.id.clone(),
                kind: it.kind,
                title: it.title.clone(),
                username: it.username.clone(),
                urls: it.urls.clone(),
                revision: s.revision,
                updated_ms: s.updated_ms,
            });
        }
        out.sort_by_key(|a| (a.title.to_lowercase(), a.id.0));
        Ok(out)
    }

    /// All items, sorted by `title.to_lowercase()` (byte-wise) then id bytes.
    pub fn list(&self) -> Result<Vec<ItemSummary>> {
        self.summaries(None)
    }

    /// Case-insensitive substring match on title, username and URLs only.
    pub fn search(&self, query: &str) -> Result<Vec<ItemSummary>> {
        self.summaries(Some(query))
    }
}

impl Vault {
    /// Changes the master password: verifies the current password and secret key, then
    /// re-wraps the **same** vault key under a master key derived from a new random salt,
    /// `new_params` and `new_password`. Records stay byte-identical; the write is atomic and
    /// any failure leaves the old file and in-memory state untouched.
    ///
    /// This does **not** revoke earlier knowledge of the vault key: anyone who knew the old
    /// password, has the secret key and holds a past copy of the header can still recover the
    /// unchanged vault key and read later records. After a suspected password compromise use
    /// [`Vault::change_master_password_and_rotate_key`], which also performs key rotation.
    pub fn change_master_password(
        &mut self,
        current_password: &SecretString,
        key: &SecretKey,
        new_password: &SecretString,
        new_params: KdfParams,
    ) -> Result<()> {
        self.rekey(
            current_password,
            key,
            Some((new_password, new_params)),
            false,
        )
    }

    /// Generates a new vault key, re-seals every record (fresh item keys and nonces, same
    /// revisions and contents) and re-wraps the key under the current master key.
    pub fn rotate_vault_key(
        &mut self,
        current_password: &SecretString,
        key: &SecretKey,
    ) -> Result<()> {
        self.rekey(current_password, key, None, true)
    }

    /// Changes the password and rotates the vault key in one atomic write; the new vault key
    /// is wrapped under the **new** master key.
    pub fn change_master_password_and_rotate_key(
        &mut self,
        current_password: &SecretString,
        key: &SecretKey,
        new_password: &SecretString,
        new_params: KdfParams,
    ) -> Result<()> {
        self.rekey(
            current_password,
            key,
            Some((new_password, new_params)),
            true,
        )
    }

    fn rekey(
        &mut self,
        current_password: &SecretString,
        key: &SecretKey,
        new: Option<(&SecretString, KdfParams)>,
        rotate: bool,
    ) -> Result<()> {
        if let Some((np, params)) = &new {
            kdf::check_new_password(np.expose())?;
            params.validate()?;
        }
        // Verify the current password and key by deriving and unwrapping.
        let h = &self.file.header;
        let cur = kdf::normalize_password(current_password.expose());
        let cur_mk = MasterKey::derive(cur.expose(), &h.kdf_salt, &h.kdf, key)?;
        let unwrapped = seal::unwrap_vk(&cur_mk, h)?;
        if unwrapped.expose() != self.vk.expose() {
            return Err(Error::Authentication);
        }
        let (mk, params, salt) = match new {
            Some((np, params)) => {
                let salt = rng::random_array::<16>()?;
                let n = kdf::normalize_password(np.expose());
                (
                    MasterKey::derive(n.expose(), &salt, &params, key)?,
                    params,
                    salt,
                )
            }
            None => (cur_mk, h.kdf, h.kdf_salt),
        };
        let new_vk = if rotate {
            VaultKey::generate()?
        } else {
            unwrapped
        };
        let header = seal::wrap_vk(&mk, &new_vk, h.vault_id, params, salt)?;
        let new_kiw = new_vk.item_wrap_key()?;
        let records = if rotate {
            let mut out = Vec::with_capacity(self.file.records.len());
            for rec in &self.file.records {
                let (item, created, updated) = seal::open_record(&self.k_iw, &h.vault_id, rec)?;
                out.push(seal::seal_item(
                    &new_kiw,
                    &h.vault_id,
                    &ItemId(rec.item_id),
                    rec.revision,
                    &item,
                    created,
                    updated,
                )?);
            }
            out
        } else {
            self.file.records.clone()
        };
        let img = seal::build_image(&header, records, &new_vk)?;
        if img.len() > max_image() {
            return Err(Error::LimitExceeded);
        }
        let parsed = VaultFile::parse(&img)?;
        self.persist(&img)?;
        self.file = parsed;
        self.vk = new_vk;
        self.k_iw = new_kiw;
        Ok(())
    }
}

#[cfg(test)]
mod export_tests;
#[cfg(test)]
mod item_tests;
#[cfg(test)]
mod rekey_tests;
#[cfg(test)]
mod robustness_tests;
#[cfg(test)]
mod tests;
