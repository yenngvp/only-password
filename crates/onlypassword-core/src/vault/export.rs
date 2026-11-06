//! Encrypted export and import (CS §8, §9 export table, §10).

use super::{max_records, Vault};
use crate::crypto::aead::{self, AeadKey};
use crate::crypto::hkdf::{self, INFO_EXPORT};
use crate::crypto::kdf::{self, KdfParams};
use crate::crypto::keys::SecretKey;
use crate::format::{Record, MAX_EXPORT_PLAINTEXT, MAX_RECORDS};
use crate::item::{CountingWriter, Item, ItemId, Probe, WireIn, WireOut};
use crate::secret::{SecretString, SecretVec};
use crate::{base32, rng, seal, storage, Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: [u8; 8] = *b"OPEXPORT";
const LABEL_X: &[u8] = b"onlypassword/v1/export";
const HEADER_LEN: usize = 74;
const TAG_LEN: usize = 16;

#[cfg(not(test))]
fn max_payload() -> usize {
    MAX_EXPORT_PLAINTEXT
}
#[cfg(test)]
thread_local! {
    pub(super) static MAX_PAYLOAD: std::cell::Cell<usize> =
        const { std::cell::Cell::new(MAX_EXPORT_PLAINTEXT) };
}
#[cfg(test)]
fn max_payload() -> usize {
    MAX_PAYLOAD.with(|m| m.get())
}

// ---- wire types: key order is declaration order (CS §8) ----

#[derive(Serialize)]
struct PayloadOut<'a> {
    export_schema: u32,
    vault_id: String,
    exported_ms: u64,
    items: Vec<EntryOut<'a>>,
}

#[derive(Serialize)]
struct EntryOut<'a> {
    id: String,
    revision: u64,
    item: WireOut<'a>,
}

#[derive(Deserialize)]
struct TopProbe {
    export_schema: i64,
}

#[derive(Deserialize)]
struct ItemsProbe {
    items: Vec<EntryProbe>,
}

#[derive(Deserialize)]
struct EntryProbe {
    item: Probe,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadIn {
    export_schema: u32,
    vault_id: String,
    #[allow(dead_code)]
    exported_ms: u64,
    items: Vec<EntryIn>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryIn {
    id: String,
    revision: u64,
    item: WireIn,
}

fn hex16(s: &str) -> Result<[u8; 16]> {
    base32::hex_decode(s)
        .ok()
        .and_then(|v| <[u8; 16]>::try_from(v).ok())
        .ok_or(Error::Corrupt("export id"))
}

/// Build `header ‖ ct` for `payload` (CS §8). Header bytes are the AEAD associated data.
pub(super) fn seal_export(
    payload: &[u8],
    export_password: &SecretString,
    key: &SecretKey,
    params: KdfParams,
) -> Result<Vec<u8>> {
    let ct_len = payload
        .len()
        .checked_add(TAG_LEN)
        .ok_or(Error::LimitExceeded)?;
    let salt = rng::random_array::<16>()?;
    let nonce = rng::random_array::<24>()?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct_len);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.push(1);
    out.push(0x13);
    out.extend_from_slice(&params.m_kib.to_be_bytes());
    out.extend_from_slice(&params.t.to_be_bytes());
    out.extend_from_slice(&params.p.to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(ct_len as u64).to_be_bytes());
    debug_assert_eq!(out.len(), HEADER_LEN);
    let kx = derive_kx(export_password, &salt, &params, key)?;
    let ad = [LABEL_X, &out[..]].concat();
    let ct = aead::seal_with_nonce(&kx, &nonce, &ad, payload)?;
    out.extend_from_slice(&ct);
    Ok(out)
}

fn derive_kx(
    export_password: &SecretString,
    salt: &[u8; 16],
    params: &KdfParams,
    key: &SecretKey,
) -> Result<AeadKey> {
    let pw = kdf::normalize_password(export_password.expose());
    let pw_key = kdf::argon2id(pw.expose(), salt, params)?;
    let mut ikm = Zeroizing::new([0u8; 64]);
    let (a, b) = ikm.split_at_mut(32);
    a.copy_from_slice(pw_key.expose());
    b.copy_from_slice(key.expose());
    let k = hkdf::extract_expand(salt, &ikm[..], INFO_EXPORT)?;
    let mut raw = *k.expose();
    let ak = AeadKey::new(raw);
    raw.zeroize();
    Ok(ak)
}

struct Parsed {
    entries: Vec<(ItemId, u64, Item, u64, u64)>,
}

/// Steps 1-10 of the CS §9 export table on `bytes`; returns the validated items.
fn open_export(bytes: &[u8], export_password: &SecretString, key: &SecretKey) -> Result<Parsed> {
    let corrupt = |m| Error::Corrupt(m);
    // 1 (the upper bound is enforced by the bounded read)
    if bytes.len() < HEADER_LEN + TAG_LEN {
        return Err(corrupt("export too short"));
    }
    if bytes.len() > MAX_EXPORT_PLAINTEXT + HEADER_LEN + TAG_LEN {
        return Err(Error::LimitExceeded);
    }
    let hdr = bytes.get(..HEADER_LEN).ok_or(corrupt("export too short"))?;
    let mut r = Cursor { d: hdr, p: 0 };
    // 2
    if r.take(8)? != MAGIC {
        return Err(corrupt("export magic"));
    }
    // 3
    if r.u16()? != 1 {
        return Err(Error::UnsupportedVersion);
    }
    // 4
    if r.u16()? != 0 {
        return Err(corrupt("export flags"));
    }
    // 5
    let (kdf_id, kdf_version) = (r.take(1)?, r.take(1)?);
    if kdf_id != [1] || kdf_version != [0x13] {
        return Err(Error::UnsupportedVersion);
    }
    // 6
    let params = KdfParams {
        m_kib: r.u32()?,
        t: r.u32()?,
        p: r.u32()?,
    };
    params
        .validate()
        .map_err(|_| corrupt("export kdf parameters"))?;
    let salt: [u8; 16] = r.arr()?;
    let nonce: [u8; 24] = r.arr()?;
    let ct_len = u64::from_be_bytes(r.arr()?);
    // 7
    let body = bytes.get(HEADER_LEN..).ok_or(corrupt("export too short"))?;
    if ct_len != body.len() as u64 || ct_len > (MAX_EXPORT_PLAINTEXT + TAG_LEN) as u64 {
        return Err(corrupt("export ct_len"));
    }
    // 8
    let kx = derive_kx(export_password, &salt, &params, key)?;
    let ad = [LABEL_X, hdr].concat();
    let pt = aead::open(&kx, &nonce, &ad, body)?;
    parse_payload(&pt)
}

struct Cursor<'a> {
    d: &'a [u8],
    p: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.p.checked_add(n).ok_or(Error::Corrupt("export"))?;
        let s = self.d.get(self.p..end).ok_or(Error::Corrupt("export"))?;
        self.p = end;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::Corrupt("export"))
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.arr()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.arr()?))
    }
}

/// Steps 9-10: two-pass payload reading.
fn parse_payload(pt: &SecretVec) -> Result<Parsed> {
    let bytes = pt.expose();
    let top: TopProbe =
        serde_json::from_slice(bytes).map_err(|_| Error::Corrupt("export schema probe"))?;
    if top.export_schema != 1 {
        return Err(Error::UnsupportedVersion);
    }
    let probe: ItemsProbe =
        serde_json::from_slice(bytes).map_err(|_| Error::Corrupt("export items probe"))?;
    if probe.items.iter().any(|e| e.item.schema != 1) {
        return Err(Error::UnsupportedVersion);
    }
    drop(probe);
    let p: PayloadIn =
        serde_json::from_slice(bytes).map_err(|_| Error::Corrupt("export payload"))?;
    if p.export_schema != 1 {
        return Err(Error::UnsupportedVersion);
    }
    hex16(&p.vault_id)?;
    if p.items.len() > MAX_RECORDS as usize {
        return Err(Error::Corrupt("too many items"));
    }
    let mut entries = Vec::with_capacity(p.items.len());
    let mut prev: Option<[u8; 16]> = None;
    for e in p.items {
        let id = hex16(&e.id)?;
        if prev.is_some_and(|q| q >= id) {
            return Err(Error::Corrupt("export ids not ascending"));
        }
        prev = Some(id);
        if e.revision == 0 {
            return Err(Error::Corrupt("export revision"));
        }
        let (item, c, u) = Item::from_wire(e.item)?;
        entries.push((ItemId(id), e.revision, item, c, u));
    }
    Ok(Parsed { entries })
}

impl Vault {
    /// Write an encrypted export of every item to `path` (CS §8). `key` is the secret key the
    /// export is bound to; `params` are the Argon2id parameters of the export file.
    /// The password minimum applies here only. Never writes to the vault file itself.
    pub fn export(
        &self,
        path: &Path,
        export_password: &SecretString,
        key: &SecretKey,
        params: KdfParams,
    ) -> Result<()> {
        kdf::check_new_password(export_password.expose())?;
        params.validate()?;
        if storage::same_file_path(path, &self.path)? {
            return Err(Error::InvalidInput("export target is the vault file"));
        }
        let now = self.clock.now_ms();
        let mut stored = Vec::with_capacity(self.file.records.len());
        for rec in &self.file.records {
            stored.push(self.open_at(rec)?);
        }
        let out = PayloadOut {
            export_schema: 1,
            vault_id: base32::hex_encode(&self.file.header.vault_id),
            exported_ms: now,
            items: stored
                .iter()
                .map(|s| EntryOut {
                    id: base32::hex_encode(&s.id.0),
                    revision: s.revision,
                    item: s.item.wire_out(s.created_ms, s.updated_ms),
                })
                .collect(),
        };
        let mut counter = CountingWriter(0);
        serde_json::to_writer(&mut counter, &out).map_err(|_| Error::InvalidInput("serialize"))?;
        if counter.0 > max_payload() {
            return Err(Error::LimitExceeded);
        }
        let mut payload = Zeroizing::new(Vec::with_capacity(counter.0));
        serde_json::to_writer(&mut *payload, &out).map_err(|_| Error::InvalidInput("serialize"))?;
        let file = seal_export(&payload, export_password, key, params)?;
        storage::write_atomic(path, &file)
    }

    /// Import every item of an export file under its original id and revision (CS §9 export
    /// table). No password minimum. Writes the vault once; returns the number of items.
    pub fn import(
        &mut self,
        path: &Path,
        export_password: &SecretString,
        source_key: &SecretKey,
    ) -> Result<usize> {
        let bytes =
            storage::read_bounded(path, (MAX_EXPORT_PLAINTEXT + HEADER_LEN + TAG_LEN) as u64)?;
        let parsed = open_export(&bytes, export_password, source_key)?;
        drop(bytes);
        // 11
        if parsed
            .entries
            .iter()
            .any(|(id, ..)| self.index_of(id).is_ok())
        {
            return Err(Error::Conflict);
        }
        // 12
        let total = self.file.records.len() + parsed.entries.len();
        if total > max_records() {
            return Err(Error::LimitExceeded);
        }
        let n = parsed.entries.len();
        let mut records: Vec<Record> = self.file.records.clone();
        for (id, revision, item, c, u) in &parsed.entries {
            records.push(seal::seal_item(
                &self.k_iw,
                &self.file.header.vault_id,
                id,
                *revision,
                item,
                *c,
                *u,
            )?);
        }
        records.sort_by_key(|r| r.item_id);
        if records.len() > max_records() {
            return Err(Error::LimitExceeded);
        }
        self.commit(records)?;
        Ok(n)
    }
}
