//! Sealing: joins `crypto` and `format` (CS §6). Header wrap, item records, file trailer.
//!
//! Records can only be opened through [`OpenedVault`], which is constructed solely by
//! [`open_vault`] after the VK unwrap (CS §9 step 8) and the trailer check (step 9) have
//! succeeded, so no record is decrypted before the trailer verifies.

use crate::crypto::aead::{self, AeadKey, Sealed};
use crate::crypto::keys::{FileAuthKey, ItemKey, ItemWrapKey, MasterKey, VaultKey};
use crate::format::{Header, Record, Trailer, VaultFile, TRAILER_LEN};
use crate::item::{Item, ItemId};
use crate::secret::SecretBytes;
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const LABEL_VK: &[u8] = b"onlypassword/v1/vault-key";
const LABEL_IK: &[u8] = b"onlypassword/v1/item-key";
const LABEL_BODY: &[u8] = b"onlypassword/v1/item-body";
const LABEL_FILE: &[u8] = b"onlypassword/v1/file";
const HEADER_PREFIX_LEN: usize = 82;
const FORMAT_VERSION: u16 = 1;
const ITEM_SCHEMA: u16 = 1;

fn aead_key(k: &[u8; 32]) -> AeadKey {
    let mut a = *k;
    let key = AeadKey::new(a);
    a.zeroize();
    key
}

/// Header bytes 0..82 (CS §5), the associated data of the VK wrap.
fn header_prefix(h: &Header) -> Vec<u8> {
    let mut o = Vec::with_capacity(HEADER_PREFIX_LEN);
    o.extend_from_slice(&crate::format::MAGIC);
    o.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    o.extend_from_slice(&0u16.to_be_bytes());
    o.extend_from_slice(&h.vault_id);
    o.push(1);
    o.push(0x13);
    o.extend_from_slice(&h.kdf.m_kib.to_be_bytes());
    o.extend_from_slice(&h.kdf.t.to_be_bytes());
    o.extend_from_slice(&h.kdf.p.to_be_bytes());
    o.extend_from_slice(&h.kdf_salt);
    o.extend_from_slice(&h.vk_nonce);
    o
}

fn ad_vk(prefix: &[u8]) -> Vec<u8> {
    [LABEL_VK, prefix].concat()
}

fn ad_item(
    label: &[u8],
    vault_id: &[u8; 16],
    item_id: &[u8; 16],
    rev: u64,
    schema: u16,
) -> Vec<u8> {
    let mut o = Vec::with_capacity(label.len() + 44);
    o.extend_from_slice(label);
    o.extend_from_slice(vault_id);
    o.extend_from_slice(item_id);
    o.extend_from_slice(&rev.to_be_bytes());
    o.extend_from_slice(&schema.to_be_bytes());
    o.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    o
}

fn ad_file(file_prefix: &[u8]) -> Vec<u8> {
    let h = Sha256::digest(file_prefix);
    [LABEL_FILE, h.as_slice()].concat()
}

fn fixed<const N: usize>(v: &[u8]) -> Result<[u8; N]> {
    v.try_into().map_err(|_| Error::Corrupt("length"))
}

/// Generate a VK and wrap it under `mk` into a complete header (new nonce each call).
/// `vk` is supplied by the caller so password change can re-wrap the same VK.
pub fn wrap_vk(
    mk: &MasterKey,
    vk: &VaultKey,
    vault_id: [u8; 16],
    kdf: crate::crypto::kdf::KdfParams,
    kdf_salt: [u8; 16],
) -> Result<Header> {
    let nonce = crate::rng::random_array::<24>()?;
    let mut h = Header {
        vault_id,
        kdf,
        kdf_salt,
        vk_nonce: nonce,
        wrapped_vk: [0u8; 48],
    };
    let ad = ad_vk(&header_prefix(&h));
    let ct = aead::seal_with_nonce(&aead_key(mk.expose()), &nonce, &ad, vk.expose())?;
    h.wrapped_vk = fixed(&ct)?;
    Ok(h)
}

/// Recover VK. Wrong MK or any changed header-prefix byte: `Authentication`.
pub fn unwrap_vk(mk: &MasterKey, h: &Header) -> Result<VaultKey> {
    let ad = ad_vk(&header_prefix(h));
    let pt = aead::open(&aead_key(mk.expose()), &h.vk_nonce, &ad, &h.wrapped_vk)?;
    let arr: [u8; 32] = pt.expose().try_into().map_err(|_| Error::Authentication)?;
    let mut arr = arr;
    let k = VaultKey::from_secret(SecretBytes::new(arr));
    arr.zeroize();
    Ok(k)
}

/// Seal one item revision with a fresh IK and fresh nonces (CS §6.3).
pub fn seal_item(
    k_iw: &ItemWrapKey,
    vault_id: &[u8; 16],
    item_id: &ItemId,
    revision: u64,
    item: &Item,
    created_ms: u64,
    updated_ms: u64,
) -> Result<Record> {
    let pt = item.to_plaintext(created_ms, updated_ms)?;
    seal_record(k_iw, vault_id, &item_id.0, revision, ITEM_SCHEMA, &pt)
}

/// Seal raw plaintext under an explicit `item_schema` (tests exercise schema mismatches).
pub(crate) fn seal_record(
    k_iw: &ItemWrapKey,
    vault_id: &[u8; 16],
    item_id: &[u8; 16],
    revision: u64,
    item_schema: u16,
    plaintext: &[u8],
) -> Result<Record> {
    if revision == 0 {
        return Err(Error::InvalidInput("revision"));
    }
    let ik = ItemKey::generate()?;
    let wrapped = aead::seal(
        &aead_key(k_iw.expose()),
        &ad_item(LABEL_IK, vault_id, item_id, revision, item_schema),
        ik.expose(),
    )?;
    let body = aead::seal(
        &aead_key(ik.expose()),
        &ad_item(LABEL_BODY, vault_id, item_id, revision, item_schema),
        plaintext,
    )?;
    let Sealed {
        nonce: key_nonce,
        ciphertext_and_tag,
    } = wrapped;
    Ok(Record {
        item_id: *item_id,
        revision,
        item_schema,
        key_nonce,
        wrapped_ik: fixed(&ciphertext_and_tag)?,
        body_nonce: body.nonce,
        body_ct: body.ciphertext_and_tag,
    })
}

/// Decrypt a record: `Authentication` for any AEAD failure (including a changed
/// `item_schema`), then JSON pass 1/2 per CS §7/§9.
fn open_record(k_iw: &ItemWrapKey, vault_id: &[u8; 16], rec: &Record) -> Result<(Item, u64, u64)> {
    let ik_bytes = aead::open(
        &aead_key(k_iw.expose()),
        &rec.key_nonce,
        &ad_item(
            LABEL_IK,
            vault_id,
            &rec.item_id,
            rec.revision,
            rec.item_schema,
        ),
        &rec.wrapped_ik,
    )?;
    let mut arr: [u8; 32] = ik_bytes
        .expose()
        .try_into()
        .map_err(|_| Error::Authentication)?;
    let ik = ItemKey::from_secret(SecretBytes::new(arr));
    arr.zeroize();
    let pt = aead::open(
        &aead_key(ik.expose()),
        &rec.body_nonce,
        &ad_item(
            LABEL_BODY,
            vault_id,
            &rec.item_id,
            rec.revision,
            rec.item_schema,
        ),
        &rec.body_ct,
    )?;
    let (item, c, u) = Item::from_plaintext(pt.expose())?;
    // from_plaintext accepted schema 1 only; the record must agree (CS §7).
    if rec.item_schema != ITEM_SCHEMA {
        return Err(Error::Corrupt("item_schema mismatch"));
    }
    Ok((item, c, u))
}

/// Trailer over SHA-256 of the file prefix (everything before the trailer), CS §6.4.
pub fn compute_trailer(k_fa: &FileAuthKey, file_prefix: &[u8]) -> Result<Trailer> {
    let s = aead::seal(&aead_key(k_fa.expose()), &ad_file(file_prefix), b"")?;
    Ok(Trailer {
        nonce: s.nonce,
        tag: fixed(&s.ciphertext_and_tag)?,
    })
}

pub fn verify_trailer(k_fa: &FileAuthKey, file_prefix: &[u8], t: &Trailer) -> Result<()> {
    aead::open(
        &aead_key(k_fa.expose()),
        &t.nonce,
        &ad_file(file_prefix),
        &t.tag,
    )
    .map(|_| ())
}

/// Serialize header + records and append a freshly computed trailer.
pub fn build_image(header: &Header, records: Vec<Record>, vk: &VaultKey) -> Result<Vec<u8>> {
    let mut vf = VaultFile {
        header: header.clone(),
        records,
        trailer: Trailer {
            nonce: [0; 24],
            tag: [0; 16],
        },
    };
    let mut img = vf.serialize()?;
    let start = img
        .len()
        .checked_sub(TRAILER_LEN)
        .ok_or(Error::Corrupt("length"))?;
    img.truncate(start);
    vf.trailer = compute_trailer(&vk.file_auth_key()?, &img)?;
    img.extend_from_slice(&vf.trailer.nonce);
    img.extend_from_slice(&vf.trailer.tag);
    Ok(img)
}

/// A vault image whose VK unwrap and trailer have been verified.
#[derive(Debug)]
pub struct OpenedVault {
    pub file: VaultFile,
    vk: VaultKey,
    k_iw: ItemWrapKey,
}

impl OpenedVault {
    pub fn vault_key(&self) -> &VaultKey {
        &self.vk
    }

    pub fn open_item(&self, rec: &Record) -> Result<(Item, u64, u64)> {
        open_record(&self.k_iw, &self.file.header.vault_id, rec)
    }
}

/// CS §9 steps 1-9: parse, unwrap VK, verify trailer. Decrypts no record.
pub fn open_vault(bytes: &[u8], mk: &MasterKey) -> Result<OpenedVault> {
    let file = VaultFile::parse(bytes)?;
    let vk = unwrap_vk(mk, &file.header)?;
    let start = bytes
        .len()
        .checked_sub(TRAILER_LEN)
        .ok_or(Error::Corrupt("length"))?;
    let prefix = bytes.get(..start).ok_or(Error::Corrupt("length"))?;
    verify_trailer(&vk.file_auth_key()?, prefix, &file.trailer)?;
    let k_iw = vk.item_wrap_key()?;
    Ok(OpenedVault { file, vk, k_iw })
}

#[cfg(test)]
mod tests;
