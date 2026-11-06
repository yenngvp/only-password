//! Pure, key-free byte codec for the vault file (CS §5, §9 steps 1-7, §10).
//!
//! Parsing never indexes, never panics and never allocates more than the input length:
//! every untrusted length is checked against the bytes actually left before use.

use crate::crypto::kdf::KdfParams;
use crate::item::MAX_ITEM_PLAINTEXT;
use crate::{Error, Result};

pub const MAGIC: [u8; 8] = *b"OPVAULT\0";
pub const HEADER_LEN: usize = 130;
pub const RECORD_FIXED_LEN: usize = 126;
pub const TRAILER_LEN: usize = 40;
pub const MAX_RECORDS: u32 = 100_000;
pub const MAX_VAULT_FILE: usize = 536_870_912;
const MIN_FILE: usize = HEADER_LEN + 4 + TRAILER_LEN;
const TAG: usize = 16;
const MAX_BODY_CT: usize = MAX_ITEM_PLAINTEXT + TAG;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub vault_id: [u8; 16],
    pub kdf: KdfParams,
    pub kdf_salt: [u8; 16],
    pub vk_nonce: [u8; 24],
    pub wrapped_vk: [u8; 48],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub item_id: [u8; 16],
    pub revision: u64,
    pub item_schema: u16,
    pub key_nonce: [u8; 24],
    pub wrapped_ik: [u8; 48],
    pub body_nonce: [u8; 24],
    /// Ciphertext ‖ tag (public data).
    pub body_ct: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trailer {
    pub nonce: [u8; 24],
    pub tag: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultFile {
    pub header: Header,
    pub records: Vec<Record>,
    pub trailer: Trailer,
}

/// Bounds-checked cursor over untrusted bytes.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::Corrupt("length overflow"))?;
        let s = self
            .data
            .get(self.pos..end)
            .ok_or(Error::Corrupt("truncated"))?;
        self.pos = end;
        Ok(s)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::Corrupt("truncated"))
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_be_bytes(self.array()?))
    }
}

impl VaultFile {
    /// Parse a vault file, applying CS §9 steps 1-7 in order.
    pub fn parse(bytes: &[u8]) -> Result<VaultFile> {
        // 1: length
        if bytes.len() > MAX_VAULT_FILE {
            return Err(Error::LimitExceeded);
        }
        if bytes.len() < MIN_FILE {
            return Err(Error::Corrupt("file too short"));
        }
        let mut r = Reader {
            data: bytes,
            pos: 0,
        };
        // 2: magic
        if r.array::<8>()? != MAGIC {
            return Err(Error::Corrupt("bad magic"));
        }
        // 3: format version
        if r.u16()? != 1 {
            return Err(Error::UnsupportedVersion);
        }
        // 4: flags
        if r.u16()? != 0 {
            return Err(Error::Corrupt("bad flags"));
        }
        let vault_id = r.array::<16>()?;
        // 5: kdf id / version
        let kdf_id = r.u8()?;
        let kdf_version = r.u8()?;
        if kdf_id != 1 || kdf_version != 0x13 {
            return Err(Error::UnsupportedVersion);
        }
        // 6: kdf bounds
        let kdf = KdfParams {
            m_kib: r.u32()?,
            t: r.u32()?,
            p: r.u32()?,
        };
        kdf.validate()
            .map_err(|_| Error::Corrupt("kdf parameters out of range"))?;
        // 7: structure
        let kdf_salt = r.array::<16>()?;
        let vk_nonce = r.array::<24>()?;
        let wrapped_vk = r.array::<48>()?;
        let header = Header {
            vault_id,
            kdf,
            kdf_salt,
            vk_nonce,
            wrapped_vk,
        };

        let count = r.u32()?;
        if count > MAX_RECORDS {
            return Err(Error::Corrupt("too many records"));
        }
        // Records live between here and the trailer.
        let body_end = bytes
            .len()
            .checked_sub(TRAILER_LEN)
            .ok_or(Error::Corrupt("truncated"))?;
        let body = bytes
            .get(r.pos..body_end)
            .ok_or(Error::Corrupt("truncated"))?;
        let mut rr = Reader { data: body, pos: 0 };
        let min_record = 4 + RECORD_FIXED_LEN + TAG;
        let count = usize::try_from(count).map_err(|_| Error::Corrupt("too many records"))?;
        // Bounds the allocation below by the real input length.
        if count > rr.remaining() / min_record {
            return Err(Error::Corrupt("record count exceeds data"));
        }
        let mut records: Vec<Record> = Vec::with_capacity(count);
        for _ in 0..count {
            let record_len =
                usize::try_from(rr.u32()?).map_err(|_| Error::Corrupt("record_len"))?;
            if !(RECORD_FIXED_LEN + TAG..=RECORD_FIXED_LEN + MAX_BODY_CT).contains(&record_len)
                || record_len > rr.remaining()
            {
                return Err(Error::Corrupt("record_len out of range"));
            }
            let rec = rr.take(record_len)?;
            let rec = parse_record(rec)?;
            if let Some(prev) = records.last() {
                if prev.item_id >= rec.item_id {
                    return Err(Error::Corrupt("records not strictly ascending"));
                }
            }
            records.push(rec);
        }
        if rr.remaining() != 0 {
            return Err(Error::Corrupt("trailing bytes"));
        }
        let mut tr = Reader {
            data: bytes.get(body_end..).ok_or(Error::Corrupt("truncated"))?,
            pos: 0,
        };
        let trailer = Trailer {
            nonce: tr.array()?,
            tag: tr.array()?,
        };
        Ok(VaultFile {
            header,
            records,
            trailer,
        })
    }

    /// Deterministic serialization. Refuses images that `parse` would not accept
    /// structurally (limits, ordering).
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let n = u32::try_from(self.records.len()).map_err(|_| Error::LimitExceeded)?;
        if n > MAX_RECORDS {
            return Err(Error::LimitExceeded);
        }
        let mut total = MIN_FILE;
        for (i, rec) in self.records.iter().enumerate() {
            if rec.body_ct.len() < TAG || rec.body_ct.len() > MAX_BODY_CT {
                return Err(Error::LimitExceeded);
            }
            if let Some(prev) = i.checked_sub(1).and_then(|j| self.records.get(j)) {
                if prev.item_id >= rec.item_id {
                    return Err(Error::Corrupt("records not strictly ascending"));
                }
            }
            total = total
                .checked_add(4 + RECORD_FIXED_LEN + rec.body_ct.len())
                .ok_or(Error::LimitExceeded)?;
            if total > MAX_VAULT_FILE {
                return Err(Error::LimitExceeded);
            }
        }
        let h = &self.header;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&h.vault_id);
        out.push(1);
        out.push(0x13);
        out.extend_from_slice(&h.kdf.m_kib.to_be_bytes());
        out.extend_from_slice(&h.kdf.t.to_be_bytes());
        out.extend_from_slice(&h.kdf.p.to_be_bytes());
        out.extend_from_slice(&h.kdf_salt);
        out.extend_from_slice(&h.vk_nonce);
        out.extend_from_slice(&h.wrapped_vk);
        out.extend_from_slice(&n.to_be_bytes());
        for rec in &self.records {
            // Cannot fail: body_ct.len() <= MAX_BODY_CT was checked above.
            let body_len = u32::try_from(rec.body_ct.len()).map_err(|_| Error::LimitExceeded)?;
            let record_len = body_len
                .checked_add(RECORD_FIXED_LEN as u32)
                .ok_or(Error::LimitExceeded)?;
            out.extend_from_slice(&record_len.to_be_bytes());
            out.extend_from_slice(&rec.item_id);
            out.extend_from_slice(&rec.revision.to_be_bytes());
            out.extend_from_slice(&rec.item_schema.to_be_bytes());
            out.extend_from_slice(&rec.key_nonce);
            out.extend_from_slice(&rec.wrapped_ik);
            out.extend_from_slice(&rec.body_nonce);
            out.extend_from_slice(&body_len.to_be_bytes());
            out.extend_from_slice(&rec.body_ct);
        }
        out.extend_from_slice(&self.trailer.nonce);
        out.extend_from_slice(&self.trailer.tag);
        Ok(out)
    }
}

fn parse_record(bytes: &[u8]) -> Result<Record> {
    let mut r = Reader {
        data: bytes,
        pos: 0,
    };
    let item_id = r.array()?;
    let revision = r.u64()?;
    let item_schema = r.u16()?;
    let key_nonce = r.array()?;
    let wrapped_ik = r.array()?;
    let body_nonce = r.array()?;
    let body_ct_len = usize::try_from(r.u32()?).map_err(|_| Error::Corrupt("body_ct_len"))?;
    if !(TAG..=MAX_BODY_CT).contains(&body_ct_len) || body_ct_len != r.remaining() {
        return Err(Error::Corrupt("body_ct_len mismatch"));
    }
    let body_ct = r.take(body_ct_len)?.to_vec();
    Ok(Record {
        item_id,
        revision,
        item_schema,
        key_nonce,
        wrapped_ik,
        body_nonce,
        body_ct,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corrupt<T: std::fmt::Debug>(r: Result<T>) {
        assert!(matches!(r, Err(Error::Corrupt(_))), "got {r:?}");
    }

    /// Hand-built image from the CS §5 offsets, independent of `serialize`.
    fn image(ids: &[u8], body_len: usize) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"OPVAULT\0");
        v.extend_from_slice(&[0, 1, 0, 0]);
        v.extend_from_slice(&[0x11; 16]);
        v.extend_from_slice(&[1, 0x13]);
        v.extend_from_slice(&19_456u32.to_be_bytes());
        v.extend_from_slice(&2u32.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&[0x22; 16]);
        v.extend_from_slice(&[0x33; 24]);
        v.extend_from_slice(&[0x44; 48]);
        assert_eq!(v.len(), 130);
        v.extend_from_slice(&(ids.len() as u32).to_be_bytes());
        for (i, id) in ids.iter().enumerate() {
            v.extend_from_slice(&((126 + body_len) as u32).to_be_bytes());
            v.extend_from_slice(&[*id; 16]);
            v.extend_from_slice(&(7u64 + i as u64).to_be_bytes());
            v.extend_from_slice(&[0, 1]);
            v.extend_from_slice(&[0x55; 24]);
            v.extend_from_slice(&[0x66; 48]);
            v.extend_from_slice(&[0x77; 24]);
            v.extend_from_slice(&(body_len as u32).to_be_bytes());
            v.extend_from_slice(&vec![0x88 + i as u8; body_len]);
        }
        v.extend_from_slice(&[0x99; 24]);
        v.extend_from_slice(&[0xAA; 16]);
        v
    }

    #[test]
    fn layout_and_round_trip() {
        let img = image(&[1, 2, 3], 20);
        let f = VaultFile::parse(&img).unwrap();
        assert_eq!(f.header.vault_id, [0x11; 16]);
        assert_eq!(
            f.header.kdf,
            KdfParams {
                m_kib: 19_456,
                t: 2,
                p: 1
            }
        );
        assert_eq!(f.header.kdf_salt, [0x22; 16]);
        assert_eq!(f.header.vk_nonce, [0x33; 24]);
        assert_eq!(f.header.wrapped_vk, [0x44; 48]);
        assert_eq!(f.records.len(), 3);
        let r = &f.records[1];
        assert_eq!(r.item_id, [2; 16]);
        assert_eq!(r.revision, 8);
        assert_eq!(r.item_schema, 1);
        assert_eq!(r.key_nonce, [0x55; 24]);
        assert_eq!(r.wrapped_ik, [0x66; 48]);
        assert_eq!(r.body_nonce, [0x77; 24]);
        assert_eq!(r.body_ct, vec![0x89; 20]);
        assert_eq!(f.trailer.nonce, [0x99; 24]);
        assert_eq!(f.trailer.tag, [0xAA; 16]);
        assert_eq!(f.serialize().unwrap(), img);
    }

    #[test]
    fn empty_vault_round_trips() {
        let img = image(&[], 16);
        assert_eq!(img.len(), 174);
        assert_eq!(VaultFile::parse(&img).unwrap().serialize().unwrap(), img);
    }

    #[test]
    fn versions() {
        for v in [0u16, 2, 0xFFFF] {
            let mut img = image(&[1], 16);
            img[8..10].copy_from_slice(&v.to_be_bytes());
            assert_eq!(VaultFile::parse(&img), Err(Error::UnsupportedVersion));
        }
        let mut img = image(&[1], 16);
        img[28] = 2;
        assert_eq!(VaultFile::parse(&img), Err(Error::UnsupportedVersion));
        let mut img = image(&[1], 16);
        img[29] = 0x10;
        assert_eq!(VaultFile::parse(&img), Err(Error::UnsupportedVersion));
    }

    #[test]
    fn flags_and_magic() {
        let mut img = image(&[1], 16);
        img[11] = 1;
        corrupt(VaultFile::parse(&img));
        let mut img = image(&[1], 16);
        img[10] = 0x80;
        corrupt(VaultFile::parse(&img));
        let mut img = image(&[1], 16);
        img[0..8].copy_from_slice(b"OPEXPORT");
        corrupt(VaultFile::parse(&img));
        let mut img = image(&[1], 16);
        img[7] = 1;
        corrupt(VaultFile::parse(&img));
    }

    #[test]
    fn kdf_bounds() {
        let cases: [(usize, u32); 7] = [
            (30, 8_191), // below even the test floor
            (30, 262_145),
            (34, 0),
            (34, 17),
            (38, 0),
            (38, 17),
            (30, u32::MAX),
        ];
        for (off, val) in cases {
            let mut img = image(&[1], 16);
            img[off..off + 4].copy_from_slice(&val.to_be_bytes());
            corrupt(VaultFile::parse(&img));
        }
    }

    #[test]
    fn real_floor_is_enforced_by_validate_strict() {
        let below = KdfParams {
            m_kib: 19_455,
            t: 2,
            p: 1,
        };
        assert!(below.validate_strict().is_err());
    }

    #[test]
    fn first_failing_step_decides() {
        let mut img = image(&[1], 16);
        img[8..10].copy_from_slice(&2u16.to_be_bytes());
        img[11] = 1;
        assert_eq!(VaultFile::parse(&img), Err(Error::UnsupportedVersion));
        // bad flags + bad kdf_id: flags (step 4) first
        let mut img = image(&[1], 16);
        img[11] = 1;
        img[28] = 9;
        corrupt(VaultFile::parse(&img));
        // bad kdf_id + bad params: kdf_id (step 5) first
        let mut img = image(&[1], 16);
        img[28] = 9;
        img[34..38].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(VaultFile::parse(&img), Err(Error::UnsupportedVersion));
        // bad magic + bad version: magic first
        let mut img = image(&[1], 16);
        img[0] = b'X';
        img[9] = 9;
        corrupt(VaultFile::parse(&img));
    }

    #[test]
    fn structure_faults() {
        // record_len mismatch
        let mut img = image(&[1], 16);
        img[134..138].copy_from_slice(&(143u32).to_be_bytes());
        corrupt(VaultFile::parse(&img));
        // body_ct_len mismatch
        let mut img = image(&[1], 16);
        img[134 + 4 + 122..134 + 4 + 126].copy_from_slice(&17u32.to_be_bytes());
        corrupt(VaultFile::parse(&img));
        // body_ct_len below tag size, consistent record_len
        let mut img = image(&[1], 16);
        img[134..138].copy_from_slice(&(141u32).to_be_bytes());
        img[134 + 4 + 122..134 + 4 + 126].copy_from_slice(&15u32.to_be_bytes());
        corrupt(VaultFile::parse(&img));
        // record_count too big for data / over limit
        for c in [2u32, 100_001, u32::MAX] {
            let mut img = image(&[1], 16);
            img[130..134].copy_from_slice(&c.to_be_bytes());
            corrupt(VaultFile::parse(&img));
        }
        // record_count smaller than data (trailing record bytes)
        let mut img = image(&[1, 2], 16);
        img[130..134].copy_from_slice(&1u32.to_be_bytes());
        corrupt(VaultFile::parse(&img));
        // unsorted and duplicate
        corrupt(VaultFile::parse(&image(&[2, 1], 16)));
        corrupt(VaultFile::parse(&image(&[1, 1], 16)));
        // trailing byte
        let mut img = image(&[1], 16);
        img.push(0);
        corrupt(VaultFile::parse(&img));
    }

    #[test]
    fn huge_claims_do_not_allocate() {
        // record_len of 4 GiB - 1
        let mut img = image(&[1], 16);
        img[134..138].copy_from_slice(&u32::MAX.to_be_bytes());
        corrupt(VaultFile::parse(&img));
        // record_count u32::MAX on a minimal file
        let mut img = image(&[], 16);
        img[130..134].copy_from_slice(&u32::MAX.to_be_bytes());
        corrupt(VaultFile::parse(&img));
    }

    #[test]
    fn truncation_at_every_length() {
        let img = image(&[1, 2], 20);
        for len in 0..img.len() {
            corrupt(VaultFile::parse(&img[..len]));
        }
        assert!(VaultFile::parse(&img).is_ok());
    }

    #[test]
    fn oversize_input_is_limit_exceeded() {
        let big = vec![0u8; MAX_VAULT_FILE + 1];
        assert_eq!(VaultFile::parse(&big), Err(Error::LimitExceeded));
    }

    #[test]
    fn serialize_rejects_bad_records() {
        let f = VaultFile::parse(&image(&[1, 2], 16)).unwrap();
        let mut g = f.clone();
        g.records.swap(0, 1);
        corrupt(g.serialize());
        let mut g = f.clone();
        g.records[0].body_ct.truncate(15);
        assert_eq!(g.serialize(), Err(Error::LimitExceeded));
        let mut g = f;
        g.records[0].body_ct = vec![0; MAX_BODY_CT + 1];
        assert_eq!(g.serialize(), Err(Error::LimitExceeded));
    }
}
