# Cryptographic specification

Status: normative. Version of this document: format version 1 (`FORMAT_VERSION = 1`).
Every parameter below is also the only value the code may accept unless a range is
stated. Where this file and another spec file disagree, this file wins for anything
byte-level; record the conflict in `agent-notes/spec-issues.md`.

## 1. Conventions

- **Integers** are unsigned and **big-endian**. `u8`, `u16`, `u32`, `u64` are 1, 2, 4, 8 bytes.
- `‖` is byte-string concatenation. `"text"` is its ASCII bytes with no terminator.
- **Randomness**: every random value (keys, salts, nonces, IDs) comes from the operating
  system CSPRNG (`getrandom`). If it fails, the operation fails; there is no fallback.
- **Key sizes**: all symmetric keys are 32 bytes. Nonces are 24 bytes. Tags are 16 bytes.
- All lengths read from a file are validated against the limits in §10 *before* any
  allocation or key derivation that depends on them.

## 2. Primitives (the complete list)

| Use | Primitive | Reference |
|---|---|---|
| Password hashing | Argon2id, version 0x13, output 32 bytes | RFC 9106 §3, §4 (parameter choice: §4 "second recommended option": t=3, p=4, m=64 MiB) |
| Key combination and subkeys | HKDF-SHA-256 (Extract and Expand) | RFC 5869 §2.2, §2.3 |
| Authenticated encryption | XChaCha20-Poly1305 (24-byte nonce, 16-byte tag) | draft-irtf-cfrg-xchacha-03 §2 (AEAD_XChaCha20_Poly1305), §2.2 (HChaCha20), §2.3 (XChaCha20), over RFC 8439 §2.8 (ChaCha20-Poly1305) |
| Hash for file binding | SHA-256 | FIPS 180-4 |
| TOTP/HOTP | HMAC-SHA-1, HMAC-SHA-256, HMAC-SHA-512 | RFC 2104, RFC 4226 §5, RFC 6238 §1.2 |
| Text encoding | Base32 (alphabet `A-Z2-7`) | RFC 4648 §6 |
| Password text normalization | Unicode NFKC | UAX #15 |

HMAC is used **only** inside HOTP/TOTP (brief). SHA-256 is used inside HKDF and for the
file binding in §6.4. No other primitive may appear.

A random 192-bit nonce per encryption is the intended use of XChaCha20-Poly1305
(draft-irtf-cfrg-xchacha §2.1: the 192-bit nonce makes random nonces safe). A key is never
used with a counter or a derived nonce.

## 3. Key hierarchy

```
master password ──NFKC──► Argon2id(salt, m,t,p) ──► pw_key (32)
                                                       │
secret key SK (32, random, never in the vault file) ───┤
                                                       ▼
              HKDF-SHA256(salt=kdf_salt, IKM=pw_key‖SK, info=INFO_MK) ──► MK  (master key, 32)
                                                       │ wraps (AEAD, §6.2)
                                                       ▼
                         VK  (vault key, 32, random)  ──┬─ HKDF-Expand(info=INFO_ITEMWRAP) ─► K_iw (item-key wrapping key)
                                                        └─ HKDF-Expand(info=INFO_FILEAUTH) ─► K_fa (file authentication key)
                                                       K_iw wraps ┐
                                                                  ▼
                              IK (item key, 32, random, one per item revision) ─ encrypts item body (§6.3)
```

### 3.1 Password input

`password_bytes = UTF-8(NFKC(password))`. The password is normalized exactly once, here, so
the same typed password unlocks on every platform. Fixed expected results (tested): `U+0065 U+0301` → `C3 A9`; `U+FB01` (ﬁ) → `66 69`; `U+00B5` → `CE BC`; `U+FF11` (full-width 1) → `31`. The normalization tables belong to the `unicode-normalization` version in `Cargo.lock`; a table change for newly assigned code points could in theory change `password_bytes`. This is accepted; `Cargo.lock` is committed, dependency updates are reviewed, and the fixed-result test above must keep passing. Minimum length is 8 Unicode scalar
values *after* normalization; empty or shorter passwords are rejected when creating a
vault, changing the master password, or choosing an export password. (Unlock and import do not
apply the minimum: a failed unlock must say nothing about it, and an export made elsewhere must stay readable.)

### 3.2 Secret key SK

- 32 bytes from the OS CSPRNG, generated when a vault is created.
- Never written to the vault file or export file. The caller stores it.
- **Text form** (for the owner to write down and for the CLI key file):
  `"OPSK1-"` followed by RFC 4648 base32 of the 32 bytes **without padding** (52
  characters), split into 13 groups of 4 characters separated by `-`. Example shape:
  `OPSK1-ABCD-EFGH-…-WXYZ`. Parsing accepts lower or upper case, ignores ASCII spaces and
  `-` after the prefix, requires the `OPSK1-` prefix (case-insensitive), requires exactly 52
  base32 characters, and rejects a final character whose 4 unused low bits are not zero.
  Anything else is `InvalidInput`. A key *file* (CLI) is read as UTF-8, ASCII whitespace (space, tab, CR, LF) is trimmed at both ends, and the result goes to `from_text`; a BOM or any other character is `InvalidInput`.

### 3.3 Master key MK

1. `pw_key = Argon2id(P = password_bytes, S = kdf_salt, m, t, p, T = 32, v = 0x13)` with no
   secret value (K) and no associated data (X). Parameters come from the vault header (§5).
2. `MK = HKDF-SHA256(salt = kdf_salt, IKM = pw_key ‖ SK, info = INFO_MK, L = 32)`
   (Extract then Expand, RFC 5869 §2.2–2.3). `pw_key` and `SK` are each exactly 32 bytes, so
   the concatenation is unambiguous.

Both secrets are required: knowing only one of `pw_key`/`SK` leaves 256 bits unknown
to the attacker in the HKDF input.

### 3.4 Subkeys from VK

`VK` is 32 uniformly random bytes, so it is used directly as the HKDF pseudorandom key
(RFC 5869 §2.3 allows Expand to take a PRK of at least HashLen bytes):
`K_iw = HKDF-Expand(PRK = VK, info = INFO_ITEMWRAP, L = 32)`,
`K_fa = HKDF-Expand(PRK = VK, info = INFO_FILEAUTH, L = 32)`.

### 3.5 Info labels (exact bytes)

```
INFO_MK       = "onlypassword/v1/master-key"
INFO_ITEMWRAP = "onlypassword/v1/item-key-wrap"
INFO_FILEAUTH = "onlypassword/v1/file-auth"
INFO_EXPORT   = "onlypassword/v1/export-key"
```

## 4. AEAD usage

`AEAD_Encrypt(key, nonce, ad, pt) -> ct ‖ tag` and `AEAD_Decrypt` are XChaCha20-Poly1305 as
in the draft above. Decrypt returns an error and **no plaintext** if the tag does not
verify. Every encryption draws a fresh random 24-byte nonce; the nonce is stored next to
the ciphertext. Associated data is always `LABEL ‖ fixed-length fields` (never
variable-length fields without a length), so no two contexts can produce the same AD.

## 5. Vault file layout (format version 1)

```
offset  size  field
0       8     magic            = "OPVAULT" ‖ 0x00        (4F 50 56 41 55 4C 54 00)
8       2     format_version   = 0x0001
10      2     flags            = 0x0000 (any other value: error)
12      16    vault_id         random, fixed for the life of the vault
28      1     kdf_id           = 0x01 (Argon2id; any other value: error)
29      1     kdf_version      = 0x13 (Argon2 v1.3; any other value: error)
30      4     kdf_m_kib        memory in KiB
34      4     kdf_t            iterations
38      4     kdf_p            lanes
42      16    kdf_salt         random; also the HKDF salt in §3.3
58      24    vk_nonce         random
82      48    wrapped_vk       AEAD ciphertext (32) ‖ tag (16) of VK        ── header ends at 130
130     4     record_count     number of item records, n
134     …     n records, each:  u32 record_len ‖ record (record_len bytes)
end-40  24    trailer_nonce
end-16  16    trailer_tag
```

The first 82 bytes (offsets 0–81) are the **header prefix**. Fixed header size is 130 bytes.

### 5.1 Record layout

```
0    16   item_id        random, unique within the file
16   8    revision       starts at 1; +1 on every update of that item
24   2    item_schema    = 0x0001 (version of the item plaintext in §7)
26   24   key_nonce
50   48   wrapped_ik     AEAD ciphertext of IK (32) ‖ tag (16)
98   24   body_nonce
122  4    body_ct_len    = length of the next field; must equal record_len − 126
126  …    body_ct        AEAD ciphertext of the item plaintext ‖ tag (16)
```

`record_len = 126 + body_ct_len`, and `16 ≤ body_ct_len ≤ MAX_ITEM_PLAINTEXT + 16`.
`revision` is a `u64`; an update of an item whose revision is `u64::MAX` returns `LimitExceeded` (only reachable via import, §8). Records appear in strictly ascending `item_id` byte order (duplicates and mis-ordering are
`Corrupt`), so serialization is deterministic given the same nonces.

## 6. Authentication of everything that influences decryption

### 6.1 KDF parameters and header
The header prefix (offsets 0–81) contains the magic, version, flags, vault ID, KDF
parameters, salt and nonce. It is the associated data of the VK wrap, so a change to any
of those bytes makes `wrapped_vk` fail to authenticate (§6.2). Changing the KDF
parameters *also* changes `pw_key`, so a modified header cannot unlock.

### 6.2 Wrapping the vault key
```
AD_VK = "onlypassword/v1/vault-key" ‖ header_prefix        (25 + 82 bytes)
wrapped_vk = AEAD_Encrypt(MK, vk_nonce, AD_VK, VK)
```
A wrong password, wrong secret key, or tampered header all surface as the same single
`Authentication` error.

### 6.3 Items
```
AD_ITEM_SUFFIX = vault_id(16) ‖ item_id(16) ‖ revision(8) ‖ item_schema(2) ‖ format_version(2)
AD_IK   = "onlypassword/v1/item-key"  ‖ AD_ITEM_SUFFIX
AD_BODY = "onlypassword/v1/item-body" ‖ AD_ITEM_SUFFIX
wrapped_ik = AEAD_Encrypt(K_iw, key_nonce,  AD_IK,   IK)
body_ct    = AEAD_Encrypt(IK,   body_nonce, AD_BODY, item_plaintext)
```
A fresh `IK` is generated for every new revision of an item (add and each update). A
A record moved to another item ID, another vault, another revision number, or another
format/schema version fails authentication. `item_schema` is never checked before
decryption: it is read from the record only to build `AD_ITEM_SUFFIX`, so a changed value is
`Authentication` (and the trailer, §6.4, already fails on unlock). After successful
decryption the JSON is handled as in §7/§9.

### 6.4 Whole-file binding (set of items, rollback of single records, removal)
Per-record AD cannot detect that a record was deleted, or replaced by an older valid
record of the same item *within the same vault key*. The trailer closes that gap:
```
h = SHA-256(file[0 .. trailer_start])          (header, record_count, all records)
AD_FILE = "onlypassword/v1/file" ‖ h           (20 + 32 bytes)
trailer_tag = AEAD_Encrypt(K_fa, trailer_nonce, AD_FILE, empty plaintext)   (tag only, 16 bytes)
```
The trailer is `trailer_nonce ‖ trailer_tag` (40 bytes). This uses the AEAD as a MAC over
the hash, so no HMAC is needed outside TOTP. On unlock, after VK is recovered and **before
any record is decrypted**, the trailer is verified; failure is `Authentication`. Structural
problems are found earlier and are `Corrupt` (see §9).

Replacing the *entire file* with an older copy of itself that the same password and secret
key unlock is **not** detectable without external state and is out of scope
(threat-model.md T-ROLLBACK-FILE).

### 6.5 Operations and what they rewrite
| Operation | New VK? | Header | Records | Trailer |
|---|---|---|---|---|
| Add / update / delete item | no | unchanged | changed item only (new IK, nonces; revision+1 on update) | recomputed (new nonce) |
| Change master password | no | new `kdf_salt`, params, `vk_nonce`, `wrapped_vk`; `vault_id`, SK unchanged | unchanged | recomputed |
| Rotate vault key | **yes** | new `vk_nonce`, `wrapped_vk` (under the same MK, or under the new MK in the combined password-change-and-rotate operation); new `vault_id` is **not** generated | **every record re-encrypted**: new IK, new nonces, same `revision`, same plaintext | recomputed with the new `K_fa` |

Changing the master password does **not** revoke access obtained earlier: someone who knew the old password and has the secret key *and* any past copy of the header can recover `VK` (unchanged) and read every later record. After a suspected compromise of the password, the owner must also rotate the vault key; `change_master_password_and_rotate_key` does both in one atomic write (CLI `passwd --rotate`). Rotating the vault key re-encrypts every body under a fresh item key so that an attacker
holding an old VK and an old file copy learns nothing about the new file's contents that
they did not already have. Rotation does not change the secret key or the password.

### 6.6 Writing files

- **Save** (every mutation): write the complete new image to a uniquely named temporary file in the target's directory (created with `create_new`, mode 0600 on Unix), `sync_all`, `rename` over the target, fsync the directory (Unix). If the target is a symbolic link, the link is resolved first (`canonicalize`) and the temporary file is created next to, and renamed over, the *resolved* file. The temporary file is removed on any failure.
- **Create** (new vault only; an export file is written with a save and replaces an existing target): a rename would silently replace a file that appeared in the meantime, and writing the final path directly could leave a torn vault. So: write the temporary file exactly as for a save, `std::fs::hard_link(temp, target)` (fails if `target` exists, on every platform), remove the temporary file, fsync the directory. If hard links are unsupported, `create` returns `Io`; it never falls back to `rename`. A crash before the link leaves no vault at the target; a crash after it leaves the complete vault.
- **Export target**: `export` rejects (`InvalidInput`) a target that is the vault file itself, comparing canonicalized paths (the canonical parent directory joined with the file name when the target does not exist yet).

## 7. Item plaintext (schema 1)

A UTF-8 JSON object (RFC 8259) produced by serde. **Writing:** `serde_json::to_vec` of the
struct, compact (no whitespace), keys in exactly the order of the table below (and `secret,
algorithm, digits, period` inside `totp`; `name, value, hidden` inside a field), into a
`Zeroizing<Vec<u8>>` created with `with_capacity`. Strings use serde_json's default escaping.
**Reading** is two-pass: pass 1 deserializes only the `schema` key (a probe struct without
`deny_unknown_fields`; a missing, duplicate or non-integer `schema` is `Corrupt`) and returns
`UnsupportedVersion` if it is not `1` *before* any other check; pass 2 deserializes the whole
object strictly. In pass 2 every object (the item, `totp`, each `fields[]` entry) is a struct
with `#[serde(deny_unknown_fields)]`; no field uses `#[serde(default)]` or `flatten`; duplicate
keys are rejected (serde's derive rejects them for structs; `serde_json::Value` must not be
used to read items). **Every key below is required, including the nullable ones**:
`username`, `password` and `totp` may hold `null` but may not be absent. A plain
`Option<T>` field would silently accept an absent key, so those three use a
`deserialize_with` function (or a non-`Option` wrapper type) that fails on absence. Any
violation in pass 2 is `Corrupt`.

| key | type | rule |
|---|---|---|
| `schema` | integer | must be `1` |
| `kind` | string | `"login"` or `"note"` |
| `title` | string | 1..=1024 bytes |
| `created_ms`, `updated_ms` | integer | Unix time in milliseconds, `updated_ms >= created_ms` |
| `username`, `password` | string or null | `null` required when `kind` is `"note"` |
| `urls` | array of string | ≤ 64 entries, each ≤ 4096 bytes; empty when `kind` is `"note"` |
| `notes` | string | ≤ 65536 bytes (empty string allowed) |
| `totp` | object or null | `null` required when `kind` is `"note"`; else `{"secret": <canonical base32>, "algorithm": "SHA1"\|"SHA256"\|"SHA512", "digits": 6..=8, "period": 1..=300}` |
| `fields` | array | ≤ 256 entries of `{"name": string(1..=256 bytes), "value": string(≤ 65536 bytes), "hidden": bool}` |

`totp.secret` is stored **canonical**: RFC 4648 base32 alphabet `A-Z2-7`, upper case, no
padding, no spaces or `-`, whose decoded length is 10..=128 bytes (and whose unused low bits
are zero). `Item::validate` rejects (`InvalidInput`) a secret that is not already canonical;
the stored form is therefore unique. `parse_totp_secret` (user input: tolerant, REQ-TOT-003)
and `normalize_totp_secret` (returns the canonical text) are the only ways to turn user
input into a stored secret, and the CLI uses `normalize_totp_secret` before storing.

`username`, `password` ≤ 4096 bytes each. The serialized plaintext is ≤ `MAX_ITEM_PLAINTEXT`
(1 048 576 bytes). The `schema` value in the JSON must equal `item_schema` in the record
(they cannot differ unless a writer was buggy; a mismatch is `Corrupt`). Item IDs and
revisions are *not* in the plaintext; they live in the record and AD only.

## 8. Export file

Independent of the vault file: it carries no secret key, no vault key, no item keys. It is
protected by **two secrets**, like the vault: an export password and the secret key of the
vault it is read with at import time (the same secret key the exporting vault uses; a fresh
device still needs that key to unlock anything, so nothing is lost by requiring it).

```
offset size field
0      8    magic          = "OPEXPORT"                (4F 50 45 58 50 4F 52 54)
8      2    format_version = 0x0001
10     2    flags          = 0x0000
12     1    kdf_id         = 0x01
13     1    kdf_version    = 0x13
14     4    kdf_m_kib
18     4    kdf_t
22     4    kdf_p
26     16   kdf_salt       random
42     24   nonce          random
66     8    ct_len         u64, must equal file_length − 74, ≤ MAX_EXPORT_PLAINTEXT + 16
74     …    ct             AEAD ciphertext of the payload ‖ tag (16)
```
```
export_pw_key = Argon2id(UTF-8(NFKC(export_password)), kdf_salt, m, t, p, 32, 0x13)
K_x = HKDF-SHA256(salt = kdf_salt, IKM = export_pw_key ‖ SK, info = INFO_EXPORT, L = 32)
AD_X = "onlypassword/v1/export" ‖ file[0..74]
ct = AEAD_Encrypt(K_x, nonce, AD_X, payload)
```
`SK` is the 32-byte secret key passed by the caller (for the CLI: the key file of the vault
being exported). `export` cannot verify that the key belongs to the vault (the vault does not
hold it); a wrong key yields an export that only that wrong key can import — callers
should test-import. A wrong password *or* wrong key at import is the single error
`Authentication`. The export password is chosen by the user, is independent of the master
password, must satisfy §3.1 when exporting and is *not* subject to the minimum when importing.
KDF parameters follow the bounds of §10 (including the floor), so an export is never weaker
than a vault.

Payload (UTF-8 JSON, same strictness and the same two-pass reading as §7):
`{"export_schema":1,"vault_id":"<32 hex>","exported_ms":<u64>,"items":[{"id":"<32 hex lower>","revision":<u64 ≥1>,"item":<item plaintext §7>}, …]}`
Written compact in that key order. `exported_ms` is the vault clock at export time;
`vault_id` is the exporting vault's, informational only (import does not compare it with the
target). `items` sorted by `id` (byte order of the decoded IDs), ids unique, at most
100 000 entries; each embedded `item` is read with the §7 rules, so an item `schema` ≠ 1 is
`UnsupportedVersion`. Import writes the items into the target vault under their original IDs
and revisions, with fresh keys and nonces; the target vault keeps its own `vault_id`.

## 9. Version handling and errors (no downgrade)

The core supports exactly `format_version == 1`, `item_schema == 1`, `export_schema == 1`,
`kdf_id == 1`, `kdf_version == 0x13`. Any other value, smaller or larger, is an error; the
code contains no path that reads, converts or re-saves an older format. A future version 2
ships as a new spec with an explicit, owner-approved migration. Steps are performed in the
order shown and the first failing step decides the error. Steps before "derive" never run
Argon2 and never allocate more than the file's own length.

**Opening a vault file**

| # | Check | Error |
|---|---|---|
| 1 | file length ≥ 130 + 4 + 40 and ≤ 512 MiB (read with a bound) | `Corrupt` (over the bound: `LimitExceeded`) |
| 2 | magic equals `"OPVAULT"‖00` (an export file fails here) | `Corrupt` |
| 3 | `format_version` ≠ 1 | `UnsupportedVersion` |
| 4 | `flags` ≠ 0 | `Corrupt` |
| 5 | `kdf_id` ≠ 1 or `kdf_version` ≠ 0x13 | `UnsupportedVersion` |
| 6 | KDF `m`, `t`, `p` outside §10 (floor and ceiling) | `Corrupt` |
| 7 | structure: `record_count` ≤ 100 000, each `record_len` and `body_ct_len` consistent and within limits, ascending unique `item_id`, trailer at the end, no trailing bytes | `Corrupt` |
| 8 | derive MK, decrypt `wrapped_vk` (wrong password, wrong key, tampered header) | `Authentication` |
| 9 | verify the trailer, before any record is decrypted | `Authentication` |
| 10 | (on reading an item) decrypt `wrapped_ik` and `body_ct`; `item_schema` is only an AD input and is not pre-checked | `Authentication` |
| 11 | JSON pass 1 `schema` ≠ 1 | `UnsupportedVersion` |
| 12 | JSON pass 2 invalid, or `schema` ≠ record `item_schema` | `Corrupt` |

**Opening an export file**

| # | Check | Error |
|---|---|---|
| 1 | file length ≥ 74 + 16 and ≤ MAX_EXPORT_PLAINTEXT + 90 | `Corrupt` (over the bound: `LimitExceeded`) |
| 2 | magic equals `"OPEXPORT"` | `Corrupt` |
| 3 | `format_version` ≠ 1 | `UnsupportedVersion` |
| 4 | `flags` ≠ 0 | `Corrupt` |
| 5 | `kdf_id` ≠ 1 or `kdf_version` ≠ 0x13 | `UnsupportedVersion` |
| 6 | KDF bounds (§10) | `Corrupt` |
| 7 | `ct_len` ≠ file length − 74 or above the limit | `Corrupt` |
| 8 | derive `K_x`, AEAD decrypt (wrong password, wrong key, any changed byte) | `Authentication` |
| 9 | payload JSON pass 1: `export_schema` ≠ 1; then each item's `schema` ≠ 1 | `UnsupportedVersion` |
| 10 | payload JSON pass 2 invalid, IDs unsorted/duplicate, > 100 000 items, an item violating §7 | `Corrupt` |
| 11 | any ID already in the target vault | `Conflict` |
| 12 | resulting vault would exceed a §10 limit | `LimitExceeded` |

(Because `export_schema` and item schemas are inside the AEAD, they can only be seen after
step 8, and a flipped bit anywhere in the file is `Authentication`.) Every post-key failure in
a vault is the single `Authentication`; wrong password and wrong secret key are
indistinguishable.

## 10. Limits

| Limit | Value |
|---|---|
| Argon2 `m` (KiB) | 19 456 ≤ m ≤ 262 144 (default **65 536** = 64 MiB; brief ceiling for default) |
| Argon2 `t` | 2 ≤ t ≤ 16 (default **3**) |
| Argon2 `p` | 1 ≤ p ≤ 16 (default **4**) |
| `MAX_ITEM_PLAINTEXT` | 1 048 576 bytes |
| Items per vault | ≤ 100 000 |
| Vault file size | ≤ 512 MiB (536 870 912 bytes) |
| `MAX_EXPORT_PLAINTEXT` | 1 GiB (1 073 741 824 bytes) = 2 × the vault file limit |

The floor `m = 19 456 KiB (19 MiB), t = 2, p = 1` is a deliberate lower bound (well below the
default, far above test values; it is the spec's own choice, not an RFC 9106 recommendation); it applies to creation, password change, export **and** to files
being opened (§9 step 6), so no weaker vault can exist. `KdfParams::MIN` is this floor.
Parameters above the ceiling can be neither created nor accepted.

*Test seam.* Tests need faster parameters. `KdfParams::validate` lowers its floor to
`m = 8 192, t = 1, p = 1` only when compiled with `cfg(test)` (unit tests) or with the cargo
feature `insecure-fast-kdf` of `onlypassword-core` (integration tests; it is not in
`default`, and the CLI crate never enables it — the gate's `--all-features` does enable it
for the workspace test build, which is acceptable). `KdfParams::FAST_FOR_TESTS` exists only
under the same cfg. `KdfParams::validate_strict` always uses the real floor, and unit tests
assert on it (so the real bounds stay tested under `--all-features`). The CLI always uses
`DEFAULT`.

*Enforcement on mutation.* The limits are enforced when writing, not only when parsing: any
operation that would produce a vault image above 512 MiB or above 100 000 records
(`add`, `update`, `import`) returns `LimitExceeded` before writing anything. Because every
exported item costs fewer bytes in the payload (plaintext + ≈ 80 bytes of JSON framing) than
in the vault (plaintext + 142 bytes of record framing + tag), the payload of a valid vault
never exceeds the vault size, so `export` cannot exceed `MAX_EXPORT_PLAINTEXT`; it still
checks and returns `LimitExceeded`.

## 11. Known-answer tests

Vectors in `spec/vectors/` validate the primitives (not the onlypassword compositions,
for which no official vectors can exist): `argon2id.json` (RFC 9106 §5.3),
`hkdf-sha256.json` (RFC 5869 A.1–A.3), `xchacha20poly1305.json` and `hchacha20.json`
(draft-irtf-cfrg-xchacha-03 A.1 and §2.2.1), `chacha20poly1305.json` (RFC 8439 §2.8.2),
`hmac-sha2.json` (RFC 4231), `hmac-sha1.json` (RFC 2202 cases 1–4), `hotp.json` (RFC 4226
App. D), `totp.json` (RFC 6238 App. B), `base32.json` (RFC 4648 §10). The compositions in
§3, §6 and §8 are tested by round-trip, tamper and structural tests plus the **layout tests**
in architecture.md (offsets and lengths asserted against this document), and by tests that
re-derive every key and AD byte string independently with the primitive crates, so a wiring
error is caught but a systematic error shared with the crates is not.

Notes: the Argon2id vector uses the optional secret and associated-data inputs; the
production derivation uses neither, and no published Argon2id vector without them could be
fetched from the permitted hosts, so none is provided. The XChaCha20-Poly1305 vector comes
from an Internet-Draft because no RFC exists. An end-to-end composition vector (fixed inputs
→ expected file bytes) would need an independent implementation that the planning
environment does not have; it is therefore not provided, and the owner may commission one
later (OPEN-QUESTIONS #15).
