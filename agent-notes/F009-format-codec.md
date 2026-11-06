# F009 format codec
- `format::VaultFile::{parse, serialize}` with `Header`, `Record`, `Trailer`; CS §9 steps 1-7 in order.
- KDF bounds use `KdfParams::validate` (test floor under cfg(test)/insecure-fast-kdf), mapped to `Corrupt`. The real floor is covered by `validate_strict` in F006 tests plus a test here.
- Allocation is bounded: `record_count <= remaining / 146` is checked before `Vec::with_capacity`.
- `serialize` returns `Result`: `LimitExceeded` for body_ct length/size/count limits, `Corrupt` for unsorted/duplicate ids.
- Over 512 MiB input -> `LimitExceeded` (step 1); shorter than 174 -> `Corrupt`.
- Not added: header-prefix accessor; `seal` can slice the first 82 bytes of the serialized image.
