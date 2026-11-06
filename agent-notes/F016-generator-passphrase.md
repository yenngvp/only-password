# F016 generator-passphrase

- Added `PassphraseOptions` (+Default 7/"-"/false/false), `generate_passphrase` (OS source) and `pub(crate) generate_passphrase_with(&mut dyn RandomSource, ..)` to `generator.rs`; re-exported from lib.
- **bip39 feature set:** `bip39 = { version = "2", default-features = false }` — no features at all (no `std`, no `rand`, no language features). `Language::English.word_list()` is available with none. Resolved version 2.2.2 (see Cargo.lock); it pulls `bitcoin_hashes` only.
- Draw order: one `uniform_with(2048)` per word (2048 divides 2^64, so no rejection: one 8-byte draw each, index = draw % 2048); then, if `include_digit`, `uniform(words)` for the word and `uniform(10)` for the digit.
- Validation first: words 4..=24, separator <= 8 bytes and ASCII (empty separator allowed), else `InvalidInput`.
- Capitalize ASCII-uppercases the first byte. Words are held in `Zeroizing<String>`; the result is a `SecretString`.
- Tests use a fixed-sequence stub (`Seq`) to check exact word mapping and draw counts.
