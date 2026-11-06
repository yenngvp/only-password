# F003-rng

Built `crates/onlypassword-core/src/rng.rs`: `fill_random`, `random_array::<N>()`, `uniform(n)`,
and internal `pub(crate) trait RandomSource { fn fill(&mut self, &mut [u8]) -> Result<()> }`
with a single implementation `OsSource` (getrandom::fill, errors -> `Error::Rng`). No fallback.

- `uniform_with(&mut dyn RandomSource, n)` / `random_array_with` are the `pub(crate)` injectable forms.
- `reject_sample(n, bits, draw)` is the width-generic helper (threshold = 2^bits mod n; for 64 bits
  it is `n.wrapping_neg() % n` per spec). `uniform` assembles u64 with `from_be_bytes`.
- `uniform(0)` -> `Error::InvalidInput`.
- Only dependency added: `getrandom` 0.4.3 (Cargo.lock updated).
- Tests: stub sequences for n=3, 10, 2^63+1; exhaustive 8-bit equal residue counts for n=3,10.
