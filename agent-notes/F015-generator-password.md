# F015 generator-password

- New `generator.rs`: `PasswordOptions` (+Default), `generate_password` (OS source), `pub(crate) generate_password_with(&mut dyn RandomSource, ..)`. Re-exported from lib.
- `rng.rs` gained `pub(crate) fn os_source()` so the generator can use the OS source without making `OsSource` public.
- Algorithm per architecture.md: one pick per enabled class (if `require_each`), fill from union, Fisher-Yates via `uniform_with`. Working buffer is `Zeroizing<Vec<u8>>`.
- Order of checks: length 4..=256, empty class after exclusion, no class, length < classes. The last check is unreachable with the fixed sets (min length 4 = max classes) but kept as defence. Empty-class-after-exclusion is likewise unreachable; the zero-class case is tested.
- Frequency test uses a splitmix64 stub (deterministic), 86-char union, 6% tolerance (~4.6 sd).
- Passphrase (`generate_passphrase`) is not part of this feature.
