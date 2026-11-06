# F001-workspace
Virtual workspace (resolver 2) with onlypassword-core (lib; non-default features
insecure-fast-kdf, test-hooks) and onlypassword-cli (bin `onlypassword`). No dependencies.
Crate roots carry forbid(unsafe_code) and the cfg_attr(not(test), deny(...)) clippy lints.
One trivial test per crate (uses unwrap, proving the lints skip test code).
.gitignore already ignored /target/, so unchanged. Cargo.lock committed.
