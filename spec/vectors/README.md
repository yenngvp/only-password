# Test vectors

Official known-answer vectors, extracted mechanically (by script, not from memory) from the
cited documents on 2026-11-06. Each JSON file records `source`, `document`, `section` and the
vectors; hex strings are lower-case with no separators.

| file | document | covers |
|---|---|---|
| argon2id.json | RFC 9106 §5.3 | Argon2id (with the optional secret and associated data inputs) |
| hkdf-sha256.json | RFC 5869 App. A.1–A.3 | HKDF-SHA-256 extract and expand |
| xchacha20poly1305.json | draft-irtf-cfrg-xchacha-03 App. A.1 | XChaCha20-Poly1305 AEAD |
| hmac-sha2.json | RFC 4231 §4 (cases 1–4, 6, 7) | HMAC-SHA-256 and HMAC-SHA-512 |
| hotp.json | RFC 4226 App. D | HOTP, HMAC-SHA-1, 6 digits |
| totp.json | RFC 6238 App. B | TOTP SHA-1/256/512, 8 digits, 30 s |
| base32.json | RFC 4648 §10 | base32 encoding (with padding as published) |
| chacha20poly1305.json | RFC 8439 §2.8.2 | ChaCha20-Poly1305 (96-bit nonce = `07000000` ‖ IV), the construction under XChaCha20-Poly1305 |
| hchacha20.json | draft-irtf-cfrg-xchacha-03 §2.2.1 | HChaCha20 subkey derivation (key, 16-byte nonce → subkey; the draft prints the subkey as the byte string) |
| hmac-sha1.json | RFC 2202 §3 (cases 1–4) | HMAC-SHA-1 (cases 5–7 omitted) |

Not available as an official source reachable from the planning environment, so **not
provided** (no values were invented): standalone SHA-1/SHA-256 vectors (covered indirectly
by HKDF, HMAC and TOTP vectors), an Argon2id vector without the optional secret and associated data (none could be fetched from the permitted hosts), and any vector for the onlypassword compositions
(CS §3, §6, §8), which are tested by round-trip, tamper and layout tests.

Notes on individual files:
- `totp.json`: the RFC 6238 Appendix B prose names only the 20-byte seed; the SHA-256 and
  SHA-512 rows use the longer seeds from the reference implementation in Appendix A of the
  same RFC (32 and 64 bytes of repeating "1234567890"). `secret_hex` records the seed used.
- `hmac-sha2.json`: RFC 4231 test case 5 (truncated output) is omitted on purpose.
- `hkdf-sha256.json`: an empty hex string is a zero-length octet string.
