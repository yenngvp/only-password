
## F008 (attempt 2)
- Over-size serialization returns `LimitExceeded`; spec/acceptance only mention InvalidInput for the size limit (on read, `InvalidInput` is used). Owner to confirm.
- `to_plaintext`/`from_plaintext` take/return `(created_ms, updated_ms)`, deviating from the architecture sketch. Owner to confirm.

## F008 (attempt 2)
- Over-size serialization returns `LimitExceeded`; spec/acceptance only mention InvalidInput for the size limit (on read, `InvalidInput` is used). Owner to confirm.
- `to_plaintext`/`from_plaintext` take/return `(created_ms, updated_ms)`, deviating from the architecture sketch. Owner to confirm.
