# onlypassword

A personal, cross-platform password manager. The code in this repo is written by
an agent pipeline; `pipeline/README.md` explains how it runs.

## Layout

- `spec/` — the target. `brief.md` is the owner's; everything else is produced by
  the planner and frozen once the owner approves it.
- `pipeline/` — the harness: driver, container images, gate, prompts, state.
- `crates/` — Rust code, written by generator agents.
- `agent-notes/` — hand-off notes agents leave for later sessions.

## Rules for every agent

1. **Protected paths.** Never change `spec/`, `pipeline/`, `.claude/`, `.github/`
   or `CLAUDE.md`. The one exception is the planner, which writes under `spec/`
   (but never `spec/brief.md`). The driver rejects any branch that breaks this.
2. **The spec is the authority.** If it is wrong or ambiguous, record that in
   `agent-notes/spec-issues.md` and take the closest safe reading. Never deviate
   silently and never edit the spec to match the code.
3. **Dependencies.** Direct dependencies must be listed in
   `spec/approved-deps.txt`. To ask for another crate, explain why in
   `agent-notes/dep-requests.md`; do not add it.
4. **Cryptography.** Standard primitives combined exactly as `spec/crypto-spec.md`
   says. No home-made constructions. Every crate root carries
   `#![forbid(unsafe_code)]`.
5. **Secrets.** Key material and plaintext are zeroized on drop and never appear
   in `Debug`, `Display`, logs or error messages. Parsers return errors on
   untrusted input; they never panic.
6. **Tests.** Never delete, weaken or `#[ignore]` a test to get the gate to pass.
   Known-answer tests load their vectors from `spec/vectors/`.
7. **The gate.** `bash /src/pipeline/gate.sh` (inside the agent container) must
   print `GATE PASSED` before work is committed.
8. **Real data.** No real passwords, keys or personal data in the repo, tests or
   notes.

## Git

- Pipeline agents (inside the container) commit only to the `agent/*` branch they
  were given. The driver merges into `main` after the gate and the evaluator pass.
- Override for this repo only: Agents have credentials for the remote.
- Override for this repo only: Allow auto commits, creates branches and worktrees.
