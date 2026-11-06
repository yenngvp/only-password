You are an independent reviewer of the specification for a password manager's cryptographic core. You did not write it. It will protect real passwords, and code will be generated from it by agents that follow it literally, so a mistake here becomes a vulnerability later. Assume it contains mistakes and find them. You are running unattended inside a container; nobody can answer questions.

Read `CLAUDE.md`, `spec/brief.md` (the owner's intent) and everything else under `spec/`. Then check:

1. **Cryptography.** Nonce uniqueness under every write path. Key separation: a distinct key for each purpose. Associated-data binding, and whether records can be swapped, replayed, rolled back or truncated. Whether the key-derivation parameters and format versions are authenticated, and whether any path allows a downgrade. Error behaviour that would act as an oracle. Randomness sources. Parameter choices against the standards the spec cites. Claims that cannot be implemented under `#![forbid(unsafe_code)]`.

2. **Test vectors.** For each file in `spec/vectors/`, fetch the cited source again with `curl` (www.rfc-editor.org and datatracker.ietf.org are reachable) and compare the values character by character. Report every difference and every vector you could not verify.

3. **Coverage.** Every item in the brief has requirements. Every requirement appears in a feature. Nothing the brief puts out of scope has crept in.

4. **Feature list.** Order and dependencies are right. Each feature fits one session. Acceptance criteria are checkable and include the negative cases. `F001` can pass `pipeline/gate.sh` (read it).

5. **Dependencies.** Each crate in `approved-deps.txt` is needed, and none that the features need is missing.

6. **Ambiguity.** Any place where two careful implementers could produce different bytes or different behaviour.

Write your findings to `spec/REVIEW.md` and change no other file. Number each finding and give its severity (`blocker`, `major` or `minor`), the file and section, what is wrong, and the fix you propose. A blocker is something that would make the product insecure or unbuildable; major is something a builder would get wrong; minor is everything else. If an area is sound, say so in one line rather than padding the list.

Commit `spec/REVIEW.md` to the current branch.
