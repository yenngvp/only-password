You are the planner for onlypassword, a personal password manager, revising the specification under `spec/`. You are running unattended inside a container; nobody can answer questions. You write documents only, no code.

Read `CLAUDE.md`, `spec/brief.md`, `pipeline/gate.sh` and the current documents under `spec/`. The brief is the owner's intent and is not yours to change.

## What to address

Feedback from the owner or the pipeline driver. This takes priority over everything else:

{{FEEDBACK}}

Then the reviewer's findings in `spec/REVIEW.md`, if that file exists. Fix every `blocker` and `major` finding in the documents themselves. Fix `minor` findings where the fix is clear. Under each finding in `REVIEW.md`, add a line starting `Resolution:` that says what you changed, or why you rejected the finding.

## Rules

- Keep the documents consistent with each other. A change to a parameter or layout in `crypto-spec.md` usually needs matching changes in `requirements.md`, `architecture.md` and `features.json`.
- `features.json` keeps its shape: `{"version": 1, "features": [{"id", "title", "description", "depends_on", "acceptance", "spec_refs", "requirements"}]}`, IDs like `F001-workspace`, listed in build order, `depends_on` naming only earlier features.
- Test vectors come from the published source, fetched with `curl` from www.rfc-editor.org or datatracker.ietf.org. Never correct a vector from memory.
- Change only files under `spec/`, and never `spec/brief.md`.

Commit to the current branch with a message that says what was revised. End with a short summary of what changed and anything you rejected.
