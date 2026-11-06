# The agent pipeline

This harness lets Claude agents build onlypassword unattended, inside a boundary
that is enforced by the machine instead of by instructions.

- **The target** is `spec/`. You write `spec/brief.md`; a planner agent expands it
  into requirements, a threat model, a crypto spec, an architecture, test vectors,
  an approved dependency list and a feature list. You approve it once, and from
  then on it is frozen.
- **The boundary** is the container, the network allowlist, the protected paths
  and the gate. Agents cannot change any of them.
- **Everything in between** is the agents' to decide.

## One-time setup

```sh
claude setup-token                                   # prints a long-lived token
mkdir -p ~/.config/onlypassword && chmod 700 ~/.config/onlypassword
printf 'CLAUDE_CODE_OAUTH_TOKEN=%s\n' '<the token>' > ~/.config/onlypassword/agent.env
chmod 600 ~/.config/onlypassword/agent.env

pipeline/run.py doctor --live                        # builds images, checks the boundary
```

## Running it

```sh
pipeline/run.py plan            # planner -> critic -> revise; result on branch agent/spec
pipeline/run.py plan --feedback notes.txt            # ask for changes, as often as needed
pipeline/run.py approve-spec    # your gate: merges the spec into main and freezes it
pipeline/run.py build           # builds features in order until done, blocked or over budget
pipeline/run.py status
```

`build` can be stopped and started again at any time; it picks up at the first
feature that has not passed. A feature that fails `max_attempts` times is marked
blocked and the run stops, with the work kept on its `agent/<feature>` branch.
After looking at it: `pipeline/run.py build --retry --note "what to do differently"`.

## What happens to one feature

1. **Generator** (container, has the Claude login): works in a private clone on
   branch `agent/<feature>`, writes tests and code, commits.
2. **Driver** (host): imports the commits as a git bundle, then checks mechanically
   that no protected path, symlink or submodule was touched.
3. **Gate** (container, no login): approved dependencies only, `cargo-deny`,
   `#![forbid(unsafe_code)]`, no ignored tests, `fmt`, `clippy`, tests.
4. **Evaluator** (container, fresh context): reads the diff against the spec and
   writes a verdict. Any blocker or major finding sends the feature back.
5. **Driver**: merges into `main` and records the result in `state/`.

Failures at steps 2 to 4 are fed back to the generator for the next attempt.

## The boundary

| Control | How it is enforced |
|---|---|
| Agents cannot touch your files | The repo is mounted read-only; agents work in a clone inside a disposable container and return commits as a bundle. The host never runs agent-written code. |
| Network | Containers sit on an internal Docker network. The only way out is a proxy that forwards to the hosts in `proxy/allowlist`. Every connection is logged per run. |
| Web access | Claude Code's web search and web fetch tools are switched off for agents. |
| No remote access | Containers hold no SSH keys or GitHub tokens. The driver never pushes. |
| Protected paths | `spec/`, `pipeline/`, `.claude/`, `.github/`, `CLAUDE.md`. A branch that changes one is rejected before the gate runs. |
| Dependencies | Direct dependencies must be in `spec/approved-deps.txt`, which is part of the spec you approve. `deny.toml` restricts sources to crates.io and checks advisories and licenses. |
| Self-grading | Feature status lives in `state/status.json`, written only by the driver. |
| Spend | A dollar budget and a time limit per session, an attempt limit per feature, and a ceiling per `build` run, all in `config.toml`. |

Known limits: the login token is visible to the agent inside its own container;
the advisory database is a snapshot taken when the image was built
(`pipeline/run.py build-images` refreshes it); the evaluator is another agent,
not an audit.

## Files

- `run.py`: the driver. `config.toml`: budgets, limits, model per role.
- `Dockerfile`, `proxy/`: the two images. `deny.toml`: supply-chain policy.
- `gate.sh`: the gate. `container/`: scripts that run inside containers.
- `prompts/`: what each agent is told.
- `state/`: `status.json`, `spec.lock.json`, `PROGRESS.md`, committed by the driver.
- `../.pipeline/runs/`: per-session logs, transcripts and proxy logs (not committed).
