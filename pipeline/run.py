#!/usr/bin/env python3
"""Driver for the onlypassword agent pipeline.

Runs on the host, standard library only. It never executes agent-written code
on the host: agents and the gate run in containers, and their work comes back
as git bundles that are checked before anything is merged.

    pipeline/run.py doctor [--live]     check the setup and the boundary
    pipeline/run.py plan                planner -> critic -> revise, on agent/spec
    pipeline/run.py plan --feedback F   revise the spec again with your notes
    pipeline/run.py approve-spec        merge agent/spec into main and freeze it
    pipeline/run.py build               build features until done, blocked or over budget
    pipeline/run.py status              show where things stand
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIPE = ROOT / "pipeline"
STATE = PIPE / "state"
RUNTIME = ROOT / ".pipeline"
STATUS_FILE = STATE / "status.json"
LOCK_FILE = STATE / "spec.lock.json"
PROGRESS_FILE = STATE / "PROGRESS.md"
CFG = tomllib.loads((PIPE / "config.toml").read_text())

AGENT_IMAGE = os.environ.get("ONLYPASSWORD_AGENT_IMAGE", "onlypassword-agent:latest")
PROXY_IMAGE = "onlypassword-proxy:latest"
NETWORK = "onlypassword-agents"
PROXY_NAME = "onlypassword-proxy"
PROXY_URL = f"http://{PROXY_NAME}:8888"
ENV_FILE = Path(
    os.environ.get("ONLYPASSWORD_AGENT_ENV", "~/.config/onlypassword/agent.env")
).expanduser()

SPEC_BRANCH = "agent/spec"
SPEC_REQUIRED = (
    "requirements.md",
    "threat-model.md",
    "crypto-spec.md",
    "architecture.md",
    "approved-deps.txt",
    "features.json",
)
# Paths no build-stage agent may change.
PROTECTED = ("spec/", "pipeline/", ".claude/", ".github/", "CLAUDE.md")
FEATURE_ID = re.compile(r"^F\d{3}-[a-z0-9]+(-[a-z0-9]+)*$")
IDENT = ["-c", "user.name=onlypassword-pipeline", "-c", "user.email=pipeline@onlypassword.invalid"]

_running_container: str | None = None


class Fail(Exception):
    """A condition the owner has to look at. Printed without a traceback."""


def log(msg: str) -> None:
    print(f"[{dt.datetime.now():%H:%M:%S}] {msg}", flush=True)


# --------------------------------------------------------------------------
# processes and git


def run(cmd, *, check=True, capture=False, **kw) -> subprocess.CompletedProcess:
    if capture:
        kw.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc = subprocess.run([str(c) for c in cmd], cwd=ROOT, text=True, **kw)
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip() if capture else ""
        raise Fail(f"command failed ({proc.returncode}): {' '.join(map(str, cmd))}\n{detail}")
    return proc


def git(*args: str) -> str:
    return run(["git", *args], capture=True).stdout.strip()


def git_ok(*args: str) -> bool:
    return run(["git", *args], capture=True, check=False).returncode == 0


def branch_tip(branch: str) -> str | None:
    proc = run(["git", "rev-parse", "-q", "--verify", f"refs/heads/{branch}"], capture=True, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else None


def require_repo() -> None:
    if not git_ok("rev-parse", "-q", "--verify", "HEAD"):
        raise Fail(
            "This repository has no commits yet. Review the harness, then make the first\n"
            "commit yourself:  git add -A && git commit -m 'Add agent pipeline harness'"
        )
    if git("rev-parse", "--abbrev-ref", "HEAD") != "main":
        raise Fail("The host checkout must be on 'main'; the driver merges agent branches into it.")
    dirty = [
        line
        for line in git("status", "--porcelain", "--untracked-files=no").splitlines()
        if not line[3:].startswith("pipeline/state/")
    ]
    if dirty:
        raise Fail(
            "Tracked files have uncommitted changes. Agents only see committed work, so\n"
            "commit or discard these first:\n  " + "\n  ".join(dirty)
        )


def commit_state(message: str) -> None:
    run(["git", "add", "--", "pipeline/state"])
    if not git_ok("diff", "--cached", "--quiet", "--", "pipeline/state"):
        run(["git", *IDENT, "commit", "-q", "-m", message, "--", "pipeline/state"])


def merge_branch(branch: str, message: str) -> None:
    proc = run(["git", *IDENT, "merge", "--no-ff", "-q", "-m", message, branch], capture=True, check=False)
    if proc.returncode != 0:
        run(["git", "merge", "--abort"], capture=True, check=False)
        raise Fail(f"could not merge {branch} into main:\n{proc.stderr.strip() or proc.stdout.strip()}")


# --------------------------------------------------------------------------
# status


def load_status() -> dict:
    if STATUS_FILE.exists():
        return json.loads(STATUS_FILE.read_text())
    return {"spec": {}, "features": {}, "total_cost_usd": 0.0}


def save_status(status: dict) -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    STATUS_FILE.write_text(json.dumps(status, indent=2) + "\n")


def add_cost(status: dict, bucket: dict, cost: float) -> None:
    bucket["cost_usd"] = round(bucket.get("cost_usd", 0.0) + cost, 4)
    status["total_cost_usd"] = round(status.get("total_cost_usd", 0.0) + cost, 4)


# --------------------------------------------------------------------------
# docker


def docker_ok(*args: str) -> bool:
    return run(["docker", *args], capture=True, check=False).returncode == 0


def build_images(force: bool = False) -> None:
    if force or not docker_ok("image", "inspect", PROXY_IMAGE):
        log("building the proxy image")
        run(["docker", "build", "-q", "-t", PROXY_IMAGE, PIPE / "proxy"])
    if force or not docker_ok("image", "inspect", AGENT_IMAGE):
        log("building the agent image (a few minutes the first time)")
        run(["docker", "build", "-t", AGENT_IMAGE,
             "--build-arg", f"UID={os.getuid()}", "--build-arg", f"GID={os.getgid()}",
             "-f", PIPE / "Dockerfile", PIPE])


def ensure_infra(*, restart_proxy: bool = False) -> None:
    if not docker_ok("version"):
        raise Fail("Docker is not available to this user.")
    build_images()
    if not docker_ok("network", "inspect", NETWORK):
        run(["docker", "network", "create", "--internal", NETWORK], capture=True)
    state = run(["docker", "inspect", "-f", "{{.State.Running}}", PROXY_NAME], capture=True, check=False)
    if state.returncode == 0 and state.stdout.strip() == "true" and not restart_proxy:
        return
    run(["docker", "rm", "-f", PROXY_NAME], capture=True, check=False)
    run(["docker", "run", "-d", "--name", PROXY_NAME, "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges", PROXY_IMAGE], capture=True)
    run(["docker", "network", "connect", NETWORK, PROXY_NAME], capture=True)


def require_auth() -> None:
    if not ENV_FILE.exists():
        raise Fail(
            f"No agent login found at {ENV_FILE}. Create it once:\n"
            "  claude setup-token        # prints a long-lived token\n"
            f"  mkdir -p {ENV_FILE.parent} && chmod 700 {ENV_FILE.parent}\n"
            f"  printf 'CLAUDE_CODE_OAUTH_TOKEN=%s\\n' '<the token>' > {ENV_FILE}\n"
            f"  chmod 600 {ENV_FILE}"
        )
    if ENV_FILE.stat().st_mode & 0o077:
        raise Fail(f"{ENV_FILE} is readable by other users; run: chmod 600 {ENV_FILE}")


def new_run(label: str) -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = RUNTIME / "runs" / f"{stamp}-{label.replace('/', '_')}"
    (run_dir / "in").mkdir(parents=True)
    (run_dir / "out").mkdir()
    # The container user must be able to write here however Docker maps ownership.
    (run_dir / "out").chmod(0o777)
    return run_dir


def container(run_dir: Path, script: str, env: dict, *, auth: bool, timeout_min: int) -> int:
    """Run one pipeline container to completion. Output goes to <run_dir>/container.log."""
    global _running_container
    name = f"onlypassword-{run_dir.name}"
    limits = CFG["container"]
    cmd = ["docker", "run", "--rm", "--name", name, "--network", NETWORK,
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
           "--memory", limits["memory"], "--cpus", str(limits["cpus"]),
           "--pids-limit", str(limits["pids"]),
           "-v", f"{ROOT}:/src:ro", "-v", f"{run_dir / 'in'}:/in:ro", "-v", f"{run_dir / 'out'}:/out"]
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        cmd += ["-e", f"{key}={PROXY_URL}"]
    if auth:
        cmd += ["--env-file", str(ENV_FILE)]
    for key, value in env.items():
        cmd += ["-e", f"{key}={value}"]
    cmd += [AGENT_IMAGE, "bash", f"/src/pipeline/container/{script}"]

    started = dt.datetime.now(dt.timezone.utc).isoformat()
    _running_container = name
    try:
        with open(run_dir / "container.log", "w") as out:
            try:
                rc = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT,
                                    timeout=timeout_min * 60 + 120).returncode
            except subprocess.TimeoutExpired:
                run(["docker", "kill", name], capture=True, check=False)
                rc = 124
    finally:
        _running_container = None
    proxy = run(["docker", "logs", "--since", started, PROXY_NAME], capture=True, check=False)
    (run_dir / "proxy.log").write_text((proxy.stdout or "") + (proxy.stderr or ""))
    return rc


def refused_hosts(run_dir: Path) -> list[str]:
    path = run_dir / "proxy.log"
    if not path.exists():
        return []
    hosts = re.findall(r'refused on filtered (?:domain|url) "([^"]+)"', path.read_text(errors="replace"))
    return sorted(set(hosts))


# --------------------------------------------------------------------------
# agent sessions


def render(template: str, **values) -> str:
    text = (PIPE / "prompts" / template).read_text()
    for key, value in values.items():
        text = text.replace("{{" + key + "}}", str(value))
    return text


def agent_session(role: str, branch: str, prompt: str) -> dict:
    cfg = CFG[role]
    run_dir = new_run(f"{role}-{branch}")
    (run_dir / "in" / "prompt.md").write_text(prompt)
    env = {"ROLE": role, "BRANCH": branch, "BASE": "main",
           "BUDGET_USD": cfg["budget_usd"], "TIMEOUT_MIN": cfg["timeout_min"],
           "MODEL": cfg.get("model", ""), "EFFORT": cfg.get("effort", "")}
    log(f"{role}: session started on {branch} (budget ${cfg['budget_usd']}, {cfg['timeout_min']} min)")
    rc = container(run_dir, "agent-entry.sh", env, auth=True, timeout_min=cfg["timeout_min"])

    info = {"run": str(run_dir.relative_to(ROOT)), "dir": run_dir, "rc": rc,
            "cost_usd": 0.0, "turns": 0, "ended": "no result recorded"}
    transcript = run_dir / "out" / "claude.jsonl"
    if transcript.exists():
        for line in transcript.read_text(errors="replace").splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if isinstance(event, dict) and event.get("type") == "result":
                info["cost_usd"] = float(event.get("total_cost_usd") or 0.0)
                info["turns"] = int(event.get("num_turns") or 0)
                info["ended"] = str(event.get("subtype") or "")
    refused = refused_hosts(run_dir)
    log(f"{role}: finished ({info['ended']}, {info['turns']} turns, ${info['cost_usd']:.2f})"
        + (f"; proxy refused: {', '.join(refused)}" if refused else ""))
    return info


def import_branch(session: dict, branch: str) -> str | None:
    """Fetch the session's commits into the host repo. Returns a problem, or None."""
    before = branch_tip(branch)
    bundle = session["dir"] / "out" / "result.bundle"
    if not bundle.exists():
        return (f"The session ended without any new commit on {branch} "
                f"(session result: {session['ended']}). Work must be committed to that branch.")
    if not git_ok("bundle", "verify", "-q", str(bundle)):
        return "The session's git bundle did not verify against the host repository."
    proc = run(["git", "fetch", "-q", str(bundle), f"refs/heads/{branch}:refs/heads/{branch}"],
               capture=True, check=False)
    if proc.returncode != 0:
        return (f"{branch} could not be updated from the session's commits; existing history on the "
                f"branch must be kept, not rewritten. ({proc.stderr.strip()})")
    if branch_tip(branch) == before:
        return f"The session added no new commits to {branch}."
    return None


def boundary_violations(branch: str, *, allowed=None) -> list[str]:
    """Mechanical checks on what a branch changed relative to main."""
    problems = []
    if not git_ok("merge-base", "--is-ancestor", "main", branch):
        problems.append(f"{branch} is not built on top of main (merge origin/main into it; do not rebase)")
    raw = run(["git", "diff", "--raw", "--no-renames", "-z", f"main...{branch}"], capture=True).stdout
    fields = raw.split("\0")
    for meta, path in zip(fields[0::2], fields[1::2]):
        mode = meta.split()[1]
        if mode in ("120000", "160000"):
            problems.append(f"{path}: symlinks and submodules are not allowed")
        if allowed is not None:
            if not allowed(path):
                problems.append(f"{path}: outside what this stage may change")
        elif any(path == p or path.startswith(p) for p in PROTECTED):
            problems.append(f"{path}: protected path")
    return problems


# --------------------------------------------------------------------------
# spec


def spec_allowed(path: str) -> bool:
    return path.startswith("spec/") and path != "spec/brief.md"


def read_at(ref: str, path: str) -> str | None:
    proc = run(["git", "show", f"{ref}:{path}"], capture=True, check=False)
    return proc.stdout if proc.returncode == 0 else None


def spec_problems(ref: str) -> list[str]:
    problems = [f"spec/{name} is missing" for name in SPEC_REQUIRED if read_at(ref, f"spec/{name}") is None]
    raw = read_at(ref, "spec/features.json")
    if raw is None:
        return problems
    try:
        features = json.loads(raw)["features"]
        assert isinstance(features, list) and features
    except Exception:
        return problems + ['spec/features.json must be {"version": 1, "features": [...]} with at least one feature']
    seen: set[str] = set()
    for index, feature in enumerate(features):
        fid = feature.get("id") if isinstance(feature, dict) else None
        where = f"features[{index}] ({fid})"
        if not isinstance(fid, str) or not FEATURE_ID.match(fid):
            problems.append(f"{where}: id must look like F001-short-slug")
            continue
        if fid in seen:
            problems.append(f"{where}: duplicate id")
        for key in ("title", "description"):
            if not isinstance(feature.get(key), str) or not feature[key].strip():
                problems.append(f"{where}: '{key}' must be a non-empty string")
        acceptance = feature.get("acceptance")
        if not isinstance(acceptance, list) or not acceptance or not all(isinstance(a, str) for a in acceptance):
            problems.append(f"{where}: 'acceptance' must be a non-empty list of strings")
        deps = feature.get("depends_on", [])
        if not isinstance(deps, list):
            problems.append(f"{where}: 'depends_on' must be a list")
        else:
            problems += [f"{where}: depends on '{d}', which is not an earlier feature" for d in deps if d not in seen]
        seen.add(fid)
    return problems


def load_features() -> list[dict]:
    return json.loads(read_at("main", "spec/features.json") or '{"features": []}')["features"]


def spec_tree() -> str | None:
    proc = run(["git", "rev-parse", "-q", "--verify", "main:spec"], capture=True, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else None


def require_spec_lock() -> None:
    if not LOCK_FILE.exists():
        raise Fail("The spec has not been approved yet. Run: pipeline/run.py approve-spec")
    if json.loads(LOCK_FILE.read_text()).get("spec_tree") != spec_tree():
        raise Fail("spec/ on main differs from the approved version. If the change is yours and\n"
                   "intended, run 'pipeline/run.py approve-spec' again to re-approve it.")


def cmd_plan(args) -> None:
    require_repo()
    require_auth()
    if read_at("main", "spec/brief.md") is None:
        raise Fail("spec/brief.md must be committed on main before planning.")
    ensure_infra()
    status = load_status()
    spec = status.setdefault("spec", {})
    exists = branch_tip(SPEC_BRANCH) is not None

    if args.feedback:
        if not exists:
            raise Fail(f"There is no {SPEC_BRANCH} branch to revise. Run 'plan' without --feedback first.")
        steps = [("planner", "revise.md", Path(args.feedback).read_text())]
    else:
        if exists and not args.restart:
            raise Fail(f"{SPEC_BRANCH} already exists. Use --feedback FILE to revise it, or --restart to plan again.")
        if exists:
            old = f"{SPEC_BRANCH}-old-{dt.datetime.now():%Y%m%d-%H%M%S}"
            git("branch", "-m", SPEC_BRANCH, old)
            log(f"kept the previous attempt as {old}")
        steps = [("planner", "planner.md", ""), ("critic", "critic.md", ""),
                 ("planner", "revise.md", "None. Work from the reviewer's findings.")]

    def step(role: str, template: str, feedback: str) -> None:
        session = agent_session(role, SPEC_BRANCH, render(template, FEEDBACK=feedback))
        add_cost(status, spec, session["cost_usd"])
        save_status(status)
        problem = import_branch(session, SPEC_BRANCH)
        if problem:
            raise Fail(f"{role} step failed: {problem}\nSee {session['run']}/")
        violations = boundary_violations(SPEC_BRANCH, allowed=spec_allowed)
        if violations:
            raise Fail(f"{role} changed files outside spec/ (branch kept, not merged):\n  " + "\n  ".join(violations))

    for role, template, feedback in steps:
        step(role, template, feedback)
    problems = spec_problems(SPEC_BRANCH)
    if problems:
        log("the spec does not validate; asking the planner to fix it once")
        step("planner", "revise.md", "The pipeline driver rejected the spec for these reasons:\n- " + "\n- ".join(problems))
        problems = spec_problems(SPEC_BRANCH)
    if problems:
        raise Fail("The spec still does not validate:\n  " + "\n  ".join(problems))

    count = len(json.loads(read_at(SPEC_BRANCH, "spec/features.json"))["features"])
    print(f"""
The spec is ready for your review on branch {SPEC_BRANCH} ({count} features, ${spec.get('cost_usd', 0):.2f} so far).

  git diff --stat main {SPEC_BRANCH}
  git show {SPEC_BRANCH}:spec/OPEN-QUESTIONS.md
  git show {SPEC_BRANCH}:spec/crypto-spec.md
  git show {SPEC_BRANCH}:spec/REVIEW.md

To change something:  pipeline/run.py plan --feedback notes.txt
To accept it:         pipeline/run.py approve-spec
""")


def cmd_approve_spec(_args) -> None:
    require_repo()
    status = load_status()
    pending = branch_tip(SPEC_BRANCH) is not None and not git_ok("merge-base", "--is-ancestor", SPEC_BRANCH, "main")
    if pending:
        violations = boundary_violations(SPEC_BRANCH, allowed=spec_allowed)
        problems = violations + spec_problems(SPEC_BRANCH)
        if problems:
            raise Fail("The spec branch cannot be approved:\n  " + "\n  ".join(problems))
        merge_branch(SPEC_BRANCH, "pipeline: merge approved spec")
        log(f"merged {SPEC_BRANCH} into main")
    problems = spec_problems("main")
    if problems:
        raise Fail("There is no valid spec on main to approve:\n  " + "\n  ".join(problems))
    STATE.mkdir(parents=True, exist_ok=True)
    LOCK_FILE.write_text(json.dumps({"spec_tree": spec_tree(), "commit": git("rev-parse", "main"),
                                     "approved_at": dt.datetime.now().isoformat(timespec="seconds")}, indent=2) + "\n")
    if not PROGRESS_FILE.exists():
        PROGRESS_FILE.write_text("# Progress\n\nWritten by the pipeline driver. One entry per feature that reached main.\n")
    status.setdefault("spec", {})["approved"] = True
    save_status(status)
    commit_state("pipeline: lock approved spec")
    log("spec approved and frozen. Next: pipeline/run.py build")


# --------------------------------------------------------------------------
# build


def run_gate(branch: str) -> tuple[bool, Path]:
    run_dir = new_run(f"gate-{branch}")
    log(f"gate: checking {branch}")
    rc = container(run_dir, "gate-entry.sh", {"BRANCH": branch}, auth=False,
                   timeout_min=CFG["gate"]["timeout_min"])
    log("gate: passed" if rc == 0 else f"gate: FAILED (exit {rc})")
    return rc == 0, run_dir / "container.log"


def tail(path: Path, lines: int) -> str:
    return "\n".join(path.read_text(errors="replace").splitlines()[-lines:])


def read_verdict(session: dict) -> dict | None:
    try:
        verdict = json.loads((session["dir"] / "out" / "verdict.json").read_text())
        assert verdict["verdict"] in ("pass", "fail") and isinstance(verdict.get("findings", []), list)
        return verdict
    except Exception:
        return None


def verdict_feedback(verdict: dict) -> str:
    lines = ["The evaluator rejected the change.", "", verdict.get("summary", ""), ""]
    for item in verdict.get("criteria", []):
        if isinstance(item, dict) and not item.get("met", True):
            lines.append(f"- criterion not met: {item.get('criterion')} ({item.get('evidence', '')})")
    for finding in verdict.get("findings", []):
        if isinstance(finding, dict):
            lines.append(f"- [{finding.get('severity')}] {finding.get('location')}: "
                         f"{finding.get('problem')} Fix: {finding.get('fix')}")
    return "\n".join(lines)


def attempt_feature(feature: dict, entry: dict, status: dict, feedback: str) -> tuple[str, str]:
    """One generator attempt and its checks. Returns (outcome, feedback for the next attempt)."""
    fid, branch = feature["id"], f"agent/{feature['id']}"
    feature_json = json.dumps(feature, indent=2)
    prompt = render("generator.md", FEATURE_ID=fid, FEATURE_JSON=feature_json,
                    ATTEMPT=entry["attempts"], MAX_ATTEMPTS=CFG["limits"]["max_attempts"],
                    FEEDBACK=feedback or "None. This is the first attempt.")
    session = agent_session("generator", branch, prompt)
    add_cost(status, entry, session["cost_usd"])
    record = {"attempt": entry["attempts"], "generator_run": session["run"]}
    entry["history"].append(record)

    def done(outcome: str, text: str = "") -> tuple[str, str]:
        record["outcome"] = outcome
        save_status(status)
        return outcome, text

    problem = import_branch(session, branch)
    if problem:
        return done("no_commits", problem)

    violations = boundary_violations(branch)
    if violations:
        return done("boundary_violation",
                    "The driver rejected the branch because it breaks the boundary rules:\n- "
                    + "\n- ".join(violations)
                    + "\nUndo those changes on this branch (for a file that exists on main: "
                      "`git checkout origin/main -- <path>`; for a new file: `git rm`), then commit.")

    passed, gate_log = run_gate(branch)
    record["gate_log"] = str(gate_log.relative_to(ROOT))
    if not passed:
        return done("gate_failed",
                    "The gate failed on your branch in a clean container. The end of its output:\n\n"
                    + tail(gate_log, 120))

    verdict = None
    for _ in range(2):  # one retry if the evaluator leaves no usable verdict
        review = agent_session("evaluator", branch, render("evaluator.md", FEATURE_JSON=feature_json))
        add_cost(status, entry, review["cost_usd"])
        record["evaluator_run"] = review["run"]
        verdict = read_verdict(review)
        if verdict:
            break
    if not verdict:
        return done("evaluator_error", feedback)
    blocking = [f for f in verdict.get("findings", [])
                if isinstance(f, dict) and f.get("severity") in ("blocker", "major")]
    record["evaluator_summary"] = verdict.get("summary", "")
    if verdict["verdict"] != "pass" or blocking:
        return done("evaluator_rejected", verdict_feedback(verdict))
    return done("passed")


def build_feature(feature: dict, status: dict) -> bool:
    fid, branch = feature["id"], f"agent/{feature['id']}"
    entry = status["features"].setdefault(fid, {"status": "pending", "attempts": 0, "cost_usd": 0.0, "history": []})
    entry["status"] = "in_progress"
    feedback = entry.pop("pending_feedback", "")
    limit = CFG["limits"]["max_attempts"]
    log(f"=== {fid}: {feature['title']} ===")

    while entry["attempts"] < limit:
        entry["attempts"] += 1
        save_status(status)
        outcome, feedback = attempt_feature(feature, entry, status, feedback)
        log(f"{fid}: attempt {entry['attempts']}/{limit} -> {outcome}")
        if outcome == "passed":
            merge_branch(branch, f"pipeline: merge {fid} ({feature['title']})")
            entry["status"] = "passed"
            save_status(status)
            summary = entry["history"][-1].get("evaluator_summary", "").strip()
            with open(PROGRESS_FILE, "a") as progress:
                progress.write(f"\n## {fid}: {feature['title']}\n\n"
                               f"Merged {dt.date.today()} after {entry['attempts']} attempt(s), "
                               f"${entry['cost_usd']:.2f}. Evaluator: {summary}\n")
            commit_state(f"pipeline: {fid} passed")
            return True

    entry["status"] = "blocked"
    entry["pending_feedback"] = feedback
    save_status(status)
    commit_state(f"pipeline: {fid} blocked after {limit} attempts")
    log(f"{fid}: BLOCKED. The work so far is on branch {branch}; the last problem was:\n{feedback}")
    return False


def next_feature(features: list[dict], status: dict) -> dict | None:
    done = {fid for fid, entry in status["features"].items() if entry.get("status") == "passed"}
    for feature in features:
        if feature["id"] not in done:
            return feature
    return None


def cmd_build(args) -> None:
    require_repo()
    require_spec_lock()
    require_auth()
    ensure_infra()
    features = load_features()
    status = load_status()
    start_cost = status.get("total_cost_usd", 0.0)
    built = 0

    while True:
        feature = next_feature(features, status)
        if feature is None:
            log("every feature has passed. The pilot is complete.")
            return
        entry = status["features"].get(feature["id"], {})
        if entry.get("status") == "blocked":
            if not args.retry:
                raise Fail(f"{feature['id']} is blocked. Look at branch agent/{feature['id']} and the notes in\n"
                           "agent-notes/, then run 'pipeline/run.py build --retry' (add --note 'guidance' to steer it).")
            entry["attempts"] = 0
            args.retry = False
        if args.note:
            entry = status["features"].setdefault(feature["id"], {"status": "pending", "attempts": 0,
                                                                  "cost_usd": 0.0, "history": []})
            entry["pending_feedback"] = (entry.get("pending_feedback", "") + "\n\nGuidance from the owner:\n" + args.note).strip()
            args.note = None
        spent = status.get("total_cost_usd", 0.0) - start_cost
        if spent >= CFG["limits"]["max_run_usd"]:
            log(f"stopping: this run has spent ${spent:.2f}, at or over the ${CFG['limits']['max_run_usd']} limit")
            return
        if args.max_features and built >= args.max_features:
            log(f"stopping after {built} feature(s), as requested")
            return
        if not build_feature(feature, status):
            sys.exit(2)
        built += 1


# --------------------------------------------------------------------------
# status, gate, doctor


def cmd_status(_args) -> None:
    status = load_status()
    locked = LOCK_FILE.exists() and json.loads(LOCK_FILE.read_text()).get("spec_tree") == spec_tree()
    pending = branch_tip(SPEC_BRANCH) is not None and not git_ok("merge-base", "--is-ancestor", SPEC_BRANCH, "main")
    print("spec:     " + ("approved and frozen" if locked else
                          f"waiting for your review on {SPEC_BRANCH}" if pending else "not planned yet"))
    features = load_features() if locked else []
    for feature in features:
        entry = status["features"].get(feature["id"], {})
        print(f"  {entry.get('status', 'pending'):<12} {feature['id']:<28} attempts={entry.get('attempts', 0)} "
              f"${entry.get('cost_usd', 0.0):.2f}  {feature['title']}")
    passed = sum(1 for f in features if status["features"].get(f["id"], {}).get("status") == "passed")
    if features:
        print(f"features: {passed}/{len(features)} passed")
    print(f"spent:    ${status.get('total_cost_usd', 0.0):.2f}")


def cmd_gate(args) -> None:
    require_repo()
    ensure_infra()
    passed, gate_log = run_gate(args.branch)
    print(tail(gate_log, 40))
    sys.exit(0 if passed else 1)


def cmd_doctor(args) -> None:
    ensure_infra(restart_proxy=True)
    log("images, network and proxy are up")
    if args.live:
        require_auth()
    run_dir = new_run("doctor")
    rc = container(run_dir, "smoke.sh", {"LIVE": "1" if args.live else "0"}, auth=args.live, timeout_min=5)
    print((run_dir / "container.log").read_text().rstrip())
    refused = refused_hosts(run_dir)
    if refused:
        print("proxy refused: " + ", ".join(refused))
    print("login:    " + (f"found at {ENV_FILE}" if ENV_FILE.exists() else f"missing ({ENV_FILE})"))
    print("repo:     " + ("has commits" if git_ok("rev-parse", "-q", "--verify", "HEAD") else "no commits yet"))
    sys.exit(rc)


def cmd_build_images(_args) -> None:
    build_images(force=True)
    ensure_infra(restart_proxy=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="onlypassword agent pipeline")
    sub = parser.add_subparsers(dest="command", required=True)
    doctor = sub.add_parser("doctor", help="check the setup and that the container boundary holds")
    doctor.add_argument("--live", action="store_true", help="also make one small Claude call from the container")
    doctor.set_defaults(func=cmd_doctor)
    sub.add_parser("build-images", help="rebuild the images (refreshes the advisory database)").set_defaults(func=cmd_build_images)
    plan = sub.add_parser("plan", help="produce the spec on agent/spec for your review")
    plan.add_argument("--feedback", metavar="FILE", help="revise the existing spec using your notes in FILE")
    plan.add_argument("--restart", action="store_true", help="set the existing spec branch aside and plan again")
    plan.set_defaults(func=cmd_plan)
    sub.add_parser("approve-spec", help="merge agent/spec into main and freeze the spec").set_defaults(func=cmd_approve_spec)
    build = sub.add_parser("build", help="build features in order")
    build.add_argument("--max-features", type=int, default=0, help="stop after this many features")
    build.add_argument("--retry", action="store_true", help="give a blocked feature a fresh set of attempts")
    build.add_argument("--note", help="guidance passed to the generator for the next feature")
    build.set_defaults(func=cmd_build)
    sub.add_parser("status", help="show spec and feature status").set_defaults(func=cmd_status)
    gate = sub.add_parser("gate", help="run the gate on a branch")
    gate.add_argument("branch")
    gate.set_defaults(func=cmd_gate)

    args = parser.parse_args()
    try:
        args.func(args)
    except Fail as problem:
        print(f"\nSTOPPED: {problem}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        if _running_container:
            subprocess.run(["docker", "kill", _running_container], capture_output=True)
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
