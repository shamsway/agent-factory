"""Durable deployment incidents and a conservative GitHub notification outbox.

A create with an unknown outcome is never repeated automatically. REST listing
(including closed issues), not search, reconciles a stable body marker. Absence
after an uncertain create is not proof that GitHub did not accept it.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from . import artifacts, config, deploy

MAX_ATTEMPTS = 3
MAX_RECORD_BYTES = 1024 * 1024
ID_RE = re.compile(r"incident-[0-9a-f]{24}")
END = "<!-- factory-incident-end -->"


class UncertainCreation(ValueError):
    """Operator must verify remote absence before another create is permitted."""


class AmbiguousIncidents(ValueError):
    """Multiple remote identities require manual reconciliation."""


class RemoteIncidentUnavailable(ValueError):
    """An existing issue is not visible; never replace it automatically."""


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def identity(repo: str, target: str, ticket: int) -> str:
    key = json.dumps([repo, target, ticket], separators=(",", ":"))
    return "incident-" + hashlib.sha256(key.encode()).hexdigest()[:24]


def marker(incident_id: str) -> str:
    if not ID_RE.fullmatch(incident_id):
        raise ValueError("invalid incident identity")
    return f"<!-- factory-incident: {incident_id} -->"


def directory(factory: Path, *, create: bool = False) -> Path:
    path = factory / "incidents"
    if path.is_symlink():
        raise ValueError("incident store must not be a symlink")
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.chmod(0o700)
    return path


@contextmanager
def locked(factory: Path):
    path = directory(factory, create=True)
    fd = os.open(path / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield path
    finally:
        os.close(fd)


def read(path: Path) -> dict:
    if path.is_symlink():
        raise ValueError("symlink record")
    with path.open("rb") as handle:
        raw = handle.read(MAX_RECORD_BYTES + 1)
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("oversized record")
    row = json.loads(raw)
    if (row.get("version") != 1 or row.get("id") != path.stem
            or not ID_RE.fullmatch(row["id"])
            or row.get("status") not in {"pending", "uncertain", "delivered", "failed"}
            or not isinstance(row.get("runs"), list)
            or not isinstance(row.get("attempts"), int)
            or not isinstance(row.get("uncertain"), bool)
            or not isinstance(row.get("published_runs"), int)):
        raise ValueError("invalid incident record")
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", row.get("repo", ""))
            or not artifacts.TARGET_RE.fullmatch(row.get("target", ""))
            or not isinstance(row.get("original_ticket"), int)
            or row["id"] != identity(row["repo"], row["target"], row["original_ticket"])
            or row["attempts"] < 0):
        raise ValueError("invalid root incident")
    for run in row["runs"]:
        if (not artifacts.RUN_ID_RE.fullmatch(run.get("run_id", ""))
                or not isinstance(run.get("ticket"), int)
                or run.get("artifact_ref") != f"artifacts/{row['target']}/{run['run_id']}/manifest.json"
                or not re.fullmatch(r"(?:[0-9a-f]{7,40})?", run.get("commit", ""))):
            raise ValueError("invalid correlated run")
    return row


def write(path: Path, row: dict) -> None:
    raw = (json.dumps(row, indent=2) + "\n").encode()
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("oversized incident record")
    fd, name = tempfile.mkstemp(prefix=".incident-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        parent = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        Path(name).unlink(missing_ok=True)


def enqueue(factory: Path, repo: str, run: deploy.DeployRun, *, root_id: str | None = None) -> str:
    """Idempotently attach a failed run. SHA-202 can supply its persisted root id."""
    if run.status != deploy.DeployStatus.FAILED:
        raise ValueError("only failed runs create incidents")
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)
            or not isinstance(run.ticket, int) or run.ticket <= 0):
        raise ValueError("invalid source identity")
    if not artifacts.RUN_ID_RE.fullmatch(run.run_id) or not artifacts.TARGET_RE.fullmatch(run.target):
        raise ValueError("invalid run reference")
    with locked(factory) as store:
        rid = root_id or identity(repo, run.target, run.ticket)
        marker(rid)
        # Replay must preserve explicit remediation attachments rather than open
        # a second root for that child ticket after restart.
        attached = []
        for existing in store.glob("incident-*.json"):
            prior = read(existing)
            if prior["repo"] == repo and any(r["run_id"] == run.run_id for r in prior["runs"]):
                attached.append(prior["id"])
        if len(attached) > 1 or (root_id and attached and attached != [root_id]):
            raise ValueError("ambiguous local incident attachment")
        if attached:
            return attached[0]
        path = store / (rid + ".json")
        if path.exists():
            row = read(path)
            if row["repo"] != repo or row["target"] != run.target:
                raise ValueError("root incident belongs to another target or repo")
        elif root_id:
            raise ValueError("root incident not found")
        else:
            row = {"version": 1, "id": rid, "repo": repo, "target": run.target,
                   "original_ticket": run.ticket, "created_at": now(), "updated_at": now(),
                   "status": "pending", "uncertain": False, "attempts": 0,
                   "issue": None, "published_runs": 0, "last_error": None, "runs": []}
        if any(r["run_id"] == run.run_id for r in row["runs"]):
            return rid
        # No raw errors, logs, plans or environment values are copied into the outbox.
        row["runs"].append({"run_id": run.run_id, "ticket": run.ticket, "pr": run.pr,
                            "commit": run.commit if re.fullmatch(r"[0-9a-f]{7,40}", run.commit) else "",
                            "artifact_ref": f"artifacts/{run.target}/{run.run_id}/manifest.json",
                            "completed_at": run.completed_at})
        row["updated_at"] = now()
        if row["status"] == "delivered":
            row.update(status="pending", attempts=0)
        write(path, row)
    return rid


def body(row: dict) -> str:
    lines = [marker(row["id"]), "## Deployment incident", "",
             f"Target: `{row['target']}`; original ticket: #{row['original_ticket']}.",
             "", "Read-only investigation: gather evidence and report findings. Do not modify",
             "tracked files, merge, apply, restart workloads or acknowledge a failed run.",
             "Production repair remains subject to normal gates and human approval.", "",
             "### Correlated failed runs (latest 20)"]
    for run in row["runs"][-20:]:
        pr = f", PR #{run['pr']}" if run["pr"] else ""
        lines.append(f"- `{run['run_id']}`: ticket #{run['ticket']}{pr}, revision `{run['commit']}`; "
                     f"sanitized artifact reference `{run['artifact_ref']}`.")
    lines.extend(["", f"{len(row['runs'])} recorded run(s). Use `factory incidents --id {row['id']}`",
                  "for the durable index; missing artifacts are unavailable evidence, not success.", END])
    return "\n".join(lines)


class GitHub:
    """Bounded REST transport. Provider output remains internal, never in errors."""

    def __init__(self, cfg: config.Config):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", cfg.repo):
            raise ValueError("invalid GitHub repository")
        self.repo = cfg.repo
        self.deadline = time.monotonic() + 60
        self.env = dict(os.environ)
        for key in cfg.apply_env:
            self.env.pop(key, None)
        self.env.update({k: str(v) for k, v in cfg.install.get("env", {}).items() if k == "GH_TOKEN"})

    def api(self, endpoint: str, payload: dict | None = None, method: str = "GET"):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("incident delivery budget exhausted")
        cmd = ["gh", "api", "--method", method, endpoint]
        if payload is not None:
            cmd.extend(["--input", "-"])
        proc = subprocess.run(cmd, input=json.dumps(payload) if payload is not None else None,
                              env=self.env, capture_output=True, text=True, timeout=min(20, remaining))
        if proc.returncode or len(proc.stdout) > 2 * MAX_RECORD_BYTES:
            raise RuntimeError("GitHub request failed")
        return json.loads(proc.stdout)

    def find(self, row: dict) -> list[dict]:
        found = []
        # Repository listing is authoritative and includes closed issues; search is lagged.
        for page in range(1, 11):
            rows = self.api(f"repos/{self.repo}/issues?state=all&per_page=100&page={page}")
            if not isinstance(rows, list):
                raise ValueError("invalid GitHub list response")
            found.extend(r for r in rows if not r.get("pull_request")
                         and marker(row["id"]) in (r.get("body") or ""))
            if len(rows) < 100:
                return found
        raise RuntimeError("incomplete incident lookup")

    def create(self, row: dict) -> int:
        result = self.api(f"repos/{self.repo}/issues", {
            "title": f"Deployment incident: {row['target']} / ticket #{row['original_ticket']}",
            "body": body(row), "labels": [config.LABEL_INVESTIGATE]}, "POST")
        number = result.get("number")
        if not isinstance(number, int) or number <= 0:
            raise ValueError("invalid GitHub issue response")
        return number

    def update(self, row: dict, issue: dict) -> None:
        old = issue.get("body") or ""
        start = old.find(marker(row["id"]))
        end = old.find(END, start)
        if start < 0 or end < 0:
            raise ValueError("incident section changed")
        new = old[:start] + body(row) + old[end + len(END):]
        self.api(f"repos/{self.repo}/issues/{row['issue']}", {"body": new}, "PATCH")


def deliver(factory: Path, client: GitHub, *, only: str | None = None) -> list[dict]:
    """Serialize local delivery; uncertain creates only reconcile, never recreate."""
    with locked(factory) as store:
        results = []
        for path in sorted(store.glob("incident-*.json")):
            row = None
            if only and path.stem != only:
                continue
            try:
                row = read(path)
                if row["repo"] != client.repo:
                    continue
                if row["status"] in {"delivered", "failed"}:
                    continue
                if row["attempts"] >= MAX_ATTEMPTS:
                    row.update(status="failed", last_error="delivery_budget_exhausted")
                    write(path, row)
                    results.append(metadata(row))
                    continue
                row.update(attempts=row["attempts"] + 1, last_attempt_at=now(), last_error=None)
                write(path, row)
                matches = client.find(row)
                if len(matches) > 1:
                    row.update(status="failed", last_error="ambiguous_remote_incidents")
                elif matches:
                    number = matches[0].get("number")
                    if not isinstance(number, int) or number <= 0:
                        raise ValueError("invalid remote incident")
                    if row["issue"] and row["issue"] != number:
                        row.update(status="failed", last_error="remote_identity_changed")
                    else:
                        row.update(issue=number, uncertain=False)
                        # Idempotent update also reconciles crash/lost-response after create.
                        client.update(row, matches[0])
                        row.update(status="delivered", published_runs=len(row["runs"]))
                elif row["issue"]:
                    row.update(status="failed", last_error="remote_incident_unavailable")
                elif row["uncertain"]:
                    row.update(status="uncertain", last_error="creation_outcome_unknown")
                else:
                    # Commit uncertainty BEFORE the API side effect, including a crash before send.
                    row.update(status="uncertain", uncertain=True)
                    write(path, row)
                    number = client.create(row)
                    row.update(issue=number, status="delivered", uncertain=False,
                               published_runs=len(row["runs"]))
            except Exception as exc:
                if row is None:
                    results.append({"id": path.stem, "status": "unavailable", "last_error": type(exc).__name__})
                    continue
                row["last_error"] = type(exc).__name__
            if row["status"] != "delivered" and row["attempts"] >= MAX_ATTEMPTS:
                row["status"] = "failed"
            row["updated_at"] = now()
            write(path, row)
            results.append(metadata(row))
        return results


def metadata(row: dict) -> dict:
    keys = ("id", "target", "original_ticket", "status", "issue", "attempts", "uncertain",
            "last_error", "last_attempt_at", "updated_at", "published_runs")
    return {**{k: row.get(k) for k in keys}, "runs": row["runs"]}


def snapshot(factory: Path) -> dict:
    try:
        store = directory(factory)
        rows = [metadata(read(path)) for path in sorted(store.glob("incident-*.json"))]
        return {"status": "observed", "incidents": rows,
                "pending": sum(r["status"] in {"pending", "uncertain"} for r in rows),
                "failed": sum(r["status"] == "failed" for r in rows)}
    except Exception as exc:
        return {"status": "unavailable", "incidents": [], "error_type": type(exc).__name__}


def recover(factory: Path, incident_id: str, client: GitHub, *, confirm_not_created: bool = False) -> None:
    marker(incident_id)
    with locked(factory) as store:
        path = store / (incident_id + ".json")
        row = read(path)
        if row["repo"] != client.repo:
            raise ValueError("wrong repository")
        matches = client.find(row)
        if len(matches) > 1:
            raise AmbiguousIncidents("ambiguous remote incidents")
        if row["uncertain"] and not matches and not confirm_not_created:
            raise UncertainCreation("manually confirm no issue was created before rearming creation")
        if row["issue"] and not matches:
            raise RemoteIncidentUnavailable("recorded issue is unavailable; refusing to recreate")
        if matches:
            row.update(issue=matches[0]["number"], uncertain=False)
        elif confirm_not_created:
            row["uncertain"] = False
        row.update(status="pending", attempts=0, updated_at=now(), last_error=None,
                   operator_retries=row.get("operator_retries", 0) + 1)
        write(path, row)


def sync_failed(cfg: config.Config) -> None:
    """Reconstruct missing outbox entries after a crash, without reopening old failures."""
    for state in deploy.replay_events(cfg.factory / "events.jsonl").values():
        for ticket in state.unacknowledged_failed_tickets:
            run = state.runs_by_ticket[ticket][-1]
            if run.status == deploy.DeployStatus.FAILED and run.run_id.startswith("deploy-"):
                enqueue(cfg.factory, cfg.repo, run)


def attach_run(cfg: config.Config, run_id: str, root_id: str) -> None:
    """Explicitly associate a repair attempt; never acknowledges or authorizes it."""
    matches = [run for state in deploy.replay_events(cfg.factory / "events.jsonl").values()
               for run in state.runs if run.run_id == run_id]
    if len(matches) != 1:
        raise ValueError("failed run must exist uniquely in the journal")
    enqueue(cfg.factory, cfg.repo, matches[0], root_id=root_id)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", help="show one incident's durable run index")
    parser.add_argument("--deliver", action="store_true", help="replay failed runs and deliver pending outbox")
    parser.add_argument("--retry", metavar="ID", help="reconcile and rearm exhausted delivery budget")
    parser.add_argument("--attach-run", metavar="RUN_ID", help="attach failed remediation attempt to --id root")
    parser.add_argument("--confirm-not-created", action="store_true",
                        help="with --retry: operator has manually confirmed uncertain create never succeeded")
    args = parser.parse_args(argv)
    cfg = config.load()
    try:
        if args.confirm_not_created and not args.retry:
            raise ValueError("--confirm-not-created requires --retry")
        if args.id:
            marker(args.id)
        if args.attach_run:
            if not args.id:
                raise ValueError("--attach-run requires --id")
            attach_run(cfg, args.attach_run, args.id)
        if args.retry:
            recover(cfg.factory, args.retry, GitHub(cfg), confirm_not_created=args.confirm_not_created)
        if args.deliver:
            sync_failed(cfg)
            deliver(cfg.factory, GitHub(cfg), only=args.id or args.retry)
        result = snapshot(cfg.factory)
        if args.id:
            result["incidents"] = [r for r in result["incidents"] if r["id"] == args.id]
            if not result["incidents"] and result["status"] == "observed":
                raise ValueError("incident not found")
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "observed" else 1
    except Exception as exc:
        print(json.dumps({"status": "unavailable", "error_type": type(exc).__name__}))
        return 1
