"""Inactive trusted publication outbox. No default transport or dispatch hook.

Only freshly rendered fixed envelopes can enter. Caller supplies a separately
reviewed publisher transport and identity; model output never supplies either.
"""
from contextlib import contextmanager
import fcntl
import os
import re
import stat

from . import incidents, investigation_model as model, investigation_evidence as evidence


@contextmanager
def store(cfg, incident, run):
    evidence.require(incidents.ID_RE.fullmatch(incident) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", run), "invalid_reference")
    name = evidence.digest((cfg.repo + "\0" + incident + "\0" + run).encode())
    with evidence.directory(cfg.factory) as parent:
        try:
            os.mkdir("investigation-outbox", mode=0o700, dir_fd=parent)
        except FileExistsError:
            pass
        fd = os.open("investigation-outbox", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            lock = os.open(name + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
            try:
                evidence.require(stat.S_ISREG(os.fstat(lock).st_mode), "unsafe_file_type")
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield fd, name + ".json"
            finally:
                os.close(lock)
        finally:
            os.close(fd)


def read(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    row, _ = evidence.read_json(fd, (name,))
    allowed = {"version", "incident", "run", "repo", "issue", "key", "body_sha256",
               "state", "code", "created_at", "publisher_login"}
    evidence.require(set(row) <= allowed and row.get("version") == 1
                     and row.get("state") in {"queued", "uncertain", "delivered", "failed", "blocked"}
                     and row.get("code") in {"prepared", "fresh_validation_failed", "reconciled",
                         "post_intent", "post_rejected", "post_outcome_unknown", "confirmed"}
                     and type(row.get("issue")) is int and row["issue"] > 0
                     and isinstance(row.get("body_sha256"), str)
                     and re.fullmatch(r"[0-9a-f]{64}", row["body_sha256"]), "invalid_publication_destination")
    return row


def binding(envelope):
    evidence.require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", envelope.repository)
                     and type(envelope.issue) is int and envelope.issue > 0, "invalid_publication_destination")
    return {"repo": envelope.repository, "issue": envelope.issue,
            "key": envelope.idempotency_key, "body_sha256": evidence.digest(envelope.body.encode())}


def enqueue(cfg, incident, run, *, now=None):
    """Persist only trusted identity and hashes; never take a supplied body."""
    envelope = model.prepare(cfg, incident, run, now=now)
    expected = binding(envelope)
    with store(cfg, incident, run) as (fd, name):
        row = read(fd, name)
        if row is not None:
            evidence.require(all(row.get(k) == v for k, v in expected.items()), "publication_binding_changed")
            return row
        row = {"version": 1, "incident": incident, "run": run, **expected,
               "state": "queued", "code": "prepared", "created_at": incidents.now()}
        model._write(fd, name, row)
        return row


def deliver(cfg, incident, run, *, publisher, publisher_login, now=None):
    """Explicit trusted call only. No credentials/default network integration.

    Reconcile a lost POST only by exact marker/body AND publisher author. Never
    repeat an unknown POST. Fresh evidence and destination are required before
    first POST; a changed binding blocks instead of publishing stale findings.
    """
    evidence.require(isinstance(publisher_login, str) and re.fullmatch(r"[A-Za-z0-9_\[\]-]{1,100}", publisher_login), "invalid_publication_destination")
    with store(cfg, incident, run) as (fd, name):
        row = read(fd, name)
        evidence.require(row is not None and row.get("repo") == cfg.repo
                         and row.get("incident") == incident and row.get("run") == run,
                         "invalid_publication_destination")
        evidence.require(row.get("publisher_login", publisher_login) == publisher_login, "publication_binding_changed")
        if row["state"] in {"delivered", "failed", "blocked"}:
            return row
        try:
            envelope = model.prepare(cfg, incident, run, now=now)
            expected = binding(envelope)
            evidence.require(all(row.get(k) == v for k, v in expected.items()), "publication_binding_changed")
        except (model.ModelRefused, evidence.EvidenceRefused):
            row.update(state="blocked", code="fresh_validation_failed")
            model._write(fd, name, row)
            return row
        marker = "<!-- factory-investigation-publication: " + name[:-5] + " -->"
        body = marker + "\n" + envelope.body
        endpoint = f"repos/{cfg.repo}/issues/{envelope.issue}/comments"
        # Bounded complete lookup; unknown lookup never grants permission to POST.
        try:
            for page in range(1, 11):
                comments = publisher.api(endpoint + f"?per_page=100&page={page}")
                evidence.require(isinstance(comments, list), "invalid_publication_destination")
                matches = [c for c in comments if isinstance(c, dict) and c.get("body") == body
                           and c.get("user", {}).get("login") == publisher_login]
                if matches:
                    row.update(state="delivered", code="reconciled")
                    model._write(fd, name, row)
                    return row
                if len(comments) < 100:
                    break
            else:
                return row
        except Exception:
            return row  # Lookup failed; no POST, no raw exception persisted.
        if row["state"] == "uncertain":
            return row
        row.update(state="uncertain", code="post_intent", publisher_login=publisher_login)
        model._write(fd, name, row)  # durable intent before POST, no retries
        try:
            response = publisher.api(endpoint, {"body": body}, "POST")
            evidence.require(isinstance(response, dict) and type(response.get("id")) is int
                             and response["id"] > 0 and response.get("body") == body
                             and response.get("user", {}).get("login") == publisher_login,
                             "invalid_publication_destination")
        except incidents.RequestRefused:
            row.update(state="failed", code="post_rejected")
        except Exception:
            row.update(code="post_outcome_unknown")
        else:
            row.update(state="delivered", code="confirmed")
        model._write(fd, name, row)
        return row
