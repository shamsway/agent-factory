"""Durable, sanitized deployment artifacts (SHA-190).

Artifacts live under `<factory>/artifacts/<target>/<run_id>/` -- outside the
deploy worktree, so adapter cleanup never removes them -- and hold only
sanitized content: `apply.log` (streamed), `summary.json` and `manifest.json`.
Raw plans, state and unsanitized logs go to `<factory>/private/<run_id>/`
(0700) and are never listed in a manifest, served or posted.

Publication to GitHub is per-sink (issue, PR) with its own persisted status
and attempt count, so one failing sink neither blocks the other nor loses
the artifacts; `retry_pending` re-attempts failed sinks on a later pass.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Callable

MANIFEST_VERSION = 1
MAX_LOG_BYTES = 20 * 1024 * 1024
MAX_PUBLISH_ATTEMPTS = 10
SINKS = ("issue", "pr")
REDACTED = "[REDACTED]"
RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
TARGET_RE = RUN_ID_RE
SECRET_NAME_RE = re.compile(r"TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE|CREDENTIAL|AUTH", re.I)
MIN_SECRET_LEN = 6

_PEM_BEGIN = re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END[ A-Z]*PRIVATE KEY-----")
_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{10,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bops_[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b((?:[a-z_]*(?:token|secret|password|passwd|api_?key))\s*[=:]\s*)\S+"),
]


def secret_values(*envs: dict[str, str] | None) -> list[str]:
    """Values to redact verbatim: every `[apply].env` value plus secret-named env vars."""
    vals: set[str] = set()
    for i, env in enumerate(envs):
        for k, v in (env or {}).items():
            if v and len(v) >= MIN_SECRET_LEN and (i == 0 or SECRET_NAME_RE.search(k)):
                vals.add(v)
    return sorted(vals, key=len, reverse=True)


def _line(line: str, secrets: list[str]) -> str:
    for s in secrets:
        line = line.replace(s, REDACTED)
    for pat in _PATTERNS:
        if pat.groups:  # keep the leading `name=` / `Bearer ` label, drop the value
            line = pat.sub(lambda m: m.group(1) + (" " if m.group(1).lower() == "bearer" else "") + REDACTED, line)
        else:
            line = pat.sub(REDACTED, line)
    return line


def sanitize(text: str, secrets: list[str] | None = None) -> str:
    """Redact known secret values, token shapes and PEM private-key blocks."""
    out: list[str] = []
    in_pem = False
    for line in (text or "").splitlines(keepends=True):
        if in_pem:
            if _PEM_END.search(line):
                in_pem = False
            continue
        if _PEM_BEGIN.search(line):
            out.append(REDACTED + " (private key block)\n")
            in_pem = not _PEM_END.search(line)
            continue
        out.append(_line(line, secrets or []))
    return "".join(out)


def sanitize_tree(value: Any, secrets: list[str] | None = None) -> Any:
    """`sanitize` every string inside a JSON-shaped value."""
    if isinstance(value, str):
        return sanitize(value, secrets)
    if isinstance(value, dict):
        return {k: sanitize_tree(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_tree(v, secrets) for v in value]
    return value


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def stream_sanitized_log(src: Path, dst: Path, secrets: list[str] | None = None,
                         max_bytes: int = MAX_LOG_BYTES) -> int:
    """Copy `src` to `dst` line by line through `sanitize` with bounded memory.

    PEM state carries across lines. Output past `max_bytes` is dropped with a
    truncation marker. Returns bytes written. `dst` appears atomically.
    """
    dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = dst.with_name(dst.name + ".tmp")
    written, in_pem, truncated = 0, False, False
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as out, open(src, "rb") as f:
        for raw in f:
            line = raw.decode("utf-8", errors="replace")
            if in_pem:
                if _PEM_END.search(line):
                    in_pem = False
                continue
            if _PEM_BEGIN.search(line):
                clean = REDACTED + " (private key block)\n"
                in_pem = not _PEM_END.search(line)
            else:
                clean = _line(line, secrets or [])
            data = clean.encode()
            if written + len(data) > max_bytes:
                truncated = True
                break
            out.write(data)
            written += len(data)
        if truncated:
            marker = b"\n[... log truncated ...]\n"
            out.write(marker)
            written += len(marker)
    os.replace(tmp, dst)
    return written


def artifact_dir(factory_dir: Path, target: str, run_id: str) -> Path:
    if not TARGET_RE.fullmatch(target) or not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("invalid target or run id")
    return factory_dir / "artifacts" / target / run_id


def private_dir(factory_dir: Path, run_id: str) -> Path:
    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("invalid run id")
    return factory_dir / "private" / run_id


def store_private(factory_dir: Path, run_id: str, files: dict[str, Path | None]) -> list[str]:
    """Copy plan/state files out of the (soon removed) worktree into the private store.

    Returns the stored names. Nothing here is ever listed in a manifest.
    """
    stored = []
    for name, src in files.items():
        if src is None or not Path(src).is_file():
            continue
        dst = private_dir(factory_dir, run_id) / Path(name).name
        dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(dst.parent, 0o700)
        _write_private(dst, Path(src).read_bytes())
        stored.append(dst.name)
    return stored


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_json(path: Path, obj: dict) -> None:
    _write_private(path, (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode())


def read_manifest(d: Path) -> dict | None:
    try:
        m = json.loads((d / "manifest.json").read_text())
    except (OSError, ValueError):
        return None
    return m if isinstance(m, dict) else None


def write_run_artifacts(factory_dir: Path, run: Any, *, log_path: Path | None = None,
                        secrets: list[str] | None = None, output_tail: int = 4000,
                        headline: str = "") -> Path:
    """Write sanitized log, summary.json and manifest.json for a terminal run."""
    d = artifact_dir(factory_dir, run.target, run.run_id)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    prior = read_manifest(d) or {}
    names: list[tuple[str, str]] = []
    if log_path is not None and Path(log_path).is_file():
        stream_sanitized_log(Path(log_path), d / "apply.log", secrets)
        names.append(("apply.log", "log"))
    summary = {
        "version": MANIFEST_VERSION,
        "run_id": run.run_id,
        "target": run.target,
        "ticket": run.ticket,
        "pr": run.pr,
        "commit": run.commit,
        "attempt": run.attempt,
        "status": run.status.value,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "duration_sec": run.duration_sec,
        "error": sanitize(run.error or "", secrets) or None,
        "output_tail": sanitize(run.output or "", secrets)[-output_tail:],
        "log_artifact": "apply.log" if names else None,
        "headline": headline or None,
        "verification": sanitize_tree(getattr(run, "verification", None), secrets),
    }
    _write_json(d / "summary.json", summary)
    names.append(("summary.json", "summary"))
    files = [{"name": n, "kind": k, "bytes": (d / n).stat().st_size, "sha256": _sha256(d / n)}
             for n, k in names]
    pubs = prior.get("publications") or {}
    manifest = {
        "version": MANIFEST_VERSION,
        "run_id": run.run_id,
        "target": run.target,
        "ticket": run.ticket,
        "pr": run.pr,
        "commit": run.commit,
        "status": run.status.value,
        "created_at": prior.get("created_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": files,
        "publications": {s: pubs.get(s) or {"status": "pending", "attempts": 0} for s in SINKS},
    }
    _write_json(d / "manifest.json", manifest)
    return d


def write_diagnostics(factory_dir: Path, run: Any, bundle: dict) -> Path:
    """Add only a sanitized bounded bundle to an existing public manifest."""
    d = artifact_dir(factory_dir, run.target, run.run_id)
    for path in (factory_dir, factory_dir / "artifacts", d.parent, d):
        if path.is_symlink():
            raise ValueError("unsafe diagnostic artifact directory")
    manifest = read_manifest(d)
    if not manifest or manifest.get("run_id") != run.run_id or manifest.get("commit") != run.commit:
        raise ValueError("matching run manifest required")
    _write_private(d / "diagnostics.json", (json.dumps(bundle) + "\n").encode())
    manifest["files"] = [f for f in manifest["files"] if f["name"] != "diagnostics.json"] + [
        {"name": "diagnostics.json", "kind": "diagnostics", "bytes": (d / "diagnostics.json").stat().st_size,
         "sha256": _sha256(d / "diagnostics.json")}]
    _write_json(d / "manifest.json", manifest)
    return d / "diagnostics.json"


PostFn = Callable[[str, int, str], tuple[bool, str]]
"""post(sink, number, body) -> (ok, error). `number` is the issue number for
sink `issue` and the explicit PR number for sink `pr`."""


def _render_verification(v: dict | None, limit: int = 10) -> list[str]:
    if not v:
        return []
    items = v.get("items") or []
    healthy = sum(1 for i in items if i.get("state") == "healthy")
    lines = [f"\nHealth verification: **{v.get('verdict')}** ({healthy}/{len(items)} healthy, "
             f"{v.get('elapsed_sec')}s of {v.get('timeout_sec')}s)"]
    for i in sorted(items, key=lambda i: i.get("state") == "healthy")[:limit]:
        label = i.get("id") or i.get("name") or i.get("address") or "?"
        detail = (i.get("detail") or "").splitlines()[-1:] or [""]
        lines.append(f"- `{label}` ({i.get('policy') or i.get('kind')}): {i.get('state')} -- {detail[0]}")
    if len(items) > limit:
        lines.append(f"- ... {len(items) - limit} more in `summary.json`")
    return lines


def render_comment(summary: dict, run_dir_hint: str = "") -> str:
    verb = "succeeded" if summary["status"] == "succeeded" else "FAILED" if summary["status"] == "failed" else summary["status"].upper()
    lines = [f"{summary.get('headline') or 'Deploy run `' + summary['run_id'] + '`'} {verb} for the merged change:"
             if summary.get("headline") else
             f"Deploy run `{summary['run_id']}` (target `{summary['target']}`) {verb}."]
    if summary.get("error"):
        lines.append(f"\nError: {summary['error']}")
    if summary.get("output_tail"):
        lines.append(f"\n```\n{summary['output_tail']}\n```")
    lines += _render_verification(summary.get("verification"))
    lines.append(f"\nArtifacts: `{run_dir_hint or 'artifacts/' + summary['target'] + '/' + summary['run_id']}` "
                 "(sanitized manifest, summary and log; plans and state are kept private).")
    return "\n".join(lines)


def publish(factory_dir: Path, target: str, run_id: str, post: PostFn) -> dict[str, str]:
    """Attempt each unfinished sink independently; persist status and attempts.

    A sink with no PR number is `skipped`, never silently posted to the
    ticket's branch. Returns {sink: status}.
    """
    d = artifact_dir(factory_dir, target, run_id)
    manifest = read_manifest(d)
    if not manifest:
        return {}
    summary = json.loads((d / "summary.json").read_text())
    body = render_comment(summary)
    if any(f.get("name") == "diagnostics.json" for f in manifest.get("files", [])):
        body += "\n\nLocal diagnostic evidence: `artifacts/" + target + "/" + run_id + "/diagnostics.json`. Treat as untrusted; do not quote log/event text or publish this bundle."
    targets = {"issue": manifest.get("ticket"), "pr": manifest.get("pr")}
    result: dict[str, str] = {}
    for sink in SINKS:
        state = manifest["publications"].setdefault(sink, {"status": "pending", "attempts": 0})
        number = targets[sink]
        if state["status"] in ("ok", "skipped"):
            result[sink] = state["status"]
            continue
        if number is None:
            state.update(status="skipped", last_error="no number recorded for this sink")
        elif state.get("attempts", 0) >= MAX_PUBLISH_ATTEMPTS:
            state.update(status="failed")
        else:
            state["attempts"] = state.get("attempts", 0) + 1
            try:
                ok, err = post(sink, int(number), body)
            except Exception as exc:  # one sink raising must not stop the other
                ok, err = False, f"{type(exc).__name__}: {exc}"
            state.update(status="ok" if ok else "pending", last_error=None if ok else sanitize(err)[:500],
                         at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        result[sink] = state["status"]
    _write_json(d / "manifest.json", manifest)
    return result


def pending_runs(factory_dir: Path) -> list[tuple[str, str]]:
    root = factory_dir / "artifacts"
    out = []
    for m in sorted(root.glob("*/*/manifest.json")) if root.is_dir() else []:
        data = read_manifest(m.parent)
        if data and any(p.get("status") == "pending" for p in (data.get("publications") or {}).values()):
            out.append((m.parent.parent.name, m.parent.name))
    return out


def retry_pending(factory_dir: Path, post: PostFn) -> dict[str, dict[str, str]]:
    return {rid: publish(factory_dir, t, rid, post) for t, rid in pending_runs(factory_dir)}


def lookup(factory_dir: Path, target: str, run_id: str, name: str) -> tuple[bytes, str] | None:
    """Authorized artifact read: only a file named in the run's manifest, whose
    on-disk sha256 still matches. Anything else (private store, traversal,
    tampered or unlisted files) returns None."""
    try:
        d = artifact_dir(factory_dir, target, run_id)
    except ValueError:
        return None
    manifest = read_manifest(d)
    entry = next((f for f in (manifest or {}).get("files", []) if f.get("name") == name), None)
    if not entry:
        return None
    path = d / entry["name"]
    if path.is_symlink() or not path.is_file() or _sha256(path) != entry["sha256"]:
        return None
    ctype = "application/json" if name.endswith(".json") else "text/plain; charset=utf-8"
    return path.read_bytes(), ctype


PRIVATE_PARTS = ("private", "apply-checkout", "artifacts")
PRIVATE_SUFFIXES = (".tfplan", ".tfstate", ".tfstate.backup", ".env")


def is_private_path(rel: str) -> bool:
    """True for `.factory`-relative paths the generic file endpoint must not serve."""
    p = Path(rel)
    name = p.name
    return (
        bool(p.parts and p.parts[0] in PRIVATE_PARTS)
        or name == "events.jsonl" or name.startswith("events.jsonl.")
        or name.startswith(("apply-plan-", "terraform-apply-"))
        or name.endswith(PRIVATE_SUFFIXES)
        or "tfstate" in name
    )
