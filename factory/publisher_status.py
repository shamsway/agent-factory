"""Publisher-to-Factory metadata only. No credential or request channel."""
import json
import os
from pathlib import Path
import time
import uuid
from types import SimpleNamespace

from . import investigation_evidence as evidence, investigation_outbox as outbox

STATES = {'queued', 'uncertain', 'blocked', 'failed', 'delivered'}
OUTCOMES = {'not_requested', 'request_reserved', 'ready', 'refresh_failed', 'unavailable'}
MAX_AGE = 300


def schema(raw, repo):
    evidence.require(isinstance(raw, dict) and set(raw) == {'version', 'repository', 'at', 'outbox', 'token', 'last_import'}
                     and type(raw['version']) is int and raw['version'] == 1 and raw['repository'] == repo, 'publisher_status_invalid')
    evidence.timestamp(raw['at'])
    box, token, imported = raw['outbox'], raw['token'], raw['last_import']
    evidence.require(isinstance(box, dict) and set(box) == {'status', 'states'}
                     and box['status'] in {'observed', 'unavailable'}
                     and isinstance(box['states'], dict) and set(box['states']) == STATES
                     and all(type(v) is int and 0 <= v <= 10000 for v in box['states'].values()), 'publisher_status_invalid')
    evidence.require(isinstance(token, dict) and set(token) == {'outcome', 'expires_at'}
                     and isinstance(token['outcome'], str) and token['outcome'] in OUTCOMES
                     and (token['expires_at'] is None or evidence.number(token['expires_at'])), 'publisher_status_invalid')
    evidence.require(isinstance(imported, dict) and set(imported) == {'result', 'at'}
                     and imported['result'] in {'none', 'imported', 'refused', 'unavailable'}, 'publisher_status_invalid')
    if imported['at'] is not None:
        evidence.timestamp(imported['at'])
    return raw


def write(policy):
    state, repo = Path(policy['state']), policy['app']['repository']
    token, imported = {'outcome': 'not_requested', 'expires_at': None}, {'result': 'none', 'at': None}
    with evidence.directory(state) as fd:
        try:
            row, _ = evidence.read_json(fd, ('publisher-token-status.json',))
            token = {'outcome': row.get('outcome'), 'expires_at': row.get('expires_at')}
        except evidence.EvidenceRefused:
            if (state / 'publisher-token-status.json').exists():
                token = {'outcome': 'unavailable', 'expires_at': None}
        try:
            row, _ = evidence.read_json(fd, ('import-result.json',))
            imported = {'result': row.get('result'), 'at': row.get('at')}
        except evidence.EvidenceRefused:
            if (state / 'import-result.json').exists():
                imported = {'result': 'unavailable', 'at': None}
    result = {'version': 1, 'repository': repo, 'at': evidence.utc(time.time()),
              'outbox': outbox.snapshot(SimpleNamespace(factory=state, repo=repo)), 'token': token, 'last_import': imported}
    schema(result, repo)
    path = Path(policy['status_file'])
    # Parent is operator-provisioned, publisher-owned, read-only to matt.
    from .publisher_credentials import protected_read
    evidence.require(protected_read(path.parent / 'broker-store.json') == evidence.encoded(
        {'version': 1, 'repository': repo}), 'publisher_status_invalid')
    with evidence.directory(path.parent) as fd:
        name = '.status-' + uuid.uuid4().hex
        handle = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644, dir_fd=fd)
        try:
            with os.fdopen(handle, 'wb') as stream:
                stream.write(evidence.encoded(result))
                os.fchmod(stream.fileno(), 0o644)
                stream.flush()
                os.fsync(stream.fileno())
            os.rename(name, path.name, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
        finally:
            try:
                os.unlink(name, dir_fd=fd)
            except FileNotFoundError:
                pass
    return result


def observe(cfg, *, now=None):
    raw_policy = cfg.publisher
    path, uid = raw_policy.get('status_file', ''), raw_policy.get('status_uid', 0)
    if not path:
        return {'status': 'not_configured'}
    now = time.time() if now is None else now
    try:
        path = Path(path)
        evidence.require(path.is_absolute() and '..' not in path.parts and type(uid) is int and uid > 0, 'publisher_status_invalid')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                meta = os.fstat(fd)
                evidence.require(meta.st_uid in {0, uid} and not meta.st_mode & 0o022, 'publisher_status_invalid')
            with evidence.file_at(fd, (path.name,)) as handle:
                meta = os.fstat(handle.fileno())
                evidence.require(meta.st_uid in {0, uid} and not meta.st_mode & 0o022, 'publisher_status_invalid')
                data = handle.read(8193)
                evidence.require(len(data) <= 8192, 'publisher_status_invalid')
        finally:
            os.close(fd)
        result = schema(json.loads(data, object_pairs_hook=evidence.unique_pairs), cfg.repo)
        age = now - evidence.timestamp(result['at'])
        evidence.require(age >= 0, 'publisher_status_invalid')
        return {'status': 'stale' if age > MAX_AGE else 'observed', **result}
    except (FileNotFoundError,):
        return {'status': 'missing'}
    except Exception:
        # file_at normalizes missing files; distinguish only actual absent pathname.
        try:
            if not path.exists() and not path.is_symlink():
                return {'status': 'missing'}
        except Exception:
            pass
        return {'status': 'malformed'}


def doctor(cfg, report):
    result = observe(cfg)
    if result['status'] == 'not_configured':
        report(True, 'publisher status', 'not configured; no unattended publisher', info=True)
    else:
        report(True if result['status'] == 'observed' else None, 'publisher status', result['status'])
        if result['status'] == 'observed':
            counts = result['outbox']['states']
            attention = sum(counts[k] for k in ('queued', 'uncertain', 'blocked', 'failed'))
            report(None if attention or result['outbox']['status'] != 'observed' else True,
                   'publisher outbox', ', '.join(f'{k}={counts[k]}' for k in sorted(STATES)))

            token = result['token']
            expired = token['expires_at'] is not None and token['expires_at'] <= time.time()
            report(None if expired or token['outcome'] in {'unavailable', 'refresh_failed', 'request_reserved'} else True,
                   'publisher token', token['outcome'] + ('; expired; no persisted token' if expired else '; no persisted token'))
            imported = result['last_import']['result']
            report(None if imported in {'refused', 'unavailable'} else True, 'publisher import', imported)
