"""Option B: explicit operator transfer of structured, unauthenticated evidence.

No logs/config/provider prose, sockets, signing identities or automatic sends.
Hashes detect substitution, not coherent forgery by the matt account.
"""
import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import time
from types import SimpleNamespace

from . import artifacts, config, incidents, investigation_evidence as evidence
from . import investigation_model as model, investigation_publication as publication
from . import investigation_outbox as outbox, investigation_scope as scope

MAX_BUNDLE = 256 * 1024
MAX_TRANSFER_AGE = 300
HEX = re.compile(r'[0-9a-f]{64}')
FIELDS = {'version', 'repository', 'incident', 'run', 'target', 'ticket', 'commit',
          'started_at', 'completed_at', 'exported_at', 'issue', 'jobs',
          'projection', 'result', 'binding', 'sha256'}
COMMON = {'ref', 'kind', 'status', 'observed_at', 'job', 'namespace', 'version'}
SPECIFIC = {
    'current_job': {'current_version', 'state', 'relation'},
    'evaluation': {'evaluation', 'state', 'event_time', 'relation', 'nodes_available',
                   'constraints_filtered', 'resources_exhausted', 'cpu_exhausted', 'memory_exhausted', 'disk_exhausted'},
    'allocation': {'allocation', 'state', 'relation'},
    'deployment': {'deployment', 'state', 'relation'},
    'task': set(),
    'task_event': {'allocation', 'task', 'state', 'event_type', 'event_time', 'relation', 'oom_killed', 'ExitCode', 'Signal'},
}


def key(repo, incident, run):
    return evidence.digest((repo + '\0' + incident + '\0' + run).encode())


def read_bundle(path):
    path = Path(path).absolute()
    with evidence.directory(path.parent) as fd:
        with evidence.file_at(fd, (path.name,)) as handle:
            raw = handle.read(MAX_BUNDLE + 1)
    evidence.require(len(raw) <= MAX_BUNDLE, 'transfer_budget')
    try:
        return json.loads(raw, object_pairs_hook=evidence.unique_pairs)
    except evidence.EvidenceRefused:
        raise
    except Exception:
        raise evidence.EvidenceRefused('transfer_invalid') from None


def validate(bundle, *, now=None):
    """Recheck closed projection/result, identity, lineage, window and digests."""
    now = time.time() if now is None else now
    evidence.require(isinstance(bundle, dict) and set(bundle) == FIELDS
                     and type(bundle['version']) is int and bundle['version'] == 1, 'transfer_invalid')
    evidence.require(len(evidence.encoded(bundle)) <= MAX_BUNDLE, 'transfer_budget')
    unsigned = {k: v for k, v in bundle.items() if k != 'sha256'}
    evidence.require(isinstance(bundle['sha256'], str) and bundle['sha256'] == evidence.digest(evidence.encoded(unsigned)),
                     'transfer_hash_mismatch')
    repo, incident, run, target = (bundle[k] for k in ('repository', 'incident', 'run', 'target'))
    evidence.require(isinstance(repo, str) and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo)
                     and isinstance(target, str) and artifacts.TARGET_RE.fullmatch(target)
                     and isinstance(incident, str) and incidents.ID_RE.fullmatch(incident)
                     and isinstance(run, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', run)
                     and type(bundle['ticket']) is int and bundle['ticket'] > 0
                     and type(bundle['issue']) is int and bundle['issue'] > 0
                     and incident == incidents.identity(repo, target, bundle['ticket']), 'transfer_identity_mismatch')
    data = bundle['projection']
    evidence.require(isinstance(data, dict) and set(data) == {'policy_version', 'incident', 'commit', 'run', 'target',
                     'ticket', 'provenance', 'window', 'rows'} and type(data['policy_version']) is int
                     and data['policy_version'] == 1, 'transfer_invalid')
    evidence.require(isinstance(bundle['commit'], str) and re.fullmatch(r'[0-9a-f]{40}', bundle['commit'])
                     and data['commit'] == bundle['commit'] and data['incident'] == incident
                     and data['run'] == evidence.alias('run', run) and data['target'] == evidence.alias('target', target)
                     and data['ticket'] == bundle['ticket'], 'transfer_identity_mismatch')
    provenance = data['provenance']
    evidence.require(isinstance(provenance, dict) and set(provenance) == {'manifest_sha256', 'bundle_sha256'}
                     and all(isinstance(v, str) and HEX.fullmatch(v) for v in provenance.values()), 'transfer_invalid')
    window = data['window']
    evidence.require(isinstance(window, dict) and set(window) == {'start', 'end'}, 'transfer_invalid')
    start, end = evidence.timestamp(window['start']), evidence.timestamp(window['end'])
    exported = evidence.timestamp(bundle['exported_at'])
    evidence.require(start == evidence.timestamp(bundle['started_at'])
                     and end == evidence.timestamp(bundle['completed_at'])
                     and 0 <= start <= end <= exported <= now and now - exported <= MAX_TRANSFER_AGE
                     and end - start <= evidence.MAX_AGE, 'transfer_window_mismatch')
    jobs = bundle['jobs']
    evidence.require(isinstance(jobs, list) and 1 <= len(jobs) <= 8, 'transfer_invalid')
    identities = set()
    for job in jobs:
        evidence.require(isinstance(job, dict) and set(job) == {'job', 'namespace', 'version'}, 'transfer_invalid')
        for field in ('job', 'namespace'):
            evidence.require(isinstance(job[field], str) and re.fullmatch(field + r'-[0-9a-f]{24}', job[field]), 'transfer_invalid')
        evidence.require(job['version'] is None or type(job['version']) is int and 0 <= job['version'] <= 2**63 - 1, 'transfer_invalid')
        identities.add((job['job'], job['namespace'], job['version']))
    evidence.require(len(identities) == len(jobs), 'transfer_invalid')
    rows = data['rows']
    evidence.require(isinstance(rows, list) and len(rows) <= evidence.MAX_ROWS, 'transfer_budget')
    allocations = set()
    for index, row in enumerate(rows, 1):
        evidence.require(isinstance(row, dict) and row.get('kind') in SPECIFIC
                         and COMMON <= set(row) <= COMMON | SPECIFIC[row['kind']], 'transfer_invalid')
        kind, status = row['kind'], row['status']
        if status != 'observed':
            evidence.require(set(row) == COMMON, 'transfer_invalid')
        else:
            evidence.require(kind != 'task', 'transfer_invalid')
            required = SPECIFIC[kind] - {'oom_killed', 'ExitCode', 'Signal'}
            evidence.require(required <= set(row), 'transfer_invalid')
        if 'relation' in row:
            relation = {'current_job': 'current_state_only', 'evaluation': 'job_time_window_not_version_proof'}.get(kind, 'recorded_health_version')
            evidence.require(row['relation'] == relation, 'transfer_lineage_mismatch')
        if kind in {'allocation', 'deployment', 'task_event'} and status == 'observed':
            evidence.require(type(row['version']) is int, 'transfer_lineage_mismatch')
        identity = row['job'], row['namespace'], row['version']
        evidence.require(identity in identities and row['ref'] == f'e{index:04d}', 'transfer_lineage_mismatch')
        evidence.require(isinstance(status, str) and status in evidence.STATUSES | {'unavailable', 'stale'}, 'transfer_invalid')
        observed = evidence.timestamp(row['observed_at'])
        evidence.require(end <= observed <= exported, 'invalid_observation_time')
        if kind == 'current_job' and status == 'observed':
            evidence.require(now - observed <= evidence.MAX_AGE, 'stale_evidence')
        for field in ('evaluation', 'allocation', 'deployment', 'task'):
            if field in row:
                evidence.require(isinstance(row[field], str) and re.fullmatch(field + r'-[0-9a-f]{24}', row[field]), 'transfer_invalid')
        if 'event_time' in row:
            evidence.require(start <= evidence.timestamp(row['event_time']) <= end, 'transfer_window_mismatch')
        for field in ('nodes_available', 'constraints_filtered', 'resources_exhausted', 'cpu_exhausted', 'memory_exhausted', 'disk_exhausted'):
            if field in row:
                evidence.require(evidence.number(row[field]), 'transfer_invalid')
        for field in ('ExitCode', 'Signal', 'current_version'):
            if field in row:
                evidence.require(type(row[field]) is int and 0 <= row[field] <= (65535 if field != 'current_version' else 2**63 - 1), 'transfer_invalid')
        if 'oom_killed' in row:
            evidence.require(type(row['oom_killed']) is bool, 'transfer_invalid')
        if 'state' in row:
            allowed = {'current_job': evidence.JOB_STATES, 'evaluation': evidence.EVAL_STATES,
                       'allocation': evidence.ALLOC_STATES, 'deployment': evidence.DEPLOY_STATES,
                       'task_event': evidence.JOB_STATES}.get(kind, frozenset())
            evidence.require(isinstance(row['state'], str) and row['state'] in allowed | {'unknown'}, 'transfer_invalid')
        if 'event_type' in row:
            evidence.require(row['event_type'] in evidence.EVENT_TYPES | {'Other'}, 'transfer_invalid')
        if kind == 'allocation' and status == 'observed':
            evidence.require('allocation' in row and 'state' in row, 'transfer_lineage_mismatch')
            allocations.add((row['allocation'], *identity))
        if kind == 'task_event':
            evidence.require({'allocation', 'task', 'state', 'event_type', 'event_time', 'relation'} <= set(row)
                             and (row['allocation'], *identity) in allocations, 'transfer_lineage_mismatch')
    projection = evidence.Projection(evidence.encoded(data), repo, bundle['issue'], True)
    body = publication.render(projection, evidence.encoded(bundle['result']))
    envelope = publication.Publication(repo, bundle['issue'], 'investigation-' + projection.sha256, body)
    evidence.require(bundle['binding'] == outbox.binding(envelope), 'publication_binding_changed')
    return projection, envelope


def export_bundle(cfg, incident, run, *, now=None):
    now = time.time() if now is None else now
    projection = evidence.read_evidence(cfg.factory, incident, run, now=now)
    evidence.require(projection.repository == cfg.repo and projection.deliverable and projection.issue is not None,
                     'publication_destination_unavailable')
    incident_row = evidence.read_incident(cfg.factory, incident)
    with evidence.directory(cfg.factory) as fd:
        committed = evidence.durable_run(fd, run, incident_row['target'], projection.data()['ticket'], time.monotonic() + 5)
    with model._store(cfg.factory, incident, run) as (fd, name):
        state = model._read(fd, name)
    evidence.require(state is not None and state.get('state') == 'complete'
                     and state.get('repository') == cfg.repo and state.get('incident') == incident
                     and state.get('run') == run and state.get('projection_sha256') == projection.sha256, 'result_unavailable')
    envelope = model.prepare(cfg, incident, run, now=now)
    jobs = [{'job': evidence.alias('job', jid), 'namespace': evidence.alias('namespace', ns), 'version': version}
            for jid, ns, region, version in evidence.jobs_for(committed)]
    bundle = {'version': 1, 'repository': cfg.repo, 'incident': incident, 'run': run,
              'target': committed['target'], 'ticket': committed['ticket'], 'commit': committed['commit'],
              'started_at': committed['started_at'], 'completed_at': committed['completed_at'],
              'exported_at': evidence.utc(now), 'issue': projection.issue, 'jobs': jobs,
              'projection': projection.data(), 'result': state['result'], 'binding': outbox.binding(envelope)}
    bundle['sha256'] = evidence.digest(evidence.encoded(bundle))
    validate(bundle, now=now)
    return bundle


def prepare_bundle(bundle, policy, *, now=None):
    projection, envelope = validate(bundle, now=now)
    evidence.require(envelope.repository == policy['app']['repository'], 'transfer_identity_mismatch')
    if bundle['result']['outcome'] == 'proposal':
        scope.prepare_from_policy(Path(policy['repository_root']), projection, evidence.encoded(bundle['result']), policy['scope_file'])
    return envelope


@contextmanager
def import_lock(policy):
    with evidence.directory(Path(policy['state'])) as fd:
        lock = os.open('import.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
        try:
            evidence.require(stat.S_ISREG(os.fstat(lock).st_mode), "unsafe_file_type")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(lock)


def import_bundle(policy, path, *, now=None):
    bundle = read_bundle(path)
    prepare_bundle(bundle, policy, now=now)
    snapshots = Path(policy['snapshots'])
    with import_lock(policy):
        stage = Path(tempfile.mkdtemp(prefix='.stage-', dir=snapshots))
        try:
            with evidence.directory(stage) as fd:
                model._write(fd, 'bundle.json', bundle)
            destination = snapshots / bundle['sha256']
            if destination.exists():
                evidence.require(read_bundle(destination / 'bundle.json') == bundle, 'transfer_hash_mismatch')
                shutil.rmtree(stage)
            else:
                os.rename(stage, destination)
            with evidence.directory(snapshots) as fd:
                model._write(fd, key(bundle['repository'], bundle['incident'], bundle['run']) + '.json', {'version': 1, 'bundle': bundle['sha256']})
            with evidence.directory(Path(policy['state'])) as fd:
                model._write(fd, 'import-result.json', {'version': 1, 'result': 'imported', 'at': evidence.utc(time.time() if now is None else now)})
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    return {'state': 'imported', 'sha256': bundle['sha256']}


def load_imported(policy, incident, run, *, now=None):
    from .publisher_credentials import protected_read
    name = key(policy['app']['repository'], incident, run)
    pointer = json.loads(protected_read(Path(policy['snapshots']) / (name + '.json')), object_pairs_hook=evidence.unique_pairs)
    evidence.require(isinstance(pointer, dict) and set(pointer) == {'version', 'bundle'} and pointer['version'] == 1
                     and isinstance(pointer['bundle'], str) and HEX.fullmatch(pointer['bundle']), 'transfer_invalid')
    path = Path(policy['snapshots']) / pointer['bundle'] / 'bundle.json'
    bundle = read_bundle(path)
    evidence.require(bundle.get('incident') == incident and bundle.get('run') == run
                     and bundle.get('sha256') == pointer['bundle'], 'transfer_identity_mismatch')
    return prepare_bundle(bundle, policy, now=now)


def main(argv):
    parser = argparse.ArgumentParser(prog='factory investigation-export')
    parser.add_argument('--incident', required=True)
    parser.add_argument('--run', required=True)
    parser.add_argument('--staging-dir', required=True)
    args = parser.parse_args(argv)
    try:
        cfg = config.load()
        bundle = export_bundle(cfg, args.incident, args.run)
        with evidence.directory(Path(args.staging_dir).absolute()) as fd:
            name = key(cfg.repo, args.incident, args.run) + '.json'
            model._write(fd, name, bundle)
            os.chmod(name, 0o640, dir_fd=fd, follow_symlinks=False)
        print(json.dumps({'state': 'exported', 'file': name, 'sha256': bundle['sha256']}))
        return 0
    except Exception:
        print(json.dumps({'ok': False, 'code': 'transfer_unavailable'}))
        return 1
