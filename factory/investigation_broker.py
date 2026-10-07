"""One-shot publisher-account broker. No listener, shared host config, or tools.

Operator invokes a reviewed incident/run from protected broker-owned snapshots.
Provisioning is operator-only. Import cannot replace durable publication state.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import time
from types import SimpleNamespace

from . import investigation_evidence as evidence, investigation_model as model
from . import investigation_outbox as outbox, investigation_publisher as publisher
from .publisher_credentials import AppTokens, app_policy, protected_read
from .investigation_publication import REFUSALS as EVIDENCE_FAILURE_CODES


def protected_store(path):
    """Reject snapshots containing worker-owned/writable files, links or devices."""
    deadline = time.monotonic() + 2
    remaining = 10000
    def scan(fd):
        nonlocal remaining
        for name in os.listdir(fd):
            remaining -= 1
            if remaining < 0 or time.monotonic() > deadline:
                raise publisher.PublisherRefused('publisher_store_unavailable')
            meta = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if meta.st_uid not in {0, os.geteuid()} or meta.st_mode & 0o022:
                raise publisher.PublisherRefused('publisher_store_unavailable')
            if stat.S_ISDIR(meta.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    scan(child)
                finally:
                    os.close(child)
            elif not stat.S_ISREG(meta.st_mode):
                raise publisher.PublisherRefused('publisher_store_unavailable')
    with evidence.directory(Path(path)) as fd:
        scan(fd)


def load_policy(path):
    raw = json.loads(protected_read(path), object_pairs_hook=evidence.unique_pairs)
    expected = {'version', 'publisher_uid', 'snapshots', 'state', 'status_file', 'repository_root', 'scope_file', 'enabled', 'allow_publish', 'app'}
    if (not isinstance(raw, dict) or set(raw) != expected or type(raw['version']) is not int
            or raw['version'] != 2 or type(raw['publisher_uid']) is not int
            or raw['publisher_uid'] <= 0 or raw['publisher_uid'] != os.geteuid()
            or type(raw['enabled']) is not bool or type(raw['allow_publish']) is not bool
            or any(not isinstance(raw[k], str) or not Path(raw[k]).is_absolute() or '..' in Path(raw[k]).parts
                   for k in ('snapshots', 'state', 'status_file', 'repository_root', 'scope_file'))):
        raise publisher.PublisherRefused('publisher_policy_invalid')
    raw['app'] = app_policy(raw['app'])
    snapshots, state = Path(raw['snapshots']), Path(raw['state'])
    if snapshots == state or snapshots in state.parents or state in snapshots.parents:
        raise publisher.PublisherRefused('publisher_policy_invalid')
    for name in ('snapshots', 'state'):
        if protected_read(Path(raw[name]) / 'broker-store.json') != evidence.encoded(
                {'version': 1, 'repository': raw['app']['repository']}):
            raise publisher.PublisherRefused('publisher_policy_invalid')
        protected_store(raw[name])
    return raw


def handle(policy, request, *, send=False, wire_fn=None):
    if (not isinstance(request, dict) or set(request) != {'incident', 'run'}
            or not isinstance(request['incident'], str)
            or not re.fullmatch(r'incident-[0-9a-f]{24}', request['incident'])
            or not isinstance(request['run'], str)
            or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', request['run'])):
        raise publisher.PublisherRefused('publisher_request_invalid')
    p = policy['app']
    cfg = SimpleNamespace(factory=Path(policy.get('snapshots', policy.get('store', ''))), repo=p['repository'])
    if policy.get('version') == 2:
        from . import investigation_transfer as transfer
        cfg.publication_store = Path(policy['state'])
        cfg.prepare_publication = lambda cfg, incident, run, now=None: transfer.load_imported(policy, incident, run, now=now)
    if not send:
        envelope = outbox.prepare_envelope(cfg, request['incident'], request['run'])
        if policy.get('version') == 2:
            from . import investigation_transfer as transfer
            with evidence.directory(cfg.publication_store) as fd:
                model._write(fd, 'preview-' + transfer.key(cfg.repo, request['incident'], request['run']) + '.json',
                             outbox.binding(envelope))
        marker = '<!-- factory-investigation-publication: ' + evidence.digest(
            (cfg.repo + '\0' + request['incident'] + '\0' + request['run']).encode()) + ' -->\n'
        return {'repository': envelope.repository, 'issue': envelope.issue, 'body': marker + envelope.body,
                'public_write': False}
    if not (policy['enabled'] and policy['allow_publish']):
        raise publisher.PublisherRefused('publisher_disabled')
    # Terminal/reconciliation paths need no fresh evidence. Queued rows do.
    with outbox.store(cfg, request['incident'], request['run']) as (fd, name):
        row = outbox.read(fd, name)
    if row is None and policy.get('version') == 2:
        from . import investigation_transfer as transfer
        envelope = outbox.prepare_envelope(cfg, request['incident'], request['run'])
        preview_path = cfg.publication_store / ('preview-' + transfer.key(cfg.repo, request['incident'], request['run']) + '.json')
        preview = json.loads(protected_read(preview_path), object_pairs_hook=evidence.unique_pairs)
        evidence.require(preview == outbox.binding(envelope), 'preview_changed')
    if row is None:
        row = outbox.enqueue(cfg, request['incident'], request['run'])
    evidence.require(row.get('repo') == cfg.repo and row.get('incident') == request['incident']
                     and row.get('run') == request['run'], 'invalid_publication_destination')
    if row['state'] in {'delivered', 'failed', 'blocked'}:
        return {'state': row['state'], 'code': row['code'], 'token': {'outcome': 'not_requested'}}
    if row['state'] == 'queued':
        envelope = outbox.prepare_envelope(cfg, request['incident'], request['run'])
        expected = outbox.binding(envelope)
        if policy.get('version') == 2:
            from . import investigation_transfer as transfer
            preview = json.loads(protected_read(cfg.publication_store / ('preview-' + transfer.key(cfg.repo,
                request['incident'], request['run']) + '.json')), object_pairs_hook=evidence.unique_pairs)
            evidence.require(preview == expected, 'preview_changed')
        evidence.require(set(expected) == {'repo', 'issue', 'key', 'body_sha256'}
                         and all(row.get(key) == value for key, value in expected.items()),
                         'publication_binding_changed')
    def audit(status):
        with evidence.directory(getattr(cfg, "publication_store", cfg.factory)) as fd:
            model._write(fd, 'publisher-token-status.json', {'version': 1, **status})
    tokens = AppTokens(p, wire_fn=wire_fn, audit=audit)
    cfg.publisher = {'enabled': True, 'allow_publish': True, 'key': tokens.get(),
                     'login': p['login'], 'kind': 'installation_token'}
    cfg.install = {'env': {}}
    cfg.apply_env, cfg.llm_key, cfg.investigation = {}, '', {}
    client = publisher.Publisher(cfg, wire_fn=wire_fn)
    client.verify()
    row = outbox.deliver(cfg, request['incident'], request['run'], publisher=client,
                         publisher_login=p['login'])
    return {'state': row['state'], 'code': row['code'], 'token': tokens.status()}



# Closed public metadata only; exception text is never accepted as a provider message.
FAILURE_CODES = frozenset({
    'publisher_policy_invalid', 'publisher_request_invalid', 'publisher_store_unavailable',
    'publisher_disabled', 'public_write_confirmation_required', 'publisher_token_unavailable',
    'publisher_key_invalid', 'publisher_identity_unverified', 'publisher_token_scope_invalid',
    'publisher_credential_invalid', 'publisher_endpoint_refused', 'publisher_budget',
    'publisher_outcome_unknown', 'publisher_response_invalid', 'publication_binding_changed',
    'invalid_publication_destination', 'publication_destination_unavailable',
    'invalid_reference', 'unsafe_path', 'unsafe_or_missing_file', 'unsafe_file_type',
    'invalid_evidence', 'stale_evidence', 'partial_evidence', 'incident_identity_mismatch',
    'incident_run_mismatch', 'result_unavailable', 'model_retry_pending', 'model_state_unavailable',
    'scope_mapping_unavailable', 'scope_revision_mismatch', 'unsupported_scope',
    'preview_changed', 'transfer_invalid', 'transfer_budget', 'transfer_hash_mismatch',
    'transfer_identity_mismatch', 'transfer_window_mismatch', 'transfer_lineage_mismatch',
}) | EVIDENCE_FAILURE_CODES


def main(argv):
    parser = argparse.ArgumentParser(prog='factory investigation-broker')
    parser.add_argument('--policy', required=True)
    parser.add_argument('--incident')
    parser.add_argument('--run')
    parser.add_argument('--status', action='store_true')
    parser.add_argument('--import-bundle')
    parser.add_argument('--verify-token', action='store_true')
    parser.add_argument('--send', action='store_true')
    parser.add_argument('--confirm-public-write', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.send and not args.confirm_public_write:
            raise publisher.PublisherRefused('public_write_confirmation_required')
        policy = load_policy(args.policy)
        if args.import_bundle:
            if args.send or args.status or args.incident or args.run or args.verify_token:
                raise publisher.PublisherRefused('publisher_request_invalid')
            from . import investigation_transfer as transfer, publisher_status
            try:
                result = transfer.import_bundle(policy, args.import_bundle)
            except Exception:
                with evidence.directory(Path(policy['state'])) as fd:
                    model._write(fd, 'import-result.json', {'version': 1, 'result': 'refused', 'at': evidence.utc(time.time())})
                publisher_status.write(policy)
                raise
            publisher_status.write(policy)
            print(json.dumps(result))
            return 0
        if args.verify_token:
            if args.send or args.status or args.incident or args.run:
                raise publisher.PublisherRefused('publisher_request_invalid')
            # Explicit separately approved read-only App/token verification; no issue POST.
            def audit(status):
                with evidence.directory(Path(policy['state'])) as fd:
                    model._write(fd, 'publisher-token-status.json', {'version': 1, **status})
            tokens = AppTokens(policy['app'], audit=audit)
            from . import publisher_status
            try:
                credential = tokens.get()
                cfg = SimpleNamespace(repo=policy['app']['repository'], publisher={
                    'key': credential, 'login': policy['app']['login']}, install={'env': {}},
                    apply_env={}, llm_key='', investigation={})
                publisher.Publisher(cfg).verify()
            finally:
                publisher_status.write(policy)
            print(json.dumps({'state': 'read_verified', 'login': policy['app']['login']}))
            return 0
        if args.status:
            if args.send or args.incident or args.run:
                raise publisher.PublisherRefused('publisher_request_invalid')
            if policy.get('version') == 2:
                from . import publisher_status
                print(json.dumps(publisher_status.write(policy)))
                return 0
            path = Path(policy.get('state', policy.get('store', ''))) / 'publisher-token-status.json'
            row = json.loads(protected_read(path), object_pairs_hook=evidence.unique_pairs)
            fields = {'version', 'outcome', 'expires_at', 'requests', 'max_requests', 'valid'}
            if (not isinstance(row, dict) or set(row) != fields or row['version'] != 1
                    or row['outcome'] not in {'request_reserved', 'ready', 'refresh_failed'}
                    or type(row['requests']) is not int or not 0 <= row['requests'] <= 3
                    or row['max_requests'] != 3 or type(row['valid']) is not bool
                    or (row['expires_at'] is not None and not evidence.number(row['expires_at']))):
                raise publisher.PublisherRefused('publisher_policy_invalid')
            # A prior process's in-memory token is gone; don't claim the cached value still exists.
            row['valid'] = False
            row['token_persisted'] = False
            print(json.dumps(row))
            return 0
        try:
            result = handle(policy, {'incident': args.incident, 'run': args.run}, send=args.send)
        finally:
            if policy.get('version') == 2:
                from . import publisher_status
                publisher_status.write(policy)
        print(json.dumps(result))
        return 0 if result.get('state', 'delivered') == 'delivered' else 1
    except (publisher.PublisherRefused, evidence.EvidenceRefused) as error:
        code = str(error)
        print(json.dumps({'ok': False, 'code': code if code in FAILURE_CODES else 'publisher_unavailable'}))
        return 1
    except Exception:
        print(json.dumps({'ok': False, 'code': 'publisher_unavailable'}))
        return 1
