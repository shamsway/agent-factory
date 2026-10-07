"""Option B operator transfer. Synthetic evidence; no network or credentials."""
import copy
import json
import os
from pathlib import Path
import tempfile
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

from factory import investigation_transfer as transfer, publisher_status as status
from factory import investigation_evidence as evidence, investigation_outbox as outbox
from factory import investigation_broker as broker
from tests import test_investigation_model as fixtures

ORIGINAL_SCOPE = transfer.scope.prepare_from_policy
NOW = fixtures.NOW + 2


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ModelTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.call(client=self.fixture.client)
        self.bundle = transfer.export_bundle(self.fixture.cfg, self.fixture.fixture.root_id,
                                             self.fixture.fixture.run.run_id, now=NOW)
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ('snapshots', 'state', 'status'):
            (self.root / directory).mkdir()
            (self.root / directory / 'broker-store.json').write_bytes(evidence.encoded(
                {'version': 1, 'repository': self.bundle['repository']}))
        self.policy = {'version': 2, 'snapshots': str(self.root / 'snapshots'),
                       'state': str(self.root / 'state'), 'status_file': str(self.root / 'status' / 'status.json'),
                       'scope_file': str(self.root / 'scope.json'), 'repository_root': str(self.root / 'repo'),
                       'app': {'repository': self.bundle['repository']}, 'enabled': False, 'allow_publish': False}
        self.path = self.root / 'export.json'
        self.save()
        self.scope = mock.patch.object(transfer.scope, 'prepare_from_policy').start()
        self.addCleanup(mock.patch.stopall)

    def save(self):
        self.bundle['sha256'] = evidence.digest(evidence.encoded({k: v for k, v in self.bundle.items() if k != 'sha256'}))
        self.path.write_bytes(evidence.encoded(self.bundle))

    def test_export_has_no_free_text_key_or_raw_logs(self):
        raw = evidence.encoded(self.bundle)
        self.assertNotIn(fixtures.SECRET.encode(), raw)
        self.assertNotIn(b'dedicated-model-key', raw)
        self.assertEqual(set(self.bundle), transfer.FIELDS)
        self.assertEqual(self.bundle['issue'], 99)

    def test_import_and_load_recheck_scope(self):
        result = transfer.import_bundle(self.policy, self.path, now=NOW)
        self.assertEqual(result['state'], 'imported')
        envelope = transfer.load_imported(self.policy, self.bundle['incident'], self.bundle['run'], now=NOW)
        self.assertEqual(envelope.issue, 99)
        self.assertEqual(self.scope.call_count, 2)
        self.assertEqual(self.scope.call_args.args[0], Path(self.policy['repository_root']))

    def test_real_scope_at_failed_commit_without_provider(self):
        repo = self.root / 'repo'
        repo.mkdir()
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        (repo / 'collector').mkdir()
        (repo / 'collector' / 'main.tf').write_text('# synthetic tracked configuration\n')
        subprocess.run(['git', '-C', str(repo), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Fixture', '-c',
                        'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'], check=True)
        commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
        self.bundle['commit'] = self.bundle['projection']['commit'] = commit
        projection = evidence.Projection(evidence.encoded(self.bundle['projection']),
                                         self.bundle['repository'], self.bundle['issue'], True)
        self.bundle['result']['projection_sha256'] = projection.sha256
        body = transfer.publication.render(projection, evidence.encoded(self.bundle['result']))
        envelope = transfer.publication.Publication(projection.repository, projection.issue,
                                                     'investigation-' + projection.sha256, body)
        self.bundle['binding'] = outbox.binding(envelope)
        job = self.bundle['jobs'][0]
        Path(self.policy['scope_file']).write_bytes(evidence.encoded({'version': 2, 'approved': True,
            'repository': self.bundle['repository'], 'approved_at': commit,
            'bindings': [{'job': job['job'], 'namespace': job['namespace'], 'paths': ['collector/main.tf']}]}))
        self.save()
        self.scope.side_effect = ORIGINAL_SCOPE
        self.assertEqual(transfer.import_bundle(self.policy, self.path, now=NOW)['state'], 'imported')
        self.assertEqual(transfer.load_imported(self.policy, self.bundle['incident'],
                                               self.bundle['run'], now=NOW).issue, 99)

    def test_unknown_field_refused_even_with_new_hash(self):
        self.bundle['private'] = fixtures.SECRET
        self.save()
        with self.assertRaises(evidence.EvidenceRefused):
            transfer.import_bundle(self.policy, self.path, now=NOW)
        self.assertFalse(list((self.root / 'snapshots').glob('.stage-*')))

    def test_tampered_hash_refused(self):
        self.bundle['issue'] += 1
        self.path.write_bytes(evidence.encoded(self.bundle))
        with self.assertRaisesRegex(evidence.EvidenceRefused, 'transfer_hash_mismatch'):
            transfer.import_bundle(self.policy, self.path, now=NOW)

    def test_forged_binding_refused(self):
        self.bundle['issue'] += 1
        self.save()
        with self.assertRaisesRegex(evidence.EvidenceRefused, 'publication_binding_changed'):
            transfer.import_bundle(self.policy, self.path, now=NOW)

    def test_oversize_refused_before_json(self):
        self.path.write_bytes(b' ' * (transfer.MAX_BUNDLE + 1))
        with self.assertRaisesRegex(evidence.EvidenceRefused, 'transfer_budget'):
            transfer.import_bundle(self.policy, self.path, now=NOW)

    def test_symlink_input_refused(self):
        link = self.root / 'link.json'
        link.symlink_to(self.path)
        with self.assertRaises(evidence.EvidenceRefused):
            transfer.import_bundle(self.policy, link, now=NOW)

    def test_unknown_projection_field_refused(self):
        self.bundle['projection']['private'] = 'forged'
        self.save()
        with self.assertRaises(evidence.EvidenceRefused):
            transfer.import_bundle(self.policy, self.path, now=NOW)

    def test_unknown_row_field_refused(self):
        self.bundle['projection']['rows'][0]['instructions'] = fixtures.SECRET
        self.save()
        with self.assertRaises(evidence.EvidenceRefused):
            transfer.import_bundle(self.policy, self.path, now=NOW)

    def test_forged_lineage_refused(self):
        self.bundle['projection']['rows'][0]['version'] = 999
        self.save()
        with self.assertRaisesRegex(evidence.EvidenceRefused, 'transfer_lineage_mismatch'):
            transfer.import_bundle(self.policy, self.path, now=NOW)

    def test_forged_relation_refused(self):
        self.bundle['projection']['rows'][0]['relation'] = 'recorded_health_version'
        self.save()
        with self.assertRaises(evidence.EvidenceRefused):
            transfer.import_bundle(self.policy, self.path, now=NOW)

    def test_forged_window_refused(self):
        self.bundle['completed_at'] = evidence.utc(NOW + 1)
        self.save()
        with self.assertRaises(evidence.EvidenceRefused):
            transfer.import_bundle(self.policy, self.path, now=NOW)

    def test_stale_operator_snapshot_refused(self):
        with self.assertRaises(evidence.EvidenceRefused):
            transfer.import_bundle(self.policy, self.path, now=NOW + transfer.MAX_TRANSFER_AGE + 1)

    def test_missing_observed_fields_refused(self):
        del self.bundle['projection']['rows'][0]['current_version']
        self.save()
        with self.assertRaises(evidence.EvidenceRefused):
            transfer.import_bundle(self.policy, self.path, now=NOW)

    def test_scope_refusal_precedes_persistence(self):
        self.scope.side_effect = evidence.EvidenceRefused('unsupported_scope')
        with self.assertRaises(evidence.EvidenceRefused):
            transfer.import_bundle(self.policy, self.path, now=NOW)
        self.assertEqual(sorted(p.name for p in (self.root / 'snapshots').iterdir()), ['broker-store.json'])

    def test_import_does_not_replace_outbox_locks_or_token_audit(self):
        state = self.root / 'state'
        (state / 'investigation-outbox').mkdir()
        receipt = state / 'investigation-outbox' / 'uncertain.json'
        receipt.write_text('{"state":"uncertain"}')
        audit = state / 'publisher-token-status.json'
        audit.write_text('{"outcome":"request_reserved"}')
        lock = state / 'durable.lock'
        lock.write_bytes(b'lock')
        before = {p: p.read_bytes() for p in (receipt, audit, lock)}
        transfer.import_bundle(self.policy, self.path, now=NOW)
        transfer.import_bundle(self.policy, self.path, now=NOW)
        for path, raw in before.items():
            self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(len(list((self.root / 'snapshots').glob('*/bundle.json'))), 1)

    def test_rename_failure_keeps_pointer_and_outbox(self):
        transfer.import_bundle(self.policy, self.path, now=NOW)
        pointer = self.root / 'snapshots' / (transfer.key(self.bundle['repository'], self.bundle['incident'], self.bundle['run']) + '.json')
        before = pointer.read_bytes()
        self.bundle['exported_at'] = evidence.utc(NOW + 1)
        self.save()
        with mock.patch.object(transfer.os, 'rename', side_effect=OSError), self.assertRaises(evidence.EvidenceRefused):
            transfer.import_bundle(self.policy, self.path, now=NOW + 1)
        self.assertEqual(pointer.read_bytes(), before)
        self.assertFalse(list((self.root / 'snapshots').glob('.stage-*')))

    def test_preview_is_exact_and_required_before_send(self):
        request = {k: self.bundle[k] for k in ('incident', 'run')}
        with mock.patch.object(transfer, 'load_imported', return_value=transfer.validate(self.bundle, now=NOW)[1]), \
                mock.patch.object(broker, 'AppTokens') as tokens:
            preview = broker.handle(self.policy, request)
            self.assertTrue(preview['body'].startswith('<!-- factory-investigation-publication: '))
            tokens.assert_not_called()
            self.policy.update(enabled=True, allow_publish=True)
            receipt = next((self.root / 'state').glob('preview-*.json'))
            receipt.write_text('{}')
            with self.assertRaisesRegex(evidence.EvidenceRefused, 'preview_changed'):
                broker.handle(self.policy, request, send=True)
            tokens.assert_not_called()

    def test_uncertain_receipt_reconciles_after_import_without_fresh_evidence(self):
        from tests.test_investigation_outbox import FakePublisher
        transfer.import_bundle(self.policy, self.path, now=NOW)
        cfg = SimpleNamespace(factory=self.root / 'snapshots', publication_store=self.root / 'state',
                              repo=self.bundle['repository'])
        cfg.prepare_publication = lambda cfg, incident, run, now=None: transfer.load_imported(
            self.policy, incident, run, now=now)
        incident, run = self.bundle['incident'], self.bundle['run']
        outbox.enqueue(cfg, incident, run, now=NOW)
        remote = FakePublisher('lost_response')
        row = outbox.deliver(cfg, incident, run, publisher=remote, publisher_login='publisher-bot', now=NOW)
        self.assertEqual(row['state'], 'uncertain')
        transfer.import_bundle(self.policy, self.path, now=NOW)
        with mock.patch.object(transfer, 'load_imported', side_effect=evidence.EvidenceRefused('stale_evidence')):
            row = outbox.deliver(cfg, incident, run, publisher=remote, publisher_login='publisher-bot', now=NOW + 10000)
        self.assertEqual(row['state'], 'delivered')
        self.assertEqual(remote.posts, 1)

    def test_status_missing_stale_malformed_and_observed(self):
        cfg = SimpleNamespace(repo=self.bundle['repository'], publisher={
            'status_file': self.policy['status_file'], 'status_uid': os.geteuid() or 1001})
        self.assertEqual(status.observe(cfg)['status'], 'missing')
        result = status.write(self.policy)
        at = evidence.timestamp(result['at'])
        self.assertEqual(status.observe(cfg, now=at + 1)['status'], 'observed')
        self.assertEqual(status.observe(cfg, now=at + status.MAX_AGE + 1)['status'], 'stale')
        path = Path(self.policy['status_file'])
        path.write_text('{"unknown":true}')
        self.assertEqual(status.observe(cfg)['status'], 'malformed')

    def test_status_counts_token_and_import_metadata_only(self):
        transfer.import_bundle(self.policy, self.path, now=NOW)
        result = status.write(self.policy)
        self.assertEqual(result['last_import']['result'], 'imported')
        self.assertEqual(result['token']['outcome'], 'not_requested')
        self.assertEqual(set(result['outbox']['states']), status.STATES)
        self.assertNotIn(fixtures.SECRET, json.dumps(result))
        self.assertEqual(Path(self.policy['status_file']).stat().st_mode & 0o777, 0o644)

    def test_status_unknown_fields_refused(self):
        result = status.write(self.policy)
        result['token']['secret'] = fixtures.SECRET
        with self.assertRaises(evidence.EvidenceRefused):
            status.schema(result, self.bundle['repository'])

    def test_nonobserved_row_cannot_carry_observed_fields(self):
        self.bundle['projection']['rows'][0]['status'] = 'unavailable'
        self.save()
        with self.assertRaises(evidence.EvidenceRefused):
            transfer.import_bundle(self.policy, self.path, now=NOW)

    def test_doctor_warns_for_missing_and_stale(self):
        cfg = SimpleNamespace(repo=self.bundle['repository'], publisher={
            'status_file': self.policy['status_file'], 'status_uid': os.geteuid() or 1001})
        reports = []
        report = lambda ok, name, text, **kwargs: reports.append((ok, name, text))
        status.doctor(cfg, report)
        self.assertIn((None, 'publisher status', 'missing'), reports)
        result = status.write(self.policy)
        result['at'] = evidence.utc(1)
        Path(self.policy['status_file']).write_bytes(evidence.encoded(result))
        reports.clear()
        status.doctor(cfg, report)
        self.assertIn((None, 'publisher status', 'stale'), reports)

    def test_status_not_configured(self):
        self.assertEqual(status.observe(SimpleNamespace(publisher={})), {'status': 'not_configured'})

    def test_status_symlink_refused(self):
        cfg = SimpleNamespace(repo=self.bundle['repository'], publisher={
            'status_file': self.policy['status_file'], 'status_uid': os.geteuid() or 1001})
        Path(self.policy['status_file']).symlink_to(self.path)
        self.assertEqual(status.observe(cfg)['status'], 'malformed')


if __name__ == '__main__':
    unittest.main()
