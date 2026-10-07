"""Publisher broker boundary; no real credentials, network or host config."""
from contextlib import contextmanager, redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from factory import config, investigation_broker as broker, investigation_evidence as evidence
from factory import investigation_outbox as outbox, investigation_model as model
from factory.investigation_publisher import PublisherRefused
from tests.test_publisher_credentials import APP

REAL_STORE, REAL_READ, REAL_DELIVER = outbox.store, outbox.read, outbox.deliver


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.entry = self.root / 'row'
        self.entry.write_text('{}')
        self.entry.chmod(0o600)

    def test_regular_store(self):
        broker.protected_store(self.root)

    def test_symlink_refused(self):
        (self.root / 'link').symlink_to(self.entry)
        with self.assertRaises(PublisherRefused):
            broker.protected_store(self.root)

    def test_fifo_refused(self):
        os.mkfifo(self.root / 'fifo')
        with self.assertRaises(PublisherRefused):
            broker.protected_store(self.root)

    def test_device_refused(self):
        actual = os.stat
        def device(path, *args, **kwargs):
            meta = actual(path, *args, **kwargs)
            if path == 'row':
                return SimpleNamespace(st_uid=meta.st_uid, st_mode=stat.S_IFCHR | 0o600)
            return meta
        with mock.patch.object(os, 'stat', side_effect=device), self.assertRaises(PublisherRefused):
            broker.protected_store(self.root)

    def test_foreign_owner_refused(self):
        actual = os.stat
        def foreign(path, *args, **kwargs):
            meta = actual(path, *args, **kwargs)
            if path == 'row':
                return SimpleNamespace(st_uid=os.geteuid() + 10000, st_mode=meta.st_mode)
            return meta
        with mock.patch.object(os, 'stat', side_effect=foreign), self.assertRaises(PublisherRefused):
            broker.protected_store(self.root)

    def test_group_or_other_writes_refused(self):
        for mode in (0o620, 0o602):
            self.entry.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(PublisherRefused):
                broker.protected_store(self.root)

    def test_entry_cap(self):
        with mock.patch.object(os, 'listdir', return_value=['row'] * 10001), self.assertRaises(PublisherRefused):
            broker.protected_store(self.root)

    def test_time_cap(self):
        with mock.patch.object(broker.time, 'monotonic', side_effect=[0, 3]), self.assertRaises(PublisherRefused):
            broker.protected_store(self.root)

    def test_nested_directory_is_scanned(self):
        (self.root / 'nested').mkdir()
        (self.root / 'nested' / 'link').symlink_to(self.entry)
        with self.assertRaises(PublisherRefused):
            broker.protected_store(self.root)


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.policy = {'version': 1, 'publisher_uid': 1001, 'store': '/protected/store',
                       'enabled': True, 'allow_publish': True, 'app': copy.deepcopy(APP)}
        self.request = {'incident': 'incident-' + 'a' * 24, 'run': 'deploy-test-01234567-1'}
        self.row = {'repo': APP['repository'], **self.request, 'issue': 101,
                    'key': 'investigation-' + 'b' * 64, 'body_sha256': 'c' * 64,
                    'state': 'queued', 'code': 'prepared'}
        self.tokens = mock.patch.object(broker, 'AppTokens').start()
        self.addCleanup(mock.patch.stopall)
        self.tokens.return_value.get.return_value = 'synthetic-token'
        self.tokens.return_value.status.return_value = {'outcome': 'ready'}
        @contextmanager
        def store(*args):
            yield 1, 'receipt.json'
        mock.patch.object(outbox, 'store', side_effect=store).start()
        mock.patch.object(outbox, 'read', side_effect=lambda *args: self.row).start()
        mock.patch.object(outbox, 'enqueue', side_effect=lambda *args: self.row).start()
        self.prepare = mock.patch.object(model, 'prepare', return_value=SimpleNamespace(
            repository=APP['repository'], issue=101, idempotency_key=self.row['key'], body='fixed body')).start()
        mock.patch.object(outbox, 'binding', return_value={k: self.row[k] for k in ('repo', 'issue', 'key', 'body_sha256')}).start()
        self.client = mock.patch.object(broker.publisher, 'Publisher').start()
        self.deliver = mock.patch.object(outbox, 'deliver', return_value={**self.row, 'state': 'delivered', 'code': 'reconciled'}).start()

    def test_bad_request_shapes(self):
        for request in ({}, {**self.request, 'body': 'private'}, {**self.request, 'incident': None},
                        {**self.request, 'run': '../private'}, {**self.request, 'incident': 'invalid'}):
            with self.subTest(request=request), self.assertRaises(PublisherRefused):
                broker.handle(self.policy, request, send=True)
        self.tokens.assert_not_called()

    def test_both_switches_required(self):
        for enabled, allow in ((False, False), (False, True), (True, False)):
            self.policy.update(enabled=enabled, allow_publish=allow)
            with self.subTest(enabled=enabled, allow=allow), self.assertRaises(PublisherRefused):
                broker.handle(self.policy, self.request, send=True)
        self.tokens.assert_not_called()

    def test_terminal_states_do_not_mint(self):
        for state in ('delivered', 'failed', 'blocked'):
            self.row['state'] = state
            result = broker.handle(self.policy, self.request, send=True)
            self.assertEqual(result['state'], state)
        self.tokens.assert_not_called()
        self.prepare.assert_not_called()

    def test_uncertain_row_reconciles_without_fresh_prepare(self):
        self.row['state'] = 'uncertain'
        result = broker.handle(self.policy, self.request, send=True)
        self.assertEqual(result['code'], 'reconciled')
        self.prepare.assert_not_called()
        self.deliver.assert_called_once()

    def test_uncertain_reconciliation_with_real_outbox_no_post(self):
        with tempfile.TemporaryDirectory() as directory:
            factory = Path(directory)
            self.policy['store'] = str(factory)
            cfg = SimpleNamespace(factory=factory, repo=APP['repository'])
            row = {**self.row, 'version': 1, 'state': 'uncertain', 'code': 'post_outcome_unknown',
                   'body_sha256': evidence.digest(b'fixed body'), 'publisher_login': APP['login']}
            with REAL_STORE(cfg, self.request['incident'], self.request['run']) as (fd, name):
                model._write(fd, name, row)
                marker = '<!-- factory-investigation-publication: ' + name[:-5] + ' -->\n'
            self.client.return_value.api.return_value = [
                {'id': 123, 'body': marker + 'fixed body', 'user': {'login': APP['login']}}]
            self.prepare.side_effect = AssertionError('uncertain path must not read fresh evidence')
            with mock.patch.object(outbox, 'store', REAL_STORE), mock.patch.object(outbox, 'read', REAL_READ), \
                    mock.patch.object(outbox, 'deliver', REAL_DELIVER):
                result = broker.handle(self.policy, self.request, send=True)
            self.assertEqual(result['state'], 'delivered')
            self.assertEqual(result['code'], 'reconciled')
            for call in self.client.return_value.api.call_args_list:
                self.assertEqual(len(call.args), 1)  # no POST payload

    def test_queued_validates_before_mint(self):
        self.prepare.side_effect = evidence.EvidenceRefused('stale_evidence')
        with self.assertRaises(evidence.EvidenceRefused):
            broker.handle(self.policy, self.request, send=True)
        self.tokens.assert_not_called()

    def test_changed_binding_prevents_mint(self):
        with mock.patch.object(outbox, 'binding', return_value={'issue': 999}):
            with self.assertRaises(evidence.EvidenceRefused):
                broker.handle(self.policy, self.request, send=True)
        self.tokens.assert_not_called()

    def test_preview_no_token_or_shared_config(self):
        with mock.patch.object(config, 'load', side_effect=AssertionError('shared config')):
            result = broker.handle(self.policy, self.request)
        self.assertFalse(result['public_write'])
        self.tokens.assert_not_called()

    def test_cli_send_requires_confirmation(self):
        with mock.patch.object(broker, 'load_policy') as load, redirect_stdout(io.StringIO()) as output:
            result = broker.main(['--policy', '/policy', '--send'])
        self.assertEqual(result, 1)
        load.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['code'], 'public_write_confirmation_required')

    def test_cli_fixed_error_allowlist_and_unknown(self):
        for error, code in ((PublisherRefused('publisher_disabled'), 'publisher_disabled'),
                            (evidence.EvidenceRefused('stale_evidence'), 'stale_evidence'),
                            (PublisherRefused('private-provider-text'), 'publisher_unavailable'),
                            (OSError('private-provider-text'), 'publisher_unavailable')):
            with mock.patch.object(broker, 'load_policy', side_effect=error), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(broker.main(['--policy', '/policy']), 1)
            self.assertEqual(json.loads(output.getvalue())['code'], code)
            self.assertNotIn('private-provider-text', output.getvalue())

    def test_status_never_claims_cached_token(self):
        status = {'version': 1, 'outcome': 'ready', 'expires_at': 2000000000,
                  'requests': 3, 'max_requests': 3, 'valid': True}
        with mock.patch.object(broker, 'load_policy', return_value=self.policy), \
                mock.patch.object(broker, 'protected_read', return_value=json.dumps(status).encode()), \
                redirect_stdout(io.StringIO()) as output:
            self.assertEqual(broker.main(['--policy', '/policy', '--status']), 0)
        result = json.loads(output.getvalue())
        self.assertFalse(result['valid'])
        self.assertFalse(result['token_persisted'])
        self.tokens.assert_not_called()

    def test_policy_uid_sentinel_schema(self):
        for patch in ({'extra': True}, {'publisher_uid': 0}, {'publisher_uid': 999}, {'enabled': 1}):
            with mock.patch.object(broker, 'protected_read', return_value=json.dumps({**self.policy, **patch}).encode()), \
                    mock.patch.object(os, 'geteuid', return_value=1001), self.assertRaises(PublisherRefused):
                broker.load_policy('/policy')
        policy = {k: v for k, v in self.policy.items() if k != 'store'}
        policy.update(version=2, snapshots='/protected/snapshots', state='/protected/state',
                      status_file='/protected/status/status.json', repository_root='/protected/repo', scope_file='/protected/scope.json')
        reads = [json.dumps(policy).encode()] + [evidence.encoded({'version': 1, 'repository': APP['repository']})] * 2
        with mock.patch.object(broker, 'protected_read', side_effect=reads), \
                mock.patch.object(os, 'geteuid', return_value=1001), mock.patch.object(broker, 'protected_store'):
            self.assertEqual(broker.load_policy('/policy')['state'], policy['state'])
