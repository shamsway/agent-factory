"""Dedicated App credentials: synthetic keys and fake HTTP only."""
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
from contextlib import redirect_stdout

from factory import investigation_evidence as evidence
from factory import publisher_credentials as credentials
from factory.investigation_publisher import PublisherRefused

NOW = 1800000000
APP = {'app_id': 10, 'installation_id': 20, 'repository_id': 30,
       'repository': 'owner/repo', 'login': 'findings[bot]', 'key_file': '/not-a-live-key'}
PERMISSIONS = {'issues': 'write', 'metadata': 'read'}


class ProtectedReadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'policy.json'
        self.path.write_bytes(b'synthetic')
        self.path.chmod(0o400)

    def test_regular_private_file(self):
        self.assertEqual(credentials.protected_read(self.path, secret=True), b'synthetic')

    def test_relative_and_parent_paths(self):
        for path in ('relative', self.root / '..' / 'policy.json'):
            with self.subTest(path=str(path)), self.assertRaises(PublisherRefused):
                credentials.protected_read(path)

    def test_final_symlink(self):
        link = self.root / 'link'
        link.symlink_to(self.path)
        with self.assertRaises((PublisherRefused, evidence.EvidenceRefused, OSError)):
            credentials.protected_read(link)

    def test_ancestor_symlink(self):
        link = self.root / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises((PublisherRefused, evidence.EvidenceRefused, OSError)):
            credentials.protected_read(link / self.path.name)

    def test_writable_ancestor(self):
        for mode in (0o720, 0o702):
            self.root.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(PublisherRefused):
                credentials.protected_read(self.path)
        self.root.chmod(0o700)

    def test_foreign_owner_on_ancestor_or_file(self):
        original = os.fstat
        for inode in (self.root.stat().st_ino, self.path.stat().st_ino):
            def foreign(fd):
                meta = original(fd)
                if meta.st_ino == inode:
                    return SimpleNamespace(st_uid=os.geteuid() + 10000, st_mode=meta.st_mode)
                return meta
            with self.subTest(inode=inode), mock.patch.object(os, 'fstat', side_effect=foreign):
                with self.assertRaises(PublisherRefused):
                    credentials.protected_read(self.path)

    def systemd_layout(self, mode=0o440, gid=0):
        original = os.fstat
        directory_inode = self.root.stat().st_ino
        file_inode = self.path.stat().st_ino
        def layout(fd):
            meta = original(fd)
            if meta.st_ino == directory_inode:
                return SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o550)
            if meta.st_ino == file_inode:
                return SimpleNamespace(st_uid=0, st_gid=gid, st_mode=stat.S_IFREG | mode)
            return meta
        return mock.patch.object(os, 'fstat', side_effect=layout)

    def test_systemd_root_group_credential_layout(self):
        for mode in (0o440, 0o400):
            with self.subTest(mode=oct(mode)), self.systemd_layout(mode):
                self.assertEqual(credentials.protected_read(self.path, secret=True), b'synthetic')

    def test_secret_refuses_unsafe_modes_and_group(self):
        for mode, gid in ((0o640, 992), (0o440, 992), (0o444, 0), (0o460, 0),
                          (0o600, 0), (0o420, 0), (0o401, 0), (0o410, 0)):
            with self.subTest(mode=oct(mode), gid=gid), self.systemd_layout(mode, gid):
                with self.assertRaises(PublisherRefused):
                    credentials.protected_read(self.path, secret=True)

    def test_real_checker_reads_and_parses_systemd_layout(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from factory import publisher_key_check
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.path.chmod(0o600)
        self.path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.path.rename(self.root / 'app-key')
        self.path = self.root / 'app-key'
        with self.systemd_layout(), mock.patch.dict(os.environ, CREDENTIALS_DIRECTORY=str(self.root)):
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(publisher_key_check.main(), 0)
        self.assertEqual(json.loads(output.getvalue()), {'key_loadable': True, 'type': 'rsa', 'bits': 2048})

    def test_real_checker_rejects_bad_pem_without_error_text(self):
        from factory import publisher_key_check
        self.path.rename(self.root / 'app-key')
        self.path = self.root / 'app-key'
        with self.systemd_layout(), mock.patch.dict(os.environ, CREDENTIALS_DIRECTORY=str(self.root)):
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(publisher_key_check.main(), 1)
        self.assertEqual(json.loads(output.getvalue()), {'key_loadable': False, 'type': None, 'bits': None})
        self.assertNotIn('synthetic', output.getvalue())

    def test_writable_policy_and_oversize(self):
        self.path.chmod(0o620)
        with self.assertRaises(PublisherRefused):
            credentials.protected_read(self.path)
        self.path.chmod(0o400)
        with self.assertRaises(PublisherRefused):
            credentials.protected_read(self.path, maximum=3)

    def test_fifo_not_read(self):
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaises(evidence.EvidenceRefused):
            credentials.protected_read(fifo)


class AppTokenTests(unittest.TestCase):
    def setUp(self):
        self.app = {'id': 10, 'slug': 'findings'}
        self.installation = {'app_id': 10, 'permissions': dict(PERMISSIONS),
                             'suspended_at': None, 'account': {'login': 'owner'}}
        self.response = {'token': 'synthetic-token', 'expires_at': evidence.utc(NOW + 3600),
                         'permissions': dict(PERMISSIONS),
                         'repositories': [{'id': 30, 'full_name': 'owner/repo'}]}
        self.calls, self.audit = [], []
        self.jwt_patch = mock.patch.object(credentials, 'jwt', return_value='synthetic-jwt')
        self.jwt_patch.start()
        self.addCleanup(self.jwt_patch.stop)
        self.client = credentials.AppTokens(APP, wire_fn=self.wire, clock=lambda: NOW,
                                           audit=lambda row: self.audit.append(copy.deepcopy(row)))

    def wire(self, request):
        self.assertEqual(self.audit[-1]['outcome'], 'request_reserved')
        self.assertEqual(self.audit[-1]['requests'], len(self.calls) + 1)
        self.calls.append(request)
        body = self.app if request['endpoint'] == 'app' else (
            self.response if request['method'] == 'POST' else self.installation)
        return {'status': 'ok', 'body': json.dumps(body)}

    def refused(self):
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(PublisherRefused) as error:
            self.client.get()
        self.assertEqual(str(error.exception), 'publisher_token_unavailable')
        self.assertEqual(output.getvalue(), '')
        text = json.dumps(self.audit) + str(error.exception)
        self.assertNotIn('synthetic-token', text)
        self.assertNotIn('synthetic-jwt', text)
        self.assertFalse(self.client.status()['valid'])

    def test_success_audit_before_network_and_cache(self):
        self.assertEqual(self.client.get(), 'synthetic-token')
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(self.calls[-1]['payload'], {'repository_ids': [30], 'permissions': PERMISSIONS})
        self.assertEqual(self.client.get(), 'synthetic-token')
        self.assertEqual(len(self.calls), 3)
        self.assertNotIn('synthetic-token', json.dumps(self.audit))
        self.assertNotIn('synthetic-jwt', json.dumps(self.audit))

    def test_wrong_app_id(self):
        self.app['id'] = 11
        self.refused()
        self.assertEqual(len(self.calls), 1)

    def test_wrong_app_slug(self):
        self.app['slug'] = 'other'
        self.refused()

    def test_wrong_installation_permissions(self):
        self.installation['permissions']['contents'] = 'read'
        self.refused()

    def test_suspended_installation(self):
        self.installation['suspended_at'] = evidence.utc(NOW)
        self.refused()

    def test_wrong_installation_account(self):
        self.installation['account']['login'] = 'other'
        self.refused()

    def test_wrong_installation_app(self):
        self.installation['app_id'] = 11
        self.refused()

    def test_wrong_token_repositories(self):
        self.response['repositories'].append({'id': 31, 'full_name': 'owner/other'})
        self.refused()

    def test_wrong_token_repository_id(self):
        self.response['repositories'][0]['id'] = 31
        self.refused()

    def test_wrong_token_repository_name(self):
        self.response['repositories'][0]['full_name'] = 'owner/other'
        self.refused()

    def test_wrong_token_permissions(self):
        self.response['permissions']['issues'] = 'read'
        self.refused()

    def test_expiry_bounds(self):
        for delta in (-1, 0, 60, 3661):
            self.response['expires_at'] = evidence.utc(NOW + delta)
            self.client = credentials.AppTokens(APP, wire_fn=self.wire, clock=lambda: NOW,
                                               audit=lambda row: self.audit.append(copy.deepcopy(row)))
            self.calls.clear()
            with self.subTest(delta=delta):
                self.refused()

    def test_bad_token_shape(self):
        for value in ('', 'token\nprivate', None, 'x' * 4097):
            self.response['token'] = value
            self.calls.clear()
            self.client = credentials.AppTokens(APP, wire_fn=self.wire, clock=lambda: NOW,
                                               audit=lambda row: self.audit.append(copy.deepcopy(row)))
            with self.subTest(value_type=type(value).__name__):
                self.refused()

    def test_three_request_lifetime_budget_no_refresh(self):
        self.client.get()
        self.client.clock = lambda: NOW + 3541
        self.refused()
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(self.client.requests, 3)

    def test_unknown_http_no_automatic_retry(self):
        self.client.wire_fn = lambda request: {'status': 'unknown'}
        self.refused()
        self.assertEqual(self.client.requests, 1)

    def test_audit_failure_prevents_network(self):
        self.client.audit = mock.Mock(side_effect=OSError('synthetic-private-text'))
        with self.assertRaises(PublisherRefused) as error:
            self.client.get()
        self.assertEqual(str(error.exception), 'publisher_token_unavailable')
        self.assertEqual(self.calls, [])

    def test_cryptography_missing_fixed_refusal(self):
        self.jwt_patch.stop()
        with mock.patch.dict('sys.modules', {'cryptography': None}):
            self.refused()
        self.assertEqual(self.calls, [])

    def test_policy_closed_shape(self):
        for patch in ({'app_id': True}, {'installation_id': 0}, {'repository_id': -1},
                      {'repository': 'bad'}, {'login': 'human'}, {'key_file': 'relative'}, {'extra': 1}):
            with self.subTest(patch=patch), self.assertRaises(PublisherRefused):
                credentials.app_policy({**APP, **patch})

    def test_rs256_claims_and_signature_without_key_persistence(self):
        self.jwt_patch.stop()
        import base64
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        with mock.patch.object(credentials, 'protected_read', return_value=pem):
            value = credentials.jwt(APP, now=NOW)
        header, claims, signature = value.split('.')
        decode = lambda value: base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
        self.assertEqual(json.loads(decode(header)), {'alg': 'RS256', 'typ': 'JWT'})
        self.assertEqual(json.loads(decode(claims)), {'iat': NOW - 60, 'exp': NOW + 540, 'iss': '10'})
        key.public_key().verify(decode(signature), (header + '.' + claims).encode(), padding.PKCS1v15(), hashes.SHA256())


    def test_invalid_pem_and_non_rsa_key_refused(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        self.jwt_patch.stop()
        keys = [b'not a PEM',
                ec.generate_private_key(ec.SECP256R1()).private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
                rsa.generate_private_key(public_exponent=65537, key_size=1024).private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())]
        for pem in keys:
            with mock.patch.object(credentials, 'protected_read', return_value=pem):
                self.refused()
        self.assertEqual(self.calls, [])

    def test_response_shape_and_duplicate_keys_refused(self):
        for body in ('[]', '{"id":10,"id":11}', 'not-json'):
            self.client = credentials.AppTokens(APP, wire_fn=lambda request: {'status': 'ok', 'body': body},
                                               clock=lambda: NOW, audit=self.audit.append)
            with self.subTest(body_shape=body[:1]):
                self.refused()
