"""Operator ownership regressions, including real chown in the Linux harness."""
import contextlib
import io
import time
from unittest.mock import patch
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

from factory.publisher_credentials import protected_read
from factory.investigation_publisher import PublisherRefused
from factory.investigation_evidence import EvidenceRefused


class ExpectedOwnerTests(unittest.TestCase):
    def test_explicit_owner_and_real_publisher_owned_ancestors(self):
        # scripts/test-linux.sh runs as root: exercise actual different ownership.
        # Ordinary CI also exercises the explicit owner restriction as its own UID.
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary)
            publisher = root / 'publisher'
            publisher.mkdir(mode=0o700)
            uid = 992 if os.geteuid() == 0 else os.geteuid()
            payload = publisher / 'status.json'
            payload.write_bytes(b'{}')
            payload.chmod(0o644)
            if os.geteuid() == 0:
                os.chown(publisher, uid, uid)
                os.chown(payload, uid, uid)
                with self.assertRaises(PublisherRefused):
                    protected_read(payload)
            self.assertEqual(protected_read(payload, owners={0, uid}), b'{}')
            with self.assertRaises(PublisherRefused):
                protected_read(payload, owners={0, uid + 1})
            payload.chmod(0o664)
            with self.assertRaises(PublisherRefused):
                protected_read(payload, owners={0, uid})
            payload.chmod(0o644)
            link = publisher / 'link'
            link.symlink_to(payload)
            with self.assertRaises((OSError, PublisherRefused, EvidenceRefused)):
                protected_read(link, owners={0, uid})
            publisher.chmod(0o720)
            with self.assertRaises(PublisherRefused):
                protected_read(payload, owners={0, uid})
            publisher.chmod(0o700)

    def test_a2_reader_names_policy_owner(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/a2-fields.py'
        spec = importlib.util.spec_from_file_location('a2_fields', script)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            path = Path(temporary) / 'audit.json'
            path.write_text(json.dumps({'outcome': 'ready'}))
            uid = 992 if os.geteuid() == 0 else os.geteuid()
            if os.geteuid() == 0:
                os.chown(path, uid, uid)
            self.assertEqual(helper.read(path, owners={0, uid}), {'outcome': 'ready'})

    def test_a2_after_with_real_owned_result_audit_and_status(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/a2-fields.py'
        spec = importlib.util.spec_from_file_location('a2_after', script)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary)
            state, work = root / 'state', root / 'work'
            state.mkdir(mode=0o700)
            work.mkdir(mode=0o750)
            uid = 992 if os.geteuid() == 0 else os.geteuid()
            policy = root / 'policy.json'
            status = root / 'status.json'
            policy.write_text(json.dumps({
                'version': 2, 'publisher_uid': uid, 'status_file': str(status),
                'enabled': False, 'allow_publish': False,
                'app': {'repository': 'shamsway/octant-private', 'login': helper.LOGIN,
                        'key_file': '/run/credentials/factory-publisher.service/app-key'}}))
            if os.geteuid() == 0:
                os.chown(state, uid, uid)
            expiry = time.time() + 3600
            with patch.object(helper, 'POLICY', policy), patch.object(helper, 'STATE', state):
                helper.before(work)
                audit = state / 'publisher-token-status.json'
                audit.write_text(json.dumps({'version': 1, 'outcome': 'ready',
                    'expires_at': expiry, 'requests': 3, 'max_requests': 3, 'valid': True}))
                result = work / 'result.json'
                result.write_text(json.dumps({'state': 'read_verified', 'login': helper.LOGIN}))
                status.write_text(json.dumps({'version': 1, 'repository': 'shamsway/octant-private',
                    'at': helper.e.utc(time.time()), 'outbox': {'status': 'observed',
                    'states': {key: 0 for key in helper.publisher_status.STATES}},
                    'token': {'outcome': 'ready', 'expires_at': expiry},
                    'last_import': {'result': 'none', 'at': None}}))
                for path in (audit, result, status):
                    path.chmod(0o644)
                    if os.geteuid() == 0:
                        os.chown(path, uid, uid)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    helper.after(work)
                self.assertEqual(json.loads(output.getvalue())['state'], 'read_verified')

    def test_invalid_owner_allowlist_refused(self):
        for owners in (set(), {True}, {-1}, {'992'}):
            with self.assertRaises(PublisherRefused):
                protected_read('/not-opened', owners=owners)
