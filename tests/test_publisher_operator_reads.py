"""Operator ownership regressions, including real chown in the Linux harness."""
import os
import tempfile
import unittest
from pathlib import Path

from factory.investigation_evidence import EvidenceRefused
from factory.investigation_publisher import PublisherRefused
from factory.publisher_credentials import protected_read


class ExpectedOwnerTests(unittest.TestCase):
    # Real root is unmapped in an unprivileged user namespace (a bwrap-sandboxed gate check), so
    # `/` reads as the overflow UID and the ancestor-ownership guard refuses every path.
    @unittest.skipIf(os.stat('/').st_uid != 0, 'root is unmapped in this user namespace')
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

    def test_invalid_owner_allowlist_refused(self):
        for owners in (set(), {True}, {-1}, {'992'}):
            with self.assertRaises(PublisherRefused):
                protected_read('/not-opened', owners=owners)
