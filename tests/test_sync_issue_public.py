"""The dispatcher's upstream sync issue on a public repository withholds runner-local paths and live mentions.

The staged gate report and merge stderr go into the issue body; only the GitHub body is sanitized.
"""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE)]

# The name discovery uses: a second import as tests.test_factory would reset its XDG_CONFIG_HOME.
from test_factory import make_repo

from factory import config

TIP = "0123456789abcdef0123456789abcdef01234567"


class SyncIssueSanitizedTest(unittest.TestCase):
    def test_public_body_withholds_paths_and_mentions_and_keeps_the_exit_gate(self) -> None:
        from subprocess import CompletedProcess
        from unittest import mock

        from factory import dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            dispatch.configure(config.load(repo))
            dispatch.FACTORY.mkdir()
            evidence = (
                "## Gate report (detached candidate)\n\n"
                f'File "{dispatch.FACTORY}/wt-upstream/tests/test_x.py", line 3, in test_x\n'
                "    @mock.patch.object(dispatch, 'run')\n"
                "AssertionError: /home/runner/.cache/uv/archive-v0 missing\n"
            )
            created = CompletedProcess([], 0, stdout="https://github.com/acme/widgets/issues/12\n", stderr="")
            with mock.patch.object(dispatch, "UPSTREAM_REPO", "upstream-owner/widgets"), \
                 mock.patch.object(dispatch, "run", return_value=created) as run_mock:
                n = dispatch.sync_issue(TIP, "3", "contains the merge of the tip", evidence)

            self.assertEqual(n, 12)
            [argv] = [c.args[0] for c in run_mock.call_args_list if c.args[0][:3] == ["gh", "issue", "create"]]
            body = Path(argv[argv.index("--body-file") + 1]).read_text()

            self.assertIn("Automatic sync of `upstream-owner/widgets` main into `main`: 3 new upstream", body)
            self.assertIn(f"Exit gate: HEAD contains upstream tip `{TIP}`", body)
            self.assertIn('File "(local path withheld)", line 3', body)
            self.assertIn("AssertionError: (local path withheld) missing", body)
            for leaked in ("/home/", str(dispatch.FACTORY)):
                self.assertNotIn(leaked, body)
            self.assertIsNone(re.search(r"@(?=[A-Za-z0-9])", body), body)
            self.assertIn("&#64;mock.patch.object", body)


if __name__ == "__main__":
    unittest.main()
