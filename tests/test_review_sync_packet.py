"""An upstream sync PR is reviewed on its fork-side change, not on upstream's commits.

Fixture: upstream adds a payload larger than the inline cap; the fork's main
diverges on one file; the sync branch merges upstream (one conflict resolved)
and adds a fix-up commit. A plain PR branch from fork main is the control.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from factory import config, dispatch

CAP = 120 * 1024
PAYLOAD = "".join(f"UPSTREAM-PAYLOAD {i:06d} {'x' * 100}\n" for i in range(1500))
GH = "#!/usr/bin/env python3\nimport json\nprint(json.dumps({'title': 'sync', 'body': 'Acceptance: sync', 'comments': []}))\n"
# Like test_review_isolation: reviewer argv gets the prompt as {prompt}; it records that prompt and approves.
PROBE = """
import sys
with open(sys.argv[1], 'w') as f:
    f.write(sys.argv[2])
print('```json\\n{"verdict":"APPROVE","findings":[]}\\n```\\nVERDICT: APPROVE')
"""


def git(cwd: Path, *args: str, strip: bool = True) -> str:
    out = subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True,
    ).stdout
    return out.strip() if strip else out


class SyncReviewPacketTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        tmp = Path(temporary.name).resolve()
        self.repo = tmp / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "config", "user.email", "t@example.com")
        git(self.repo, "config", "user.name", "t")
        git(self.repo, "remote", "add", "origin", "git@github.com:acme/widgets.git")
        git(self.repo, "remote", "add", "upstream", "git@github.com:acme/upstream.git")
        (self.repo / "AGENTS.md").write_text("Base standards.\n")
        (self.repo / "shared.txt").write_text("base\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")
        base = git(self.repo, "rev-parse", "HEAD")

        git(self.repo, "checkout", "-q", "-b", "upstream-work", base)
        (self.repo / "shared.txt").write_text("upstream line\n")
        (self.repo / "big.txt").write_text(PAYLOAD)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "upstream: large change")
        self.upstream_tip = git(self.repo, "rev-parse", "HEAD")

        git(self.repo, "checkout", "-q", "-b", "fork", base)
        (self.repo / "shared.txt").write_text("fork line\n")
        git(self.repo, "commit", "-q", "-am", "fork: own change")
        self.fork_main = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "update-ref", "refs/remotes/origin/main", self.fork_main)
        git(self.repo, "update-ref", "refs/remotes/upstream/main", self.upstream_tip)

        git(self.repo, "checkout", "-q", "-b", "agent/9", self.fork_main)
        merge = subprocess.run(
            ["git", "-C", str(self.repo), "merge", "-q", "--no-edit", self.upstream_tip],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(merge.returncode, 0, "fixture: the sync merge must conflict")
        (self.repo / "shared.txt").write_text("resolved line\n")
        git(self.repo, "add", "shared.txt")
        git(self.repo, "commit", "-q", "--no-edit")
        (self.repo / "fixup.txt").write_text("fixup line\n")
        git(self.repo, "add", "fixup.txt")
        git(self.repo, "commit", "-q", "-m", "fix-up")
        self.head = git(self.repo, "rev-parse", "HEAD")

        git(self.repo, "checkout", "-q", "-b", "agent/10", self.fork_main)
        (self.repo / "widget.txt").write_text("widget\n")
        git(self.repo, "add", "widget.txt")
        git(self.repo, "commit", "-q", "-m", "widget")
        self.plain_head = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "checkout", "-q", "agent/9")

        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(GH)
        gh.chmod(0o755)
        env = mock.patch.dict(os.environ, {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"})
        env.start()
        self.addCleanup(env.stop)

        self.out = tmp / "prompt.txt"
        cfg = config.Config(
            root=self.repo,
            repo="acme/widgets",
            upstream="upstream",
            reviewer=[sys.executable, "-c", PROBE, str(self.out), "{prompt}"],
        )
        dispatch.configure(cfg)
        cfg.factory.mkdir(exist_ok=True)

    def test_sync_packet_carries_resolution_and_fixup_not_upstream(self) -> None:
        packet, diff = dispatch._review_packet(self.repo, self.head)
        self.assertIn("resolved line", diff)
        self.assertIn("fixup line", diff)
        self.assertNotIn("UPSTREAM-PAYLOAD", diff)
        self.assertNotIn("UPSTREAM-PAYLOAD", packet)
        self.assertIn(self.upstream_tip, packet)

    def test_sync_review_prompt_fits_cap_where_full_diff_does_not(self) -> None:
        full = git(self.repo, "diff", f"origin/main..{self.head}")
        self.assertGreater(len(full.encode()), CAP, "fixture: the full diff must exceed the cap")
        verdict, findings = dispatch.review(self.repo, 9, "PASS", self.head)
        self.assertEqual(verdict, "APPROVE", findings)
        prompt = self.out.read_text()
        self.assertLess(len(prompt.encode()), CAP)
        self.assertIn("resolved line", prompt)
        self.assertIn("fixup line", prompt)
        self.assertNotIn("UPSTREAM-PAYLOAD", prompt)

    def test_non_sync_packet_is_unchanged(self) -> None:
        packet, diff = dispatch._review_packet(self.repo, self.plain_head)
        expected_diff = git(self.repo, "diff", f"{self.fork_main}..{self.plain_head}", strip=False)
        self.assertEqual(diff, expected_diff)
        self.assertEqual(
            packet,
            f"Base revision: {self.fork_main}\nReviewed revision: {self.plain_head}\n"
            "--- AGENTS.md (base revision) ---\nBase standards.\n"
            f"\n--- BEGIN UNTRUSTED DIFF ---\n{expected_diff}\n--- END UNTRUSTED DIFF ---",
        )


if __name__ == "__main__":
    unittest.main()
