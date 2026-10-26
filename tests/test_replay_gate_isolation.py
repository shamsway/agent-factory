"""A learn replay's gate reads its own linked worktree's config and writes its own journal.

Replays run in a linked worktree under `.factory/` (gitguard pins git there), so
`config.repo_root` resolves to the main checkout; the replay gate must not.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from factory import config, dispatch, lifecycle


def gate_config(passing: bool) -> str:
    return (
        '[repo]\nslug = "acme/widgets"\n'
        '[[gate.check]]\nname = "replay-config"\nrun = ['
        + json.dumps(sys.executable) + f', "-c", "raise SystemExit({0 if passing else 1})"]\n'
        '[leak_scan]\npattern = ""\n'
    )


class ReplayGateIsolationTest(unittest.TestCase):
    def test_replay_gate_uses_worktree_config_and_journal_inside_a_lifecycle_scope(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "repo"
            repo.mkdir()

            def git(*args: str, cwd: Path = repo) -> str:
                return subprocess.run(
                    ["git", *args], cwd=cwd, text=True, capture_output=True, check=True,
                ).stdout.strip()

            git("init", "-q", "-b", "main")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.com")
            (repo / config.CONFIG_NAME).write_text(gate_config(passing=True))
            git("add", "-A")
            git("commit", "-q", "-m", "base")
            base = git("rev-parse", "HEAD")
            cfg = config.Config(root=repo, repo="acme/widgets", signoff=False)
            cfg.factory.mkdir()
            dispatch.configure(cfg)
            wt = cfg.factory / "learn-7-wt"
            git("worktree", "add", "--quiet", "--detach", str(wt), base)
            # The main checkout's own config now fails; the replay revision's passes.
            (repo / config.CONFIG_NAME).write_text(gate_config(passing=False))
            main_events = cfg.factory / "events.jsonl"

            with lifecycle.scope(main_events, "learn-evaluation"):
                ok, report = dispatch.run_gate(wt, "learn-7-1", base=base, replay=True)

            self.assertTrue(ok, report)
            main_stages = {row.get("stage") for row in lifecycle.read_events(main_events)}
            self.assertNotIn("gate", main_stages)
            self.assertNotIn("gate-check", main_stages)
            replay_stages = {row.get("stage") for row in lifecycle.read_events(wt / ".factory" / "events.jsonl")}
            self.assertIn("gate", replay_stages)


if __name__ == "__main__":
    unittest.main()
