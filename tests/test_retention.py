import gzip
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from factory import retention


def run(rid, status="succeeded", target="default"):
    return dict(
        event="deploy_run",
        run_id=rid,
        target=target,
        ticket=1,
        commit="a" * 40,
        attempt=1,
        status=status,
        started_at="2026-10-01T00:00:00Z",
    )


class RetentionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def fixture(self, rows):
        (self.root / "events.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in rows)
        )
        for row in rows:
            if row.get("event") == "deploy_run":
                folder = self.root / "private" / row["run_id"]
                folder.mkdir(parents=True, exist_ok=True)
                (folder / "plan").write_text("PRIVATE FIXTURE")

    def test_recent_runs_are_kept_per_target(self):
        self.fixture(
            [
                run("a-old"),
                run("b-old", target="b"),
                run("a-new"),
                run("b-new", target="b"),
            ]
        )
        result = retention.prune(self.root, keep=1)
        self.assertEqual(result["removed"], ["a-old", "b-old"])
        self.assertTrue((self.root / "private/a-new/plan").exists())

    def test_failed_unacknowledged_and_unfinished_runs_survive(self):
        self.fixture(
            [
                run("failed", "failed"),
                run("running", "running"),
                run("pending", "pending"),
                run("new"),
            ]
        )
        self.assertEqual(retention.prune(self.root, keep=1)["removed"], [])

    def test_acknowledgement_and_supersession_allow_old_failed_plan_pruning(self):
        for disposition in ("deploy_acknowledged", "deploy_superseded"):
            with self.subTest(disposition=disposition):
                self.fixture(
                    [
                        run("failed", "failed"),
                        dict(event=disposition, target="default", run_id="failed"),
                        run("new"),
                    ]
                )
                self.assertEqual(
                    retention.prune(self.root, keep=1)["removed"], ["failed"]
                )

    def test_dry_run_is_read_only_and_unknown_dirs_survive(self):
        self.fixture([run("old"), run("new")])
        (self.root / "private/unknown").mkdir()
        result = retention.prune(self.root, keep=1, dry_run=True)
        self.assertEqual(result["removed"], ["old"])
        self.assertIn("unknown", result["retained"])
        self.assertTrue((self.root / "private/old/plan").exists())

    def test_symlinks_are_not_followed(self):
        self.fixture([run("old"), run("new")])
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "secret").write_text("PRIVATE FIXTURE")
        (self.root / "private/old/link").symlink_to(outside, target_is_directory=True)
        retention.prune(self.root, keep=1)
        self.assertTrue((outside / "secret").exists())

    def test_symlinked_store_is_refused(self):
        (self.root / "outside").mkdir()
        (self.root / "private").symlink_to(
            self.root / "outside", target_is_directory=True
        )
        with self.assertRaises(ValueError):
            retention.prune(self.root)

    def test_rotated_failure_is_preserved(self):
        self.fixture([run("failed", "failed"), run("new")])
        with gzip.open(self.root / "events.jsonl.1.gz", "wt") as f:
            f.write(json.dumps(run("failed", "failed")) + "\n")
        (self.root / "events.jsonl").write_text(json.dumps(run("new")) + "\n")
        self.assertEqual(retention.prune(self.root, keep=1)["removed"], [])

    def test_malformed_newer_record_refuses_pruning(self):
        self.fixture([run("old"), run("new")])
        with (self.root / "events.jsonl").open("a") as f:
            f.write(
                json.dumps(dict(event="deploy_run", run_id="old", status="invalid"))
                + "\n"
            )
        with self.assertRaises((ValueError, TypeError, KeyError)):
            retention.prune(self.root, keep=1)
        self.assertTrue((self.root / "private/old/plan").exists())

    def test_invalid_policy_and_unreadable_journal_do_not_delete(self):
        self.fixture([run("old"), run("new")])
        with self.assertRaises(ValueError):
            retention.prune(self.root, keep=0)
        with mock.patch.object(
            retention.lifecycle, "read_events", side_effect=OSError("unreadable")
        ):
            with self.assertRaises(OSError):
                retention.prune(self.root, keep=1)
        self.assertTrue((self.root / "private/old/plan").exists())


if __name__ == "__main__":
    unittest.main()
