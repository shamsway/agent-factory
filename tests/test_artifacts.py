"""SHA-190: durable sanitized deployment artifacts.

Run: python -m unittest tests.test_artifacts
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from factory import artifacts, config, deploy

from tests.test_factory import make_repo

SECRET = "s3cr3t-apply-value-123"
GH_TOKEN = "ghp_" + "a" * 30
PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----\n"
LOG = f"Initializing\napi_key = {SECRET}\nauth {GH_TOKEN}\n{PEM}Apply complete! Resources: 1 added.\n"


class SanitizeTest(unittest.TestCase):
    def test_redacts_values_tokens_and_key_blocks(self) -> None:
        out = artifacts.sanitize(LOG, [SECRET])
        for leaked in (SECRET, GH_TOKEN, "MIIEabc", "BEGIN RSA"):
            self.assertNotIn(leaked, out)
        self.assertIn("Apply complete!", out)

    def test_stream_handles_pem_and_truncates(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d) / "raw.log", Path(d) / "out" / "apply.log"
            src.write_text(LOG + "x" * 100 + "\n" * 2000)
            n = artifacts.stream_sanitized_log(src, dst, [SECRET], max_bytes=300)
            text = dst.read_text()
            self.assertNotIn(SECRET, text)
            self.assertNotIn("MIIEabc", text)
            self.assertIn("truncated", text)
            self.assertEqual(n, len(text.encode()))
            self.assertEqual(dst.stat().st_mode & 0o777, 0o600)


class RunFixture:
    """A finished apply_one run against a fake adapter that writes a secret-laden log."""

    def __init__(self, tmp: Path, post_ok: dict[str, bool] | None = None, ticket: int = 77, pr: int = 12) -> None:
        from factory import apply, dispatch

        self.apply, self.dispatch = apply, dispatch
        repo = make_repo(tmp, f'[apply]\nenabled = true\n[apply.env]\nCLOUD_KEY = "{SECRET}"\n')
        cfg = config.load(repo)
        cfg.apply_env = {"CLOUD_KEY": SECRET}
        dispatch.configure(cfg)
        apply.configure(cfg)
        cfg.factory.mkdir(parents=True, exist_ok=True)
        self.cfg = cfg
        self.wt = tmp / "checkout"
        self.wt.mkdir()
        self.posts: list[tuple[str, int]] = []
        self.post_ok = post_ok or {}
        self.ticket = {"ticket": ticket, "pr": pr, "commit": "deadbeef1234"}
        wt = self.wt

        class LogAdapter(deploy.FakeDeployAdapter):
            def prepare(s, ctx):
                ctx.worktree = wt
                ctx.planfile = wt / "plan.bin"
                ctx.planfile.write_text(f"plan embedding {SECRET}")
                return True, ""

            def execute(s, ctx, dry_run=False):
                raw = ctx.factory_dir / "logs" / "terraform-apply-default-77.log"
                raw.parent.mkdir(parents=True, exist_ok=True)
                raw.write_text(LOG)
                return deploy.DeployExecutionResult(ok=True, output=LOG[-400:], log_path=raw)

            def cleanup(s, ctx):
                (wt / "plan.bin").unlink(missing_ok=True)

        self.adapter = LogAdapter()

    def post(self, sink: str, number: int, body: str):
        self.posts.append((sink, number))
        assert SECRET not in body and GH_TOKEN not in body and "MIIEabc" not in body
        ok = self.post_ok.get(sink, True)
        return ok, "" if ok else "gh: HTTP 502"

    def run(self) -> None:
        with mock.patch.object(self.apply, "touches_apply_dir", return_value=True), \
             mock.patch.object(self.apply, "post_comment", side_effect=self.post):
            self.apply.apply_one(self.ticket, dry_run=False, adapter=self.adapter)

    @property
    def run_dir(self) -> Path:
        return artifacts.artifact_dir(self.cfg.factory, "default", "deploy-default-deadbeef-1")


class PublicationTest(unittest.TestCase):
    def test_artifacts_survive_cleanup_and_hold_no_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            fx = RunFixture(Path(d))
            fx.run()
            self.assertFalse((fx.wt / "plan.bin").exists())  # adapter cleanup ran and removed the worktree plan
            names = sorted(p.name for p in fx.run_dir.iterdir())
            self.assertEqual(names, ["apply.log", "manifest.json", "summary.json"])
            for p in fx.run_dir.iterdir():
                text = p.read_text()
                for leaked in (SECRET, GH_TOKEN, "MIIEabc"):
                    self.assertNotIn(leaked, text, p.name)
            manifest = json.loads((fx.run_dir / "manifest.json").read_text())
            self.assertEqual({f["name"] for f in manifest["files"]}, {"apply.log", "summary.json"})
            summary = json.loads((fx.run_dir / "summary.json").read_text())
            self.assertEqual((summary["status"], summary["pr"], summary["ticket"]), ("succeeded", 12, 77))
            events = fx.cfg.factory.joinpath("events.jsonl").read_text()
            self.assertNotIn(SECRET, events)
            self.assertNotIn(GH_TOKEN, events)

    def test_plan_stored_privately_never_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            fx = RunFixture(Path(d))
            fx.run()
            priv = artifacts.private_dir(fx.cfg.factory, "deploy-default-deadbeef-1")
            self.assertEqual(priv.stat().st_mode & 0o777, 0o700)
            self.assertEqual((priv / "plan").stat().st_mode & 0o777, 0o600)
            manifest = (fx.run_dir / "manifest.json").read_text()
            self.assertNotIn("plan", [f["name"] for f in json.loads(manifest)["files"]])
            self.assertIsNone(artifacts.lookup(fx.cfg.factory, "default", "deploy-default-deadbeef-1", "plan"))

    def test_posts_use_explicit_pr_number_not_ticket(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            fx = RunFixture(Path(d), ticket=77, pr=12)
            fx.run()
            self.assertEqual(sorted(fx.posts), [("issue", 77), ("pr", 12)])
            captured = []
            with mock.patch.object(fx.dispatch, "run", side_effect=lambda cmd, **k: captured.append(cmd) or
                                   subprocess.CompletedProcess(cmd, 0, "", "")):
                fx.apply.post_comment("pr", 12, "b")
                fx.apply.post_comment("issue", 77, "b")
            self.assertEqual(captured[0][:4], ["gh", "pr", "comment", "12"])
            self.assertEqual(captured[1][:4], ["gh", "issue", "comment", "77"])

    def test_missing_pr_number_is_skipped_not_misdirected(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            fx = RunFixture(Path(d))
            fx.ticket["pr"] = None
            fx.run()
            self.assertEqual(fx.posts, [("issue", 77)])
            m = artifacts.read_manifest(fx.run_dir)
            self.assertEqual(m["publications"]["pr"]["status"], "skipped")

    def test_sinks_fail_and_retry_independently(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            fx = RunFixture(Path(d), post_ok={"pr": False})
            fx.run()
            self.assertEqual(sorted(fx.posts), [("issue", 77), ("pr", 12)])  # PR failure did not stop issue
            m = artifacts.read_manifest(fx.run_dir)
            self.assertEqual(m["publications"]["issue"]["status"], "ok")
            self.assertEqual(m["publications"]["pr"]["status"], "pending")
            self.assertIn("502", m["publications"]["pr"]["last_error"])
            state = deploy.get_target_state("default", events_path=fx.dispatch.EVENTS)
            self.assertEqual(state.runs[-1].status, deploy.DeployStatus.SUCCEEDED)

            fx.posts.clear()
            fx.post_ok = {}
            with mock.patch.object(fx.apply, "post_comment", side_effect=fx.post):
                artifacts.retry_pending(fx.cfg.factory, fx.apply.post_comment)
            self.assertEqual(fx.posts, [("pr", 12)])  # only the unfinished sink
            m = artifacts.read_manifest(fx.run_dir)
            self.assertEqual(m["publications"]["pr"], {**m["publications"]["pr"], "status": "ok", "attempts": 2})
            self.assertEqual(artifacts.pending_runs(fx.cfg.factory), [])

    def test_raising_sink_does_not_stop_other_sink(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            fx = RunFixture(Path(d), post_ok={"issue": False, "pr": False})
            fx.run()
            calls = []

            def post(sink, n, body):
                calls.append(sink)
                if sink == "issue":
                    raise RuntimeError("boom")
                return True, ""

            artifacts.publish(fx.cfg.factory, "default", "deploy-default-deadbeef-1", post)
            self.assertEqual(calls, ["issue", "pr"])
            m = artifacts.read_manifest(fx.run_dir)
            self.assertEqual((m["publications"]["issue"]["status"], m["publications"]["pr"]["status"]), ("pending", "ok"))

    def test_retry_attempts_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            fx = RunFixture(Path(d), post_ok={"pr": False})
            fx.run()
            for _ in range(artifacts.MAX_PUBLISH_ATTEMPTS + 2):
                artifacts.publish(fx.cfg.factory, "default", "deploy-default-deadbeef-1", lambda *a: (False, "x"))
            m = artifacts.read_manifest(fx.run_dir)
            self.assertEqual(m["publications"]["pr"]["status"], "failed")
            self.assertLessEqual(m["publications"]["pr"]["attempts"], artifacts.MAX_PUBLISH_ATTEMPTS)


class LookupAndServingTest(unittest.TestCase):
    def test_lookup_is_manifest_allowlisted_and_integrity_checked(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            fx = RunFixture(Path(d))
            fx.run()
            f, rid = fx.cfg.factory, "deploy-default-deadbeef-1"
            body, ctype = artifacts.lookup(f, "default", rid, "summary.json")
            self.assertEqual(ctype, "application/json")
            self.assertEqual(json.loads(body)["run_id"], rid)
            for bad in ("manifest.json", "../../events.jsonl", "../private/" + rid + "/plan", "nope"):
                self.assertIsNone(artifacts.lookup(f, "default", rid, bad), bad)
            self.assertIsNone(artifacts.lookup(f, "..", rid, "summary.json"))
            self.assertIsNone(artifacts.lookup(f, "default", "../x", "summary.json"))
            (fx.run_dir / "apply.log").write_text(f"tampered {SECRET}")
            self.assertIsNone(artifacts.lookup(f, "default", rid, "apply.log"))

    def test_dashboard_serves_artifacts_but_never_private_files(self) -> None:
        from factory import dashboard

        with tempfile.TemporaryDirectory() as d:
            fx = RunFixture(Path(d))
            fx.run()
            rid = "deploy-default-deadbeef-1"
            f = fx.cfg.factory
            (f / "apply-checkout").mkdir()
            (f / "apply-checkout" / "terraform.tfstate").write_text(f"state {SECRET}")
            (f / "logs" / "worker-1.log").write_text("worker ok")
            with mock.patch.object(dashboard, "FACTORY", f, create=True):
                srv = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.Handler)
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                base = f"http://127.0.0.1:{srv.server_address[1]}"

                def get(path: str):
                    try:
                        with urllib.request.urlopen(base + path) as r:
                            return r.status, r.read().decode()
                    except urllib.error.HTTPError as e:
                        e.close()
                        return e.code, ""

                try:
                    code, body = get(f"/api/artifacts/default/{rid}/apply.log")
                    self.assertEqual(code, 200)
                    self.assertNotIn(SECRET, body)
                    self.assertEqual(get(f"/api/artifacts/default/{rid}/nope")[0], 404)
                    self.assertEqual(get("/api/artifacts/default/..%2f..%2fevents.jsonl")[0], 404)
                    self.assertEqual(get("/api/file?path=logs/worker-1.log"), (200, "worker ok"))
                    for private in (
                        "apply-checkout/terraform.tfstate",
                        f"private/{rid}/plan",
                        f"artifacts/default/{rid}/manifest.json",
                        "logs/terraform-apply-default-77.log",
                        "logs/../private/" + rid + "/plan",
                    ):
                        self.assertEqual(get("/api/file?path=" + private)[0], 404, private)
                finally:
                    srv.shutdown()
                    srv.server_close()


if __name__ == "__main__":
    unittest.main()
