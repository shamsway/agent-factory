"""SHA-200 read-only, bounded, correlated diagnostic contracts."""
import json
import contextlib
import io
import tempfile
import time
import subprocess
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

from factory import apply, artifacts, config, deploy, diagnostics, dispatch
from tests.test_factory import make_repo
from tests.test_health import FakeNomad


NOW = 1791054000
TOKEN = "fixture-private-token-123456789"


def run(version=2):
    return deploy.DeployRun(run_id="deploy-default-01234567-1", target="default", commit="01234567" * 5,
        ticket=1, pr=2, attempt=1, status=deploy.DeployStatus.FAILED,
        started_at=diagnostics.utc(NOW - 60), completed_at=diagnostics.utc(NOW),
        error="startup failed", output="token=" + TOKEN,
        verification={"verdict": "unhealthy", "items": [{"kind": "nomad_job", "id": "worker",
            "namespace": "infra", "region": "west", "observed": {"version": version}}]})


class FixtureHTTP:
    def __init__(self):
        self.rows = {}
        self.calls = []

    def get(self, url, headers, deadline, limit):
        path = urllib.parse.urlsplit(url).path
        self.calls.append((path, dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)), headers, deadline, limit))
        value = self.rows.get(path, diagnostics.Unavailable("absent_or_expired"))
        if isinstance(value, Exception):
            raise value
        return value.encode() if isinstance(value, str) else json.dumps(value).encode()


def fixture():
    f = FixtureHTTP()
    f.rows["/v1/job/worker"] = {"ID": "worker", "Version": 3, "Status": "running", "Env": {"RAW": "never-store"}}
    f.rows["/v1/job/worker/evaluations"] = [{"ID": "eval-fail", "JobID": "worker", "Namespace": "infra",
        "ModifyTime": (NOW - 30) * 10**9, "Status": "blocked", "StatusDescription": "placement failure"},
        {"ID": "old", "JobID": "worker", "Namespace": "infra", "ModifyTime": (NOW - 1000) * 10**9}]
    f.rows["/v1/job/worker/deployments"] = [
        {"ID": "dep-fail", "JobID": "worker", "Namespace": "infra", "JobVersion": 2, "Status": "failed"},
        {"ID": "dep-new", "JobID": "worker", "Namespace": "infra", "JobVersion": 3, "Status": "successful"}]
    f.rows["/v1/job/worker/allocations"] = [{"ID": "failed", "JobID": "worker", "Namespace": "infra", "JobVersion": 2,
        "EvalID": "eval-fail", "DeploymentID": "dep-fail", "NextAllocation": "replacement", "ClientStatus": "failed",
        "CreateTime": (NOW - 40) * 10**9, "ModifyTime": (NOW - 10) * 10**9},
        {"ID": "replacement", "JobID": "worker", "Namespace": "infra", "JobVersion": 2,
        "PreviousAllocation": "failed", "ClientStatus": "pending", "CreateTime": (NOW - 10) * 10**9, "ModifyTime": NOW * 10**9},
        {"ID": "new-version", "JobID": "worker", "Namespace": "infra", "JobVersion": 3,
        "CreateTime": NOW * 10**9, "ModifyTime": NOW * 10**9}]
    for aid in ("failed", "replacement"):
        f.rows["/v1/allocation/" + aid] = {"ID": aid, "JobID": "worker", "Namespace": "infra", "Job": {"Version": 2, "Env": {"SECRET": "never-store"}},
            "TaskStates": {"main": {"State": "dead", "Failed": True, "Events": [
                {"Type": "Terminated", "Time": (NOW - 20) * 10**9, "DisplayMessage": "startup failed token=" + TOKEN, "ExitCode": 1},
                {"Type": "old", "Time": (NOW - 1000) * 10**9, "DisplayMessage": "OUTSIDE_WINDOW"}]}}}
        f.rows["/v1/client/fs/logs/" + aid] = "bounded context secret=" + TOKEN
    return f


class DiagnosticTests(unittest.TestCase):
    def collect(self, f=None, r=None, p=None, **kw):
        return diagnostics.collect(r or run(), p or diagnostics.Policy(nomad_addr="http://nomad", logs=True),
            {"NOMAD_TOKEN": TOKEN}, transport=kw.pop("transport", f or fixture()), wall=lambda: NOW, **kw)

    def test_failure_version_and_replacement_lineage(self):
        f = fixture()
        b = self.collect(f)
        rows = b["observations"]
        allocation = next(r for r in rows if r["source"].endswith("/allocations"))
        self.assertEqual([a["ID"] for a in allocation["data"]], ["failed", "replacement"])
        self.assertEqual(allocation["lineage"]["version"], 2)
        self.assertEqual(allocation["data"][0]["NextAllocation"], "replacement")
        current = next(r for r in rows if r["source"].endswith("/current"))
        self.assertEqual(current["data"]["Version"], 3)
        self.assertEqual(current["lineage"]["relation"], "current_state_only")
        text = json.dumps(b)
        self.assertNotIn("new-version", text)
        self.assertNotIn("dep-new", text)
        self.assertNotIn("OUTSIDE_WINDOW", text)
        self.assertNotIn("never-store", text)
        self.assertNotIn(TOKEN, text)
        self.assertEqual(b["run_id"], run().run_id)
        self.assertEqual(b["commit"], run().commit)
        self.assertTrue(all(c[1]["namespace"] == "infra" and c[1]["region"] == "west" for c in f.calls))
        log = next(c for c in f.calls if "/fs/logs/" in c[0])
        self.assertEqual(log[1]["follow"], "false")
        self.assertTrue(any(r["data"] and isinstance(r["data"], dict) and r["data"].get("time_coverage") == "untimestamped_bounded_tail" for r in rows))

    def test_missing_version_never_uses_latest_allocations(self):
        f = fixture()
        b = self.collect(f, run(None))
        self.assertTrue(any(r["status"] == "version_unavailable" for r in b["observations"]))
        self.assertFalse(any("allocations" in c[0] or "logs" in c[0] for c in f.calls))

    def test_logs_off_excludes_unrecognized_workload_secret_and_all_log_reads(self):
        f = fixture()
        f.rows["/v1/allocation/failed"]["TaskStates"]["main"]["Events"][0]["DisplayMessage"] = "unknown-workload-credential"
        f.rows["/v1/health/checks/db"] = [{"Status": "critical", "Output": "unknown-workload-credential"}]
        p = diagnostics.Policy(nomad_addr="http://nomad", consul_addr="http://consul", services=["db"], error_logs=["main/local/error.log"])
        b = self.collect(f, p=p)
        self.assertNotIn("unknown-workload-credential", json.dumps(b))
        self.assertFalse(any("/fs/" in call[0] for call in f.calls))
        self.assertFalse(b["logs_enabled"])

    def test_only_explicit_oom_detail_is_retained_as_boolean_with_logs_off(self):
        f = fixture()
        event = f.rows["/v1/allocation/failed"]["TaskStates"]["main"]["Events"][0]
        event["Details"] = {"oom_killed": "true", "driver_message": "unknown-workload-secret"}
        b = self.collect(f, p=diagnostics.Policy(nomad_addr="http://nomad", logs=False))
        allocation = next(r for r in b["observations"] if r["source"] == "nomad/allocation/failed")
        projected = allocation["data"]["tasks"]["main"]["Events"][0]
        self.assertIs(projected["OOMKilled"], True)
        self.assertNotIn("Details", projected)
        self.assertNotIn("unknown-workload-secret", json.dumps(b))
        event["Details"]["oom_killed"] = "unknown-workload-secret"
        b = self.collect(f, p=diagnostics.Policy(nomad_addr="http://nomad", logs=False))
        allocation = next(r for r in b["observations"] if r["source"] == "nomad/allocation/failed")
        self.assertNotIn("OOMKilled", allocation["data"]["tasks"]["main"]["Events"][0])

    def test_apply_token_is_never_used_by_diagnostics(self):
        f = fixture()
        self.collect(f)
        self.assertTrue(all(not call[2] for call in f.calls))
        f = fixture()
        diagnostics.collect(run(), diagnostics.Policy(nomad_addr="http://nomad"),
                            {"NOMAD_TOKEN": "apply-token", "FACTORY_DIAGNOSTIC_NOMAD_TOKEN": TOKEN},
                            transport=f, wall=lambda: NOW)
        self.assertTrue(all(call[2] == {"X-Nomad-Token": TOKEN} for call in f.calls))

    def test_failed_terraform_execute_persists_plan_jobs_without_guessing_version(self):
        class PlanAdapter(deploy.FakeDeployAdapter):
            def check(self, ctx):
                ctx.metadata["plan"] = {"resource_changes": [{"type": "nomad_job", "change": {
                    "actions": ["update"], "after": {"name": "worker", "namespace": "infra"}}}]}
                return True, ""
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp), '[apply]\nenabled=true\n[apply.diagnostics]\nnomad_addr="http://nomad"\n')
            cfg = config.load(repo)
            apply.configure(cfg)
            cfg.factory.mkdir(exist_ok=True)
            f = fixture()
            with mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "apply_escalate"), mock.patch.object(apply, "post_comment", return_value=(True, "")), \
                 mock.patch.object(diagnostics, "HTTP", return_value=f):
                self.assertFalse(apply.apply_one({"ticket": 1, "pr": 2, "commit": "abcd1234"}, False,
                                                adapter=PlanAdapter(execute_error="provider rejected job registration")))
            failed = deploy.get_target_state("default", cfg.factory / "events.jsonl").latest_run
            self.assertIsNone(failed.verification)
            self.assertEqual(failed.diagnostic_jobs[0]["id"], "worker")
            self.assertTrue(any(c[0] == "/v1/job/worker" for c in f.calls))
            self.assertTrue(any(c[0].endswith("/evaluations") for c in f.calls))
            self.assertFalse(any("allocations" in c[0] or "/fs/" in c[0] for c in f.calls))

    def test_default_window_covers_long_apply_and_health_run(self):
        r = run()
        r.started_at = diagnostics.utc(NOW - 1200)
        b = self.collect(r=r)
        self.assertEqual(b["window"]["start"], r.started_at)

    def test_secret_directory_rejected(self):
        with self.assertRaises(config.ConfigError):
            diagnostics.policy({"error_logs": ["main/secrets/x.log"]})

    def test_nomad_diagnostic_credential_verifier_rejects_write_and_management(self):
        from factory import verify_secrets
        cfg = config.Config(Path("/tmp/fixture"), "test/repo")
        cfg.apply_env = {"NOMAD_TOKEN": "apply", "FACTORY_DIAGNOSTIC_NOMAD_TOKEN": TOKEN}
        cfg.targets = {"default": config.DeployTarget("default", ".", diagnostics={"nomad_addr": "http://nomad"})}
        def check(identity, rules):
            with mock.patch.object(diagnostics.HTTP, "get", side_effect=[json.dumps(identity).encode(), json.dumps({"Rules": rules}).encode(), b"[]"]):
                return verify_secrets.credential_rows(cfg, "apply", True)[0]["status"]
        client = {"Type": "client", "Policies": ["diagnostic-read"]}
        self.assertEqual(check(client, 'namespace "infra" {policy="read" capabilities=["read-logs"]}'), "valid")
        self.assertEqual(check(client, 'namespace "infra" {policy="write"}'), "invalid")
        self.assertEqual(check({"Type": "management"}, ""), "invalid")
        self.assertEqual(check(client, 'namespace "infra" {policy="read" capabilities=["submit-job"]}'), "invalid")

    def test_diagnostic_token_rejects_variables_and_unnecessary_filesystem_access(self):
        cfg = config.Config(Path("/tmp/fixture"), "test/repo")
        cfg.targets = {"default": config.DeployTarget("default", ".", diagnostics={"nomad_addr": "http://nomad"})}
        def check(rules):
            identity = {"Type": "client", "Policies": ["diagnostic-read"]}
            responses = [json.dumps(identity).encode(), json.dumps({"Rules": rules}).encode(), b"[]"]
            with mock.patch.object(diagnostics.HTTP, "get", side_effect=responses):
                return diagnostics.verify_nomad_token(cfg, TOKEN)
        for capability in ("read", "list"):
            with self.subTest(capability=capability):
                self.assertEqual(check('namespace "*" { policy="read" variables { path "*" { capabilities=["' + capability + '"] } } }'), "invalid")
        filesystem = 'namespace "infra" {policy="read" capabilities=["read-fs"]}'
        self.assertEqual(check(filesystem), "invalid")
        cfg.targets["default"].diagnostics["error_logs"] = ["main/local/error.log"]
        self.assertEqual(check(filesystem), "invalid")  # logs are still disabled
        cfg.targets["default"].diagnostics["logs"] = True
        self.assertEqual(check(filesystem), "valid")
        self.assertEqual(check('namespace "infra" { capabilities=["read"] }'), "invalid")

    def test_plan_lineage_error_cannot_leave_executed_run_running(self):
        from factory import health
        for error in (None, "provider failed"):
            with self.subTest(execute_error=error), tempfile.TemporaryDirectory() as tmp:
                repo = make_repo(Path(tmp), '[apply]\nenabled=true\n')
                cfg = config.load(repo)
                apply.configure(cfg)
                cfg.factory.mkdir(exist_ok=True)
                captured = io.StringIO()
                with mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                     mock.patch.object(apply, "apply_escalate"), \
                     mock.patch.object(apply, "post_comment", return_value=(True, "")), \
                     mock.patch.object(health, "nomad_jobs", side_effect=TypeError("private-plan-secret")), \
                     contextlib.redirect_stdout(captured):
                    result = apply.apply_one({"ticket": 1, "pr": 2, "commit": "abcd1234"}, False,
                                             adapter=deploy.FakeDeployAdapter(execute_error=error))
                self.assertEqual(result, error is None)
                final = deploy.get_target_state("default", cfg.factory / "events.jsonl").latest_run
                self.assertEqual(final.status, deploy.DeployStatus.FAILED if error else deploy.DeployStatus.SUCCEEDED)
                self.assertIsNone(final.diagnostic_jobs)
                self.assertIn("diagnostic plan lineage unavailable: TypeError", captured.getvalue())
                self.assertNotIn("private-plan-secret", captured.getvalue())

    def test_diagnostic_token_cannot_copy_apply_token_even_without_live_check(self):
        from factory import verify_secrets
        cfg = config.Config(Path("/tmp/fixture"), "test/repo")
        cfg.apply_env = {"NOMAD_TOKEN": TOKEN, "FACTORY_DIAGNOSTIC_NOMAD_TOKEN": TOKEN}
        rows = verify_secrets.credential_rows(cfg, "apply", False)
        self.assertEqual(next(row["status"] for row in rows if row["key"] == "FACTORY_DIAGNOSTIC_NOMAD_TOKEN"), "invalid")

    def test_comment_or_unreadable_policy_cannot_claim_read_only(self):
        cfg = config.Config(Path("/tmp/fixture"), "test/repo")
        cfg.targets = {"default": config.DeployTarget("default", ".", diagnostics={"nomad_addr": "http://nomad"})}
        with mock.patch.object(diagnostics.HTTP, "get", side_effect=[b'{"Type":"client","Policies":["read"]}', b'{"Rules":"# comment"}']):
            self.assertEqual(diagnostics.verify_nomad_token(cfg, TOKEN), "unavailable")

    def test_missing_failure_time_never_guesses_current_window(self):
        r = run()
        r.started_at = ""
        f = fixture()
        b = self.collect(f, r)
        self.assertFalse(b["window"]["known"])
        self.assertTrue(any(row["status"] == "window_unavailable" for row in b["observations"]))
        self.assertFalse(f.calls)

    def test_allocation_detail_mismatch_skips_logs(self):
        f = fixture()
        f.rows["/v1/allocation/failed"]["Job"]["Version"] = 3
        b = self.collect(f)
        self.assertTrue(any(r["status"] == "lineage_mismatch" for r in b["observations"]))
        self.assertFalse(any(c[0] == "/v1/client/fs/logs/failed" for c in f.calls))

    def test_wrong_namespace_excluded(self):
        f = fixture()
        f.rows["/v1/job/worker/allocations"][0]["Namespace"] = "other"
        b = self.collect(f)
        self.assertFalse(any(r["source"] == "nomad/allocation/failed" for r in b["observations"]))

    def test_log_expiry_and_permission_preserve_partial_evidence(self):
        f = fixture()
        f.rows["/v1/client/fs/logs/failed"] = diagnostics.Unavailable("expired")
        f.rows["/v1/client/fs/logs/replacement"] = diagnostics.Unavailable("permission_denied")
        b = self.collect(f)
        statuses = {r["status"] for r in b["observations"]}
        self.assertTrue({"observed", "expired", "permission_denied"} <= statuses)
        self.assertEqual(run().status, deploy.DeployStatus.FAILED)

    def test_failure_classes_are_evidence_not_invented_diagnosis(self):
        for symptom in ("placement constraints", "startup exit 1", "health-check critical", "dependency refused", "OOM Killed"):
            with self.subTest(symptom=symptom):
                f = fixture()
                f.rows["/v1/allocation/failed"]["TaskStates"]["main"]["Events"][0]["DisplayMessage"] = symptom
                b = self.collect(f)
                self.assertIn(symptom, json.dumps(b))
                self.assertNotIn("root_cause", b)

    def test_consul_dependency_and_probe_do_not_store_body(self):
        f = FixtureHTTP()
        f.rows["/v1/health/checks/database"] = [{"CheckID": "db", "Status": "critical", "Output": "dependency refused token=" + TOKEN, "Definition": {"Env": "never-store"}}]
        f.rows["/health"] = "secret payload should never be retained"
        p = diagnostics.Policy(consul_addr="http://consul", services=["database"], probes=["http://dependency/health"], logs=True)
        b = self.collect(f, p=p)
        text = json.dumps(b)
        self.assertIn("dependency refused", text)
        self.assertNotIn(TOKEN, text)
        self.assertNotIn("never-store", text)
        self.assertNotIn("secret payload", text)
        self.assertTrue(any(r["source"] == "probe/0" and r["data"]["reachable"] for r in b["observations"]))

    def test_plugin_failure_safe_and_next_collector_runs(self):
        def broken(ctx):
            ctx.add("partial", "observed", "kept")
            raise RuntimeError("private path and secret")
        def next_collector(ctx):
            ctx.add("next", "observed", "kept")
        b = self.collect(collectors=[broken, next_collector])
        self.assertEqual([r["source"] for r in b["observations"]], ["partial", "broken", "next"])
        self.assertNotIn("private path", json.dumps(b))

    def test_plugin_secret_fields_and_config_are_excluded(self):
        def plugin(ctx):
            ctx.add("plugin", "observed", {"password": "tiny", "Env": {"HIDDEN": "never-store"},
                                           "Variables": "private variable payload", "State": "dead"})
        b = self.collect(collectors=[plugin])
        text = json.dumps(b)
        self.assertNotIn("tiny", text)
        self.assertNotIn("never-store", text)
        self.assertNotIn("private variable payload", text)
        self.assertEqual(b["observations"][0]["data"]["State"], "dead")

    def test_deadline_and_output_budget(self):
        clock = mock.Mock(side_effect=[0, 21, 21, 21, 21, 21])
        b = self.collect(clock=clock, collectors=[diagnostics.nomad])
        self.assertEqual(b["observations"][0]["status"], "budget_expired")
        def huge(ctx):
            ctx.add("oversized", "observed", "x" * 20000)
            ctx.add("small", "observed", "ok")
        b = self.collect(p=diagnostics.Policy(max_bytes=8192), collectors=[huge])
        self.assertEqual(b["dropped_observations"], 1)
        self.assertLessEqual(len(json.dumps(b).encode()), 8192)
        self.assertEqual(b["observations"][0]["source"], "small")

    def test_oversize_http_response_not_stored(self):
        f = FixtureHTTP()
        f.rows["/v1/job/worker"] = "x" * 100000
        b = self.collect(f)
        self.assertTrue(any(r["status"] == "budget_expired" for r in b["observations"]))
        self.assertNotIn("x" * 1000, json.dumps(b))

    def test_manifest_authenticated_diagnostic_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            r = run()
            artifacts.write_run_artifacts(root, r, secrets=[TOKEN])
            p = artifacts.write_diagnostics(root, r, self.collect())
            result = artifacts.lookup(root, r.target, r.run_id, "diagnostics.json")
            self.assertIsNotNone(result)
            self.assertNotIn(TOKEN.encode(), result[0])
            p.write_text("tampered")
            self.assertIsNone(artifacts.lookup(root, r.target, r.run_id, "diagnostics.json"))

    def test_config_bounds_and_no_url_credentials(self):
        for raw in ({"timeout": 999}, {"lookback": 0}, {"max_bytes": 1}, {"probes": ["file:///etc/passwd"]},
                    {"nomad_addr": "http://user:secret@nomad"}, {"unknown": True}, {"services": "all"}):
            with self.subTest(raw=raw), self.assertRaises(config.ConfigError):
                diagnostics.policy(raw)
        self.assertEqual(diagnostics.policy({"timeout": 10}).timeout, 10)

    def test_allowlisted_error_log_is_bounded_and_sanitized(self):
        f = fixture()
        for aid in ("failed", "replacement"):
            f.rows["/v1/client/fs/stat/" + aid] = {"Size": 12000, "IsDir": False}
            f.rows["/v1/client/fs/readat/" + aid] = "error secret=" + TOKEN
        b = self.collect(f, p=diagnostics.Policy(nomad_addr="http://nomad", error_logs=["main/local/error.log"], logs=True))
        reads = [c for c in f.calls if "/readat/" in c[0]]
        self.assertEqual(len(reads), 2)
        self.assertEqual(reads[0][1]["offset"], "3808")
        self.assertEqual(reads[0][1]["limit"], "8192")
        self.assertNotIn(TOKEN, json.dumps(b))
        with self.assertRaises(config.ConfigError):
            diagnostics.policy({"error_logs": ["main/secrets/token"]})

    def test_policy_loaded_from_target_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp), '[apply]\nenabled=true\n[apply.targets.default]\ndir="terraform"\n[apply.targets.default.diagnostics]\ntimeout=10\nlookback=120\n')
            cfg = config.load(repo)
            self.assertEqual(cfg.targets["default"].diagnostics, {"timeout": 10, "lookback": 120})

    def test_failed_collection_preserves_apply_status_and_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp), '[apply]\nenabled=true\n[apply.diagnostics]\n')
            cfg = config.load(repo)
            apply.configure(cfg)
            cfg.factory.mkdir(exist_ok=True)
            with mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "post_comment", return_value=(True, "")) as post, \
                 mock.patch.object(apply, "apply_escalate"), \
                 mock.patch.object(diagnostics, "collect", side_effect=RuntimeError("private path")), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                ok = apply.apply_one({"ticket": 1, "pr": 2, "commit": "abcd1234"}, False,
                                     adapter=deploy.FakeDeployAdapter(execute_error="failed"))
            self.assertFalse(ok)
            state = deploy.get_target_state("default", cfg.factory / "events.jsonl")
            self.assertEqual(state.latest_run.status, deploy.DeployStatus.FAILED)
            self.assertTrue(post.called)
            self.assertNotIn("private path", output.getvalue())

    def test_apply_lists_bundle_before_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp), '[apply]\nenabled=true\n[apply.diagnostics]\n')
            cfg = config.load(repo)
            apply.configure(cfg)
            cfg.factory.mkdir(exist_ok=True)
            def publish(root, target, rid, post):
                self.assertIsNotNone(artifacts.lookup(root, target, rid, "diagnostics.json"))
                return {}
            with mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "apply_escalate"), \
                 mock.patch.object(artifacts, "publish", side_effect=publish) as publication:
                ok = apply.apply_one({"ticket": 1, "pr": 2, "commit": "abcd1234"}, False,
                                     adapter=deploy.FakeDeployAdapter(execute_error="failed"))
            self.assertFalse(ok)
            publication.assert_called_once()

    def test_dry_run_does_not_collect(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp), '[apply]\nenabled=true\n[apply.diagnostics]\n')
            cfg = config.load(repo)
            apply.configure(cfg)
            cfg.factory.mkdir(exist_ok=True)
            with mock.patch.object(apply, "touches_apply_dir", return_value=True), mock.patch.object(diagnostics, "collect") as collect:
                self.assertTrue(apply.apply_one({"ticket": 1, "pr": 2, "commit": "abcd1234"}, True, adapter=deploy.FakeDeployAdapter()))
            collect.assert_not_called()
            self.assertFalse((cfg.factory / "artifacts").exists())

    def test_cli_preserves_journal_and_creates_safe_local_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp), '[apply]\nenabled=true\n[apply.diagnostics]\n')
            cfg = config.load(repo)
            cfg.apply_env = {"NOMAD_TOKEN": TOKEN}
            cfg.factory.mkdir(exist_ok=True)
            dispatch.configure(cfg)
            deploy.record_deploy_run(run())
            before = (cfg.factory / "events.jsonl").read_bytes()
            with mock.patch.object(config, "load", return_value=cfg), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(diagnostics.main(["--run-id", run().run_id]), 0)
            self.assertEqual(before, (cfg.factory / "events.jsonl").read_bytes())
            found = artifacts.lookup(cfg.factory, "default", run().run_id, "diagnostics.json")
            self.assertIsNotNone(found)
            self.assertNotIn(TOKEN.encode(), found[0])

    def test_real_http_get_and_expired_log(self):
        fake = FakeNomad()
        try:
            fake.on("GET", "/v1/job/worker", {"ID": "worker", "Version": 3})
            b = self.collect(f=None, p=diagnostics.Policy(nomad_addr=fake.addr), transport=diagnostics.HTTP())
            self.assertTrue(any(r["status"] == "absent_or_expired" for r in b["observations"]))
            self.assertTrue(fake.requests)
            self.assertTrue(any(r["source"].endswith("/current") and r["status"] == "observed" for r in b["observations"]))
            self.assertEqual({r[0] for r in fake.requests}, {"GET"})
        finally:
            fake.close()

    def test_real_http_permission_and_size_limit(self):
        fake = FakeNomad()
        try:
            fake.on("GET", "/denied", (403, "private error"))
            fake.on("GET", "/large", "x" * 10000)
            http = diagnostics.HTTP()
            with self.assertRaisesRegex(diagnostics.Unavailable, "permission_denied"):
                http.get(fake.addr + "/denied", {}, time.monotonic() + 3, 1024)
            with self.assertRaisesRegex(diagnostics.Unavailable, "response_too_large"):
                http.get(fake.addr + "/large", {}, time.monotonic() + 3, 1024)
        finally:
            fake.close()

    def test_transport_timeout_bounds_dns_and_keeps_credentials_out_of_argv(self):
        with mock.patch.object(diagnostics.subprocess, "run", side_effect=subprocess.TimeoutExpired("reader", 1)) as process:
            with self.assertRaisesRegex(diagnostics.Unavailable, "budget_expired"):
                diagnostics.HTTP().get("http://nomad/v1/job/worker", {"X-Nomad-Token": TOKEN}, time.monotonic() + 1, 1024)
        call = process.call_args
        self.assertNotIn(TOKEN, " ".join(call.args[0]))
        self.assertIn(TOKEN.encode(), call.kwargs["input"])
        self.assertLessEqual(call.kwargs["timeout"], 1)


if __name__ == "__main__":
    unittest.main()
