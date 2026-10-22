"""post-apply target health verification.

Run: python -m unittest tests.test_health
"""

from __future__ import annotations

import json
import socket
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from factory import apply, artifacts, config, deploy, dispatch, health
from tests.test_factory import make_repo

TOKEN = "nomad-acl-token-0123456789abcdef"


class FakeNomad:
    """A scripted Nomad HTTP API. Each route answers its responses in order,
    repeating the last one; unscripted routes are 404."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], list[tuple[int, object]]] = {}
        self.requests: list[tuple[str, str, dict, str]] = []
        self.consul_tokens: list[str] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self) -> None:
                url = urllib.parse.urlsplit(self.path)
                query = dict(urllib.parse.parse_qsl(url.query))
                path = urllib.parse.unquote(url.path)
                fake.requests.append((self.command, path, query, self.headers.get("X-Nomad-Token", "")))
                fake.consul_tokens.append(self.headers.get("X-Consul-Token", ""))
                seq = fake.routes.get((self.command, path))
                status, body = (seq.pop(0) if len(seq) > 1 else seq[0]) if seq else (404, "job not found")
                data = (body if isinstance(body, str) else json.dumps(body)).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = _answer

            def log_message(self, *args) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addr = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def on(self, method: str, path: str, *responses) -> None:
        self.routes[(method, path)] = [r if isinstance(r, tuple) else (200, r) for r in responses]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def plan_with(*changes: tuple[str, list[str], dict]) -> dict:
    rcs = []
    for name, actions, values in changes:
        before = values if actions == ["delete"] else None
        after = None if actions == ["delete"] else values
        rcs.append({"address": f"nomad_job.{name.replace('-', '_')}", "mode": "managed", "type": "nomad_job",
                    "change": {"actions": actions, "before": before, "after": after}})
    return {"resource_changes": rcs}


def job(name: str, **values) -> tuple[str, list[str], dict]:
    return name, values.pop("actions", ["update"]), {"name": name, "namespace": "default", "region": "home", **values}


def policy(**kw) -> config.VerifyPolicy:
    return config.VerifyPolicy(**{"nomad": True, "timeout": 3, "interval": 1, **kw})


PERIODIC = {"Type": "batch", "Version": 4, "Status": "running", "Periodic": {"Enabled": True, "Spec": "*/30 * * * *"}}
SERVICE = {"Type": "service", "Version": 7, "Status": "running", "TaskGroups": [{"Name": "web", "Count": 2}]}


class NomadJobsFromPlanTest(unittest.TestCase):
    def test_only_changed_managed_nomad_jobs_are_observed(self) -> None:
        plan = plan_with(job("created", actions=["create"]), job("updated"), job("same", actions=["no-op"]),
                         job("gone", actions=["delete"]), job("replaced", actions=["delete", "create"]))
        plan["resource_changes"].append({"address": "nomad_variable.v", "type": "nomad_variable",
                                         "change": {"actions": ["update"], "after": {"path": "x"}}})
        jobs = health.nomad_jobs(plan)
        self.assertEqual([(j["id"], j["removed"]) for j in jobs],
                         [("created", False), ("updated", False), ("gone", True), ("replaced", False)])

    def test_unknown_job_name_is_unhealthy_not_skipped(self) -> None:
        plan = {"resource_changes": [{"address": "nomad_job.x", "type": "nomad_job",
                                      "change": {"actions": ["create"], "after": {"jobspec": "..."}}}]}
        ok, reason, ev = health.verify(policy(), plan=plan, cwd=Path("."), env={"NOMAD_ADDR": "http://127.0.0.1:9"})
        self.assertFalse(ok)
        self.assertEqual(ev["items"][0]["state"], "unhealthy")
        self.assertIn("job ID is unknown", reason)


class NomadPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.nomad = FakeNomad()
        self.env = {"NOMAD_ADDR": self.nomad.addr, "NOMAD_TOKEN": TOKEN}

    def tearDown(self) -> None:
        self.nomad.close()

    def verify(self, plan: dict, **kw):
        return health.verify(policy(**kw), plan=plan, cwd=Path("."), env=self.env)

    def test_periodic_job_registered_and_enabled_is_healthy(self) -> None:
        self.nomad.on("GET", "/v1/job/collector", PERIODIC)
        ok, reason, ev = self.verify(plan_with(job("collector")))
        self.assertTrue(ok, reason)
        self.assertEqual(ev["verdict"], "healthy")
        item = ev["items"][0]
        self.assertEqual((item["policy"], item["state"]), ("periodic-registered", "healthy"))
        _method, _path, query, token = self.nomad.requests[0]
        self.assertEqual((query["namespace"], query["region"], token), ("default", "home", TOKEN))
        self.assertNotIn(TOKEN, json.dumps(ev))

    def test_periodic_job_with_launches_disabled_fails(self) -> None:
        self.nomad.on("GET", "/v1/job/collector", {**PERIODIC, "Periodic": {"Enabled": False}})
        ok, reason, _ = self.verify(plan_with(job("collector")))
        self.assertFalse(ok)
        self.assertIn("periodic launches are disabled", reason)

    def test_stopped_job_fails(self) -> None:
        self.nomad.on("GET", "/v1/job/collector", {**PERIODIC, "Stop": True})
        ok, _, ev = self.verify(plan_with(job("collector")))
        self.assertFalse(ok)
        self.assertEqual(ev["items"][0]["detail"], "job is stopped")

    def test_forced_launch_must_complete(self) -> None:
        self.nomad.on("GET", "/v1/job/collector", PERIODIC)
        old = {"ID": "collector/periodic-100", "ParentID": "collector", "SubmitTime": 100}
        new = {"ID": "collector/periodic-200", "ParentID": "collector", "SubmitTime": 200}
        self.nomad.on("GET", "/v1/jobs", [old], [old, new])
        self.nomad.on("POST", "/v1/job/collector/periodic/force", {"EvalID": "e1"})
        self.nomad.on("GET", "/v1/job/collector/periodic-200", {"Status": "running"}, {"Status": "dead"})
        self.nomad.on("GET", "/v1/job/collector/periodic-200/allocations", [{"ClientStatus": "complete"}])
        ok, reason, ev = self.verify(plan_with(job("collector")), periodic="launch", timeout=10)
        self.assertTrue(ok, reason)
        item = ev["items"][0]
        self.assertEqual(item["observed"]["launched"], "collector/periodic-200")
        forces = [r for r in self.nomad.requests if r[0] == "POST"]
        self.assertEqual(len(forces), 1)  # one launch per verification, never per poll

    def test_forced_launch_that_fails_is_unhealthy(self) -> None:
        self.nomad.on("GET", "/v1/job/collector", PERIODIC)
        self.nomad.on("GET", "/v1/jobs", [], [{"ID": "collector/periodic-9", "ParentID": "collector"}])
        self.nomad.on("POST", "/v1/job/collector/periodic/force", {"EvalID": "e1"})
        self.nomad.on("GET", "/v1/job/collector/periodic-9", {"Status": "dead"})
        self.nomad.on("GET", "/v1/job/collector/periodic-9/allocations", [{"ClientStatus": "failed"}])
        ok, reason, ev = self.verify(plan_with(job("collector")), periodic="launch", timeout=10)
        self.assertFalse(ok)
        self.assertIn("finished without completing", reason)
        self.assertEqual(ev["items"][0]["observed"]["launch_allocations"], {"failed": 1})

    def test_service_waits_for_successful_deployment(self) -> None:
        self.nomad.on("GET", "/v1/job/web", SERVICE)
        self.nomad.on("GET", "/v1/job/web/deployment",
                      {"ID": "d1234567-x", "JobVersion": 7, "Status": "running"},
                      {"ID": "d1234567-x", "JobVersion": 7, "Status": "successful"})
        ok, reason, ev = self.verify(plan_with(job("web")))
        self.assertTrue(ok, reason)
        self.assertEqual(ev["items"][0]["polls"], 2)

    def test_service_failed_deployment_fails_without_waiting_out_the_window(self) -> None:
        self.nomad.on("GET", "/v1/job/web", SERVICE)
        self.nomad.on("GET", "/v1/job/web/deployment",
                      {"ID": "d1", "JobVersion": 7, "Status": "failed", "StatusDescription": "Failed due to progress deadline"})
        ok, reason, ev = self.verify(plan_with(job("web")), timeout=60)
        self.assertFalse(ok)
        self.assertIn("progress deadline", reason)
        self.assertLess(ev["elapsed_sec"], 5)

    def test_service_without_deployment_counts_current_allocations(self) -> None:
        self.nomad.on("GET", "/v1/job/web", SERVICE)
        stale = {"JobVersion": 6, "DesiredStatus": "run", "ClientStatus": "running"}
        cur = {"TaskGroup": "web", "JobVersion": 7, "DesiredStatus": "run", "ClientStatus": "running"}
        self.nomad.on("GET", "/v1/job/web/allocations", [stale, cur], [stale, cur, cur])
        ok, reason, ev = self.verify(plan_with(job("web")))
        self.assertTrue(ok, reason)
        self.assertEqual(ev["items"][0]["observed"]["allocations"], {"groups": {"web": {"running": 2, "wanted": 2}}, "failed": 0})

    def test_service_that_never_converges_times_out(self) -> None:
        self.nomad.on("GET", "/v1/job/web", SERVICE)
        self.nomad.on("GET", "/v1/job/web/allocations",
                      [{"JobVersion": 7, "DesiredStatus": "run", "ClientStatus": "failed"}])
        ok, reason, ev = self.verify(plan_with(job("web")), timeout=2)
        self.assertFalse(ok)
        self.assertEqual(ev["items"][0]["state"], "timeout")
        self.assertIn("0/2 allocation(s)", reason)

    def test_removed_job_must_be_gone(self) -> None:
        ok, reason, ev = self.verify(plan_with(job("old", actions=["delete"])))
        self.assertTrue(ok, reason)
        self.assertEqual(ev["items"][0]["detail"], "removed")

    def test_unreachable_nomad_fails_after_the_window_and_never_raises(self) -> None:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        ok, reason, ev = health.verify(policy(timeout=2), plan=plan_with(job("collector")), cwd=Path("."),
                                       env={"NOMAD_ADDR": f"127.0.0.1:{port}"})
        self.assertFalse(ok)
        self.assertEqual(ev["items"][0]["state"], "timeout")
        self.assertIn("Nomad API unavailable", reason)

    def test_missing_address_fails(self) -> None:
        ok, reason, _ = health.verify(policy(), plan=plan_with(job("collector")), cwd=Path("."), env={})
        self.assertFalse(ok)
        self.assertIn("no Nomad address", reason)

    def test_plan_without_nomad_jobs_has_nothing_to_observe(self) -> None:
        ok, _, ev = self.verify({"resource_changes": []})
        self.assertTrue(ok)
        self.assertEqual(ev["verdict"], "nothing_to_observe")


CONSUL_TOKEN = "consul-acl-token-fedcba9876543210"
JOBSPEC = 'job "web" {\n  group "web" {\n    count = 2\n    # image = "acme/web:0.1"\n    task "server" {\n      config { image = "acme/web:2.0" }\n    }\n  }\n}\n'
WEB = {"ID": "web", "Type": "service", "Version": 8, "Status": "running",
       "TaskGroups": [{"Name": "web", "Count": 2, "Tasks": [
           {"Name": "server", "Config": {"image": "acme/web:2.0"}, "Services": [{"Name": "web", "Provider": "consul"}]}]}]}
OLD1, OLD2 = "0000aaaa-0000-0000-0000-000000000001", "0000aaaa-0000-0000-0000-000000000002"
NEW1, NEW2 = "bbbb0000-0000-0000-0000-000000000001", "bbbb0000-0000-0000-0000-000000000002"


def alloc(aid: str, version: int = 8, client: str = "running", desired: str = "run", group: str = "web") -> dict:
    return {"ID": aid, "TaskGroup": group, "JobVersion": version, "DesiredStatus": desired, "ClientStatus": client}


def entry(aid: str, status: str = "passing", service: str = "web") -> dict:
    """A Consul /v1/health/service row for a Nomad-registered task service."""
    return {"Node": {"Node": "client-1"},
            "Service": {"ID": f"_nomad-task-{aid}-server-{service}-http", "Service": service, "Tags": []},
            "Checks": [{"CheckID": "serfHealth", "Status": "passing"},
                       {"CheckID": f"_nomad-check-{aid[:8]}", "Status": status}]}


def web_plan(**values) -> dict:
    return plan_with(job("web", jobspec=JOBSPEC, **values))


class ConsulServicePolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.nomad = FakeNomad()
        self.consul = FakeNomad()
        self.addCleanup(self.nomad.close)
        self.addCleanup(self.consul.close)
        self.env = {"NOMAD_ADDR": self.nomad.addr, "NOMAD_TOKEN": TOKEN,
                    "CONSUL_HTTP_ADDR": self.consul.addr, "CONSUL_HTTP_TOKEN": CONSUL_TOKEN}

    def verify(self, plan: dict, env: dict | None = None, **kw):
        kw = {"nomad": False, "consul": True, **kw}
        return health.verify(policy(**kw), plan=plan, cwd=Path("."), env=self.env if env is None else env)

    def serve(self, *allocs: list[dict], live: dict = WEB) -> None:
        self.nomad.on("GET", "/v1/job/web", live)
        self.nomad.on("GET", "/v1/job/web/allocations", *allocs)

    def test_passing_instances_of_the_new_version_are_healthy(self) -> None:
        self.serve([alloc(NEW1), alloc(NEW2)])
        self.consul.on("GET", "/v1/health/service/web", [entry(NEW1), entry(NEW2)])
        ok, reason, ev = self.verify(web_plan())
        self.assertTrue(ok, reason)
        self.assertEqual(ev["verdict"], "healthy")
        item = ev["items"][0]
        self.assertEqual((item["kind"], item["id"], item["policy"], item["state"]),
                         ("consul_service", "web", "consul", "healthy"))
        self.assertEqual(item["observed"]["services"]["web"],
                         {"expected": 2, "passing": 2, "failing": 0, "stale": 0, "other": 0})
        self.assertEqual((item["observed"]["job_version"], item["observed"]["image_check"]), (8, "matched"))
        self.assertIn(CONSUL_TOKEN, self.consul.consul_tokens)
        self.assertNotIn(CONSUL_TOKEN, self.nomad.consul_tokens)  # never sent to Nomad
        self.assertNotIn(CONSUL_TOKEN, json.dumps(ev) + reason)
        self.assertNotIn("acme/web:0.1", json.dumps(ev))  # commented image ignored, jobspec never recorded

    def test_critical_new_instance_is_not_healthy(self) -> None:
        self.serve([alloc(NEW1), alloc(NEW2)])
        self.consul.on("GET", "/v1/health/service/web", [entry(NEW1), entry(NEW2, "critical")])
        ok, reason, ev = self.verify(web_plan(), timeout=2)
        self.assertFalse(ok)
        self.assertEqual(ev["items"][0]["state"], "timeout")
        self.assertIn("`web` Consul services timeout", reason)
        self.assertIn("web: 1/2 passing on version 8 (1 not passing)", reason)

    def test_missing_registration_is_not_healthy(self) -> None:
        self.serve([alloc(NEW1), alloc(NEW2)])
        self.consul.on("GET", "/v1/health/service/web", [])
        ok, reason, _ = self.verify(web_plan(), timeout=2)
        self.assertFalse(ok)
        self.assertIn("0/2 passing on version 8 (no registration from the new allocations)", reason)

    def test_stale_passing_registrations_do_not_hide_a_failed_new_allocation(self) -> None:
        self.serve([alloc(OLD1, 7), alloc(OLD2, 7), alloc(NEW1, client="failed")])
        # Consul still lists the old allocations as passing: a plain count would say 2/2.
        self.consul.on("GET", "/v1/health/service/web", [entry(OLD1), entry(OLD2)])
        ok, reason, ev = self.verify(web_plan(), timeout=2)
        self.assertFalse(ok)
        self.assertNotEqual(ev["verdict"], "healthy")
        self.assertIn("0/2 passing on version 8", reason)
        self.assertIn("2 from older allocations ignored", reason)
        self.assertEqual(ev["items"][0]["observed"]["services"]["web"]["stale"], 2)

    def test_registrations_from_unknown_allocations_never_count(self) -> None:
        self.serve([alloc(NEW1), alloc(NEW2)])
        foreign = {"Service": {"ID": "web-manual-1", "Service": "web"}, "Checks": []}
        self.consul.on("GET", "/v1/health/service/web", [entry(NEW1), foreign])
        ok, _, ev = self.verify(web_plan(), timeout=2)
        self.assertFalse(ok)
        self.assertEqual(ev["items"][0]["observed"]["services"]["web"]["other"], 1)

    def test_rolling_update_waits_for_the_new_allocations(self) -> None:
        self.serve([alloc(OLD1, 7), alloc(OLD2, 7), alloc(NEW1)],
                   [alloc(OLD1, 7, desired="stop", client="complete"), alloc(OLD2, 7), alloc(NEW1), alloc(NEW2)],
                   [alloc(OLD1, 7, desired="stop", client="complete"),
                    alloc(OLD2, 7, desired="stop", client="complete"), alloc(NEW1), alloc(NEW2)])
        self.consul.on("GET", "/v1/health/service/web",
                       [entry(OLD1), entry(OLD2), entry(NEW1)],
                       [entry(OLD2), entry(NEW1), entry(NEW2, "critical")],
                       [entry(NEW1), entry(NEW2)])
        ok, reason, ev = self.verify(web_plan(), timeout=10)
        self.assertTrue(ok, reason)
        item = ev["items"][0]
        self.assertEqual(item["polls"], 3)
        self.assertEqual(item["observed"]["services"]["web"]["passing"], 2)

    def test_wrong_image_on_the_live_job_fails_at_once(self) -> None:
        live = json.loads(json.dumps(WEB))
        live["TaskGroups"][0]["Tasks"][0]["Config"]["image"] = "acme/web:1.9"
        self.serve([alloc(NEW1), alloc(NEW2)], live=live)
        self.consul.on("GET", "/v1/health/service/web", [entry(NEW1), entry(NEW2)])
        ok, reason, ev = self.verify(web_plan(), timeout=60)
        self.assertFalse(ok)
        self.assertEqual(ev["items"][0]["state"], "unhealthy")
        self.assertIn("does not run the applied image(s) acme/web:2.0", reason)
        self.assertLess(ev["elapsed_sec"], 5)

    def test_job_version_change_during_the_window_fails(self) -> None:
        self.nomad.on("GET", "/v1/job/web", WEB, {**WEB, "Version": 9})
        self.nomad.on("GET", "/v1/job/web/allocations", [alloc(NEW1)])
        self.consul.on("GET", "/v1/health/service/web", [entry(NEW1)])
        ok, reason, _ = self.verify(web_plan(), timeout=10)
        self.assertFalse(ok)
        self.assertIn("job version changed from 8 to 9", reason)

    def test_failed_deployment_of_the_version_fails_at_once(self) -> None:
        self.serve([alloc(OLD1, 7), alloc(OLD2, 7)])
        self.nomad.on("GET", "/v1/job/web/deployment", {"ID": "d1", "JobVersion": 8, "Status": "failed"})
        self.consul.on("GET", "/v1/health/service/web", [entry(OLD1), entry(OLD2)])
        ok, reason, ev = self.verify(web_plan(), timeout=60)
        self.assertFalse(ok)
        self.assertIn("deployment of version 8 failed", reason)
        self.assertLess(ev["elapsed_sec"], 5)

    def test_no_op_plan_observes_nothing(self) -> None:
        ok, _, ev = self.verify(web_plan(actions=["no-op"]))
        self.assertTrue(ok)
        self.assertEqual((ev["verdict"], ev["items"]), ("nothing_to_observe", []))
        self.assertEqual(self.nomad.requests + self.consul.requests, [])

    def test_removed_job_and_job_without_services_are_explicitly_skipped(self) -> None:
        self.nomad.on("GET", "/v1/job/worker", {"ID": "worker", "Type": "service", "Version": 1,
                                                "TaskGroups": [{"Name": "w", "Count": 1, "Tasks": [{"Name": "t"}]}]})
        plan = plan_with(job("old", actions=["delete"]), job("worker"))
        ok, reason, ev = self.verify(plan)
        self.assertTrue(ok, reason)
        self.assertEqual(ev["verdict"], "nothing_to_observe")
        self.assertEqual([(i["id"], i["state"], i["detail"]) for i in ev["items"]],
                         [("old", "skipped", "removed by the plan; no services required"),
                          ("worker", "skipped", "job declares no Consul services")])
        self.assertEqual(self.consul.requests, [])
        # Beside a healthy Nomad item a skipped one keeps the verdict healthy.
        self.nomad.on("GET", "/v1/job/worker/deployment", {"ID": "d", "JobVersion": 1, "Status": "successful"})
        ok, _, ev = self.verify(plan_with(job("worker")), nomad=True)
        self.assertTrue(ok)
        self.assertEqual([i["state"] for i in ev["items"]], ["healthy", "skipped"])
        self.assertEqual(ev["verdict"], "healthy")

    def test_batch_jobs_are_skipped(self) -> None:
        self.nomad.on("GET", "/v1/job/web", PERIODIC)
        ok, _, ev = self.verify(plan_with(job("web")))
        self.assertTrue(ok)
        self.assertEqual(ev["items"][0]["state"], "skipped")

    def test_consul_address_from_config_wins_over_env(self) -> None:
        other = FakeNomad()
        self.addCleanup(other.close)
        self.serve([alloc(NEW1), alloc(NEW2)])
        for fake in (self.consul, other):
            fake.on("GET", "/v1/health/service/web", [entry(NEW1), entry(NEW2)])
        ok, reason, _ = self.verify(web_plan(), consul_addr=other.addr)
        self.assertTrue(ok, reason)
        self.assertTrue(other.requests)
        self.assertEqual(self.consul.requests, [])
        ok, reason, _ = self.verify(web_plan())  # no consul_addr: CONSUL_HTTP_ADDR
        self.assertTrue(ok, reason)
        self.assertTrue(self.consul.requests)

    def test_missing_consul_address_fails(self) -> None:
        self.serve([alloc(NEW1)])
        env = {k: v for k, v in self.env.items() if k != "CONSUL_HTTP_ADDR"}
        ok, reason, _ = self.verify(web_plan(), env=env)
        self.assertFalse(ok)
        self.assertIn("no Consul address", reason)

    def test_unreachable_consul_fails_closed_within_the_window(self) -> None:
        self.serve([alloc(NEW1), alloc(NEW2)])
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        env = {**self.env, "CONSUL_HTTP_ADDR": f"127.0.0.1:{port}"}
        ok, reason, ev = self.verify(web_plan(), env=env, timeout=2)
        self.assertFalse(ok)
        self.assertEqual(ev["items"][0]["state"], "timeout")
        self.assertIn("Consul API unavailable", reason)
        self.assertLess(ev["elapsed_sec"], 4)
        self.assertNotIn(CONSUL_TOKEN, json.dumps(ev) + reason)


class ConsulServiceHelpersTest(unittest.TestCase):
    def test_jobspec_images_keeps_only_literals(self) -> None:
        hcl = 'task "a" {\n  config { image = "acme/a:1" }\n}\n// image = "acme/old:0"\n/* image = "acme/older:0" */\ntask "b" {\n  config { image = "${var.image}" }\n}\n'
        self.assertEqual(health.jobspec_images(hcl), ["acme/a:1"])
        js = json.dumps({"Job": {"TaskGroups": [{"Tasks": [{"Config": {"image": "acme/api:3"}}]}]}})
        self.assertEqual(health.jobspec_images(js), ["acme/api:3"])
        self.assertEqual(health.jobspec_images(None), [])

    def test_service_alloc_parses_nomad_service_ids(self) -> None:
        self.assertEqual(health.service_alloc(f"_nomad-task-{NEW1}-server-web-http"), NEW1)
        self.assertEqual(health.service_alloc(f"_nomad-task-{NEW1}-group-web-web-http"), NEW1)
        self.assertEqual(health.service_alloc("web-1"), "")
        self.assertEqual(health.service_alloc(None), "")

    def test_declared_services_counts_per_group_and_skips_nomad_provider(self) -> None:
        live = {"TaskGroups": [
            {"Name": "api", "Services": [{"Name": "${JOB}-api"}, {"Name": "native", "Provider": "nomad"}],
             "Tasks": [{"Name": "srv", "Services": [{"Name": "metrics"}, {"Name": ""}]}]},
            {"Name": "edge", "Tasks": [{"Name": "proxy", "Services": [{"Name": "metrics"}]}]}]}
        self.assertEqual(health.declared_services("acme", live),
                         {"acme-api": {"api": 1}, "metrics": {"api": 1, "edge": 1}, "acme-api-srv": {"api": 1}})

    def test_system_job_expects_every_running_new_allocation(self) -> None:
        live = {"ID": "agent", "Type": "system", "Version": 3,
                "TaskGroups": [{"Name": "web", "Count": 1, "Tasks": [{"Name": "server", "Services": [{"Name": "web"}]}]}]}
        allocs = [alloc(NEW1, 3), alloc(NEW2, 3)]

        def nomad(method, path, params=None):
            return allocs if path.endswith("/allocations") else None if path.endswith("/deployment") else live

        item = health.ConsulServices({"id": "agent", "namespace": "default", "region": "", "address": "", "removed": False})
        state, detail = item.step(nomad, lambda *a: [entry(NEW1)])
        self.assertEqual(state, health.PENDING)
        self.assertIn("1/2 passing", detail)


class CheckPolicyTest(unittest.TestCase):
    def test_check_is_retried_until_it_passes(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            marker = Path(d) / "seen"
            script = f"import pathlib,sys; p=pathlib.Path({str(marker)!r}); ok=p.exists(); p.touch(); print('up' if ok else 'starting'); sys.exit(0 if ok else 1)"
            pol = config.VerifyPolicy(timeout=5, interval=1, checks=[config.Check("probe", ["python3", "-c", script])])
            ok, reason, ev = health.verify(pol, plan=None, cwd=Path(d), env={})
            self.assertTrue(ok, reason)
            self.assertEqual((ev["items"][0]["attempts"], ev["items"][0]["detail"]), (2, "up"))

    def test_failing_check_fails_with_its_output(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            pol = config.VerifyPolicy(timeout=2, interval=1, checks=[
                config.Check("probe", ["python3", "-c", "import os; print('down', os.environ['PROBE_URL']); raise SystemExit(1)"])])
            ok, reason, ev = health.verify(pol, plan=None, cwd=Path(d), env={"PROBE_URL": "http://svc"})
            self.assertFalse(ok)
            self.assertIn("down http://svc", reason)
            self.assertEqual(ev["items"][0]["state"], "timeout")


class VerifyConfigTest(unittest.TestCase):
    def load(self, toml: str) -> config.Config:
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        return config.load(make_repo(Path(d.name), toml))

    def test_target_verify_table_parses(self) -> None:
        cfg = self.load("""
[apply]
enabled = true
[apply.targets.collectors]
dir = "terraform/collectors"
[apply.targets.collectors.verify]
nomad = true
nomad_addr = "nomad.service.consul:4646"
timeout = 600
periodic = "launch"
[[apply.targets.collectors.verify.check]]
name = "results-api"
run = ["curl", "-fsS", "http://results/health"]
timeout = 10
""")
        pol = cfg.targets["collectors"].verify
        self.assertEqual((pol.nomad, pol.nomad_addr, pol.timeout, pol.interval, pol.periodic),
                         (True, "nomad.service.consul:4646", 600, 5, "launch"))
        self.assertEqual([(c.name, c.timeout) for c in pol.checks], [("results-api", 10)])

    def test_consul_options_parse_and_activate_the_policy(self) -> None:
        cfg = self.load("""
[apply]
enabled = true
[apply.targets.web]
dir = "terraform/web"
[apply.targets.web.verify]
consul = true
consul_addr = "consul.example.invalid:8500"
""")
        pol = cfg.targets["web"].verify
        self.assertEqual((pol.consul, pol.consul_addr, pol.nomad), (True, "consul.example.invalid:8500", False))
        self.assertTrue(pol.active)

    def test_default_target_reads_apply_verify_and_unset_is_off(self) -> None:
        cfg = self.load("[apply]\nenabled = true\n[apply.verify]\nnomad = true\n")
        self.assertTrue(cfg.targets["default"].verify.active)
        self.assertIsNone(self.load("[apply]\nenabled = true\n").targets["default"].verify)

    def test_invalid_verify_tables_are_refused(self) -> None:
        for body, msg in [
            ("[apply.verify]\nnomad = true\nperiodc = 'launch'\n", "unknown key"),
            ("[apply.verify]\nperiodic = 'always'\n", "periodic must be one of"),
            ("[apply.verify]\ntimeout = 0\n", "positive integer"),
            ("[apply.verify]\ntimeout = 5\ninterval = 10\n", "must not exceed"),
            ("[apply.verify]\nnomad = 'yes'\n", "true or false"),
            ("[apply.verify]\nconsul = 1\n", "consul must be true or false"),
            ("[apply.verify]\nconsul_addr = 8500\n", "consul_addr must be a string"),
            ("[[apply.verify.check]]\nname = 'x'\nrun = 'curl'\n", "non-empty list"),
            ("[[apply.verify.check]]\nname = 'x'\nrun = ['a']\nexclusive = true\n", "allowed keys"),
            ("[apply.targets.a]\ndir = 'a'\n[apply.verify]\nnomad = true\n", "default target only"),
        ]:
            with self.subTest(msg=msg), self.assertRaises(config.ConfigError) as cm:
                self.load("[apply]\nenabled = true\n" + body)
            self.assertIn(msg, str(cm.exception))


class ApplyVerificationTest(unittest.TestCase):
    """Acceptance: apply success plus an unhealthy runtime is a failed run."""

    def run_apply(self, nomad: FakeNomad, tmp: Path) -> tuple[deploy.DeployRun, list[str], dict]:
        repo = make_repo(tmp, f"""
[apply]
enabled = true
[apply.targets.collectors]
dir = "terraform/collectors"
adapter = "fake"
[apply.targets.collectors.verify]
nomad = true
nomad_addr = "{nomad.addr}"
timeout = 3
interval = 1
""")
        cfg = config.load(repo)
        cfg.apply_env = {"NOMAD_TOKEN": TOKEN}
        dispatch.configure(cfg)
        apply.configure(cfg)
        cfg.factory.mkdir(parents=True, exist_ok=True)

        class PlanAdapter(deploy.FakeDeployAdapter):
            verify = deploy.DeployAdapter.verify  # the real policy-driven hook

            def check(self, ctx):
                ctx.metadata["plan"] = plan_with(job("collector"))
                return True, ""

        escalations: list[str] = []
        with mock.patch.object(apply, "touches_target_dir", return_value=True), \
             mock.patch.object(apply, "post_comment", return_value=(True, "")), \
             mock.patch.object(apply, "apply_escalate", side_effect=lambda n, pr, reason, **kw: escalations.append(reason)):
            apply.apply_one({"ticket": 5, "pr": 6, "commit": "abcdef123456"}, dry_run=False,
                            target="collectors", adapter=PlanAdapter())
        rows = [json.loads(line) for line in (cfg.factory / "events.jsonl").read_text().splitlines()]
        final = [r for r in rows if r.get("event") == "deploy_run" and r.get("status") != "running"]
        self.assertEqual(len(final), 1)
        run = deploy.DeployRun.from_dict({k: v for k, v in final[0].items() if k not in ("event", "at")})
        summary = json.loads((artifacts.artifact_dir(cfg.factory, "collectors", run.run_id) / "summary.json").read_text())
        return run, escalations, summary

    def test_unhealthy_runtime_after_successful_apply_is_a_failed_run(self) -> None:
        nomad = FakeNomad()
        self.addCleanup(nomad.close)
        nomad.on("GET", "/v1/job/collector", {**PERIODIC, "Periodic": {"Enabled": False}})
        with tempfile.TemporaryDirectory() as d:
            run, escalations, summary = self.run_apply(nomad, Path(d))
        self.assertEqual(run.status, deploy.DeployStatus.FAILED)
        self.assertIn("post-apply health verification failed", run.error)
        self.assertEqual(run.verification["verdict"], "unhealthy")
        self.assertEqual(summary["verification"]["items"][0]["detail"], "periodic launches are disabled")
        self.assertEqual(len(escalations), 1)
        self.assertIn("health verification failed", escalations[0])
        body = artifacts.render_comment(summary)
        self.assertIn("Health verification: **unhealthy**", body)
        self.assertNotIn(TOKEN, json.dumps(summary) + body + json.dumps(run.to_dict()))

    def test_healthy_runtime_succeeds_with_evidence(self) -> None:
        nomad = FakeNomad()
        self.addCleanup(nomad.close)
        nomad.on("GET", "/v1/job/collector", PERIODIC)
        with tempfile.TemporaryDirectory() as d:
            run, escalations, summary = self.run_apply(nomad, Path(d))
        self.assertEqual(run.status, deploy.DeployStatus.SUCCEEDED)
        self.assertEqual(escalations, [])
        self.assertEqual(summary["verification"]["verdict"], "healthy")
        self.assertEqual(nomad.requests[0][3], TOKEN)  # apply-env token reached Nomad

    def test_verifier_crash_fails_the_run_instead_of_leaving_it_running(self) -> None:
        nomad = FakeNomad()
        self.addCleanup(nomad.close)
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(health, "verify", side_effect=RuntimeError("boom")):
            run, _escalations, _ = self.run_apply(nomad, Path(d))
        self.assertEqual(run.status, deploy.DeployStatus.FAILED)
        self.assertIn("raised RuntimeError", run.error)


class HealthRegressionTest(unittest.TestCase):
    def test_missing_group_cannot_be_hidden_by_extra_allocations(self):
        live = {
            "Type": "service",
            "Version": 7,
            "TaskGroups": [{"Name": "web", "Count": 1}, {"Name": "worker", "Count": 1}],
        }
        allocs = [
            {
                "TaskGroup": "web",
                "JobVersion": 7,
                "DesiredStatus": "run",
                "ClientStatus": "running",
            }
        ] * 2

        def api(method, path, params=None):
            if path.endswith("/deployment"):
                return None
            if path.endswith("/allocations"):
                return allocs
            return live

        item = health.NomadJob(
            {"id": "web", "namespace": "default", "region": "", "removed": False},
            "registered",
        )
        state, _ = item.step(api)
        self.assertEqual(state, health.PENDING)
        self.assertEqual(item.observed["allocations"]["groups"]["worker"]["running"], 0)

    def test_observation_after_deadline_is_not_healthy(self):
        now = [0.0]

        def api(*args):
            now[0] += 10
            return PERIODIC

        ok, _, evidence = health.verify(
            policy(timeout=1),
            plan=plan_with(job("collector")),
            cwd=Path("."),
            env={},
            api=api,
            clock=lambda: now[0],
            sleep=lambda _: None,
        )
        self.assertFalse(ok)
        self.assertEqual(evidence["items"][0]["state"], "timeout")

    def test_deadline_prevents_starting_another_item(self):
        now = [0.0]
        calls = []

        def api(method, path, params=None):
            calls.append(path)
            now[0] += 2
            return PERIODIC

        ok, _, evidence = health.verify(
            policy(timeout=1),
            plan=plan_with(job("one"), job("two")),
            cwd=Path("."),
            env={},
            api=api,
            clock=lambda: now[0],
            sleep=lambda _: None,
        )
        self.assertFalse(ok)
        self.assertEqual(len(calls), 1)
        self.assertEqual(evidence["items"][1]["polls"], 0)

    def test_http_timeout_uses_remaining_window(self):
        with mock.patch.object(
            health.urllib.request, "urlopen", side_effect=OSError("down")
        ) as request:
            api = health.nomad_api("http://nomad", deadline=1.5, clock=lambda: 1.0)
            with self.assertRaises(health.NomadError):
                api("GET", "/v1/job/test")
            self.assertEqual(request.call_args.kwargs["timeout"], 0.5)
            expired = health.nomad_api("http://nomad", deadline=1, clock=lambda: 2)
            with self.assertRaises(health.NomadError):
                expired("GET", "/v1/job/test")
            self.assertEqual(request.call_count, 1)

    def test_system_job_with_queued_placement_is_not_healthy(self):
        live = {
            "Type": "system",
            "Version": 7,
            "TaskGroups": [{"Name": "agent", "Count": 1}],
        }

        def api(method, path, params=None):
            if path.endswith("/deployment"):
                return None
            if path.endswith("/allocations"):
                return [
                    {
                        "TaskGroup": "agent",
                        "JobVersion": 7,
                        "DesiredStatus": "run",
                        "ClientStatus": "running",
                    }
                ]
            if path.endswith("/summary"):
                return {"Summary": {"agent": {"Running": 1, "Queued": 1}}}
            return live

        item = health.NomadJob(
            {"id": "agents", "namespace": "default", "region": "", "removed": False},
            "registered",
        )
        self.assertEqual(item.step(api)[0], health.PENDING)


if __name__ == "__main__":
    unittest.main()
