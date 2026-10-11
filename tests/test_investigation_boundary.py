"""SHA-201 broker/renderer security fixtures, no agents or live API calls."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from factory import artifacts, deploy, diagnostics, incidents, lifecycle
from factory import investigation_evidence as evidence
from factory import investigation_publication as publication

NOW = 1791054000
AID = "11111111-1111-1111-1111-111111111111"
EID = "22222222-2222-2222-2222-222222222222"
SECRET = "unknown-workload-password-do-not-publish"


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.factory = Path(self.temp.name).resolve() / ".factory"
        self.factory.mkdir()
        self.run = deploy.DeployRun("deploy-default-01234567-1", "default", "01234567" * 5, 9, 1,
            deploy.DeployStatus.FAILED, diagnostics.utc(NOW - 60), pr=10,
            completed_at=diagnostics.utc(NOW), error=SECRET, output=SECRET,
            verification={"items": [{"kind": "nomad_job", "id": "worker", "namespace": "infra",
                                      "region": "west", "observed": {"version": 2}}]})
        deploy.record_deploy_run(self.run, self.factory / "events.jsonl")
        self.root_id = incidents.enqueue(self.factory, "acme/widgets", self.run)
        self.path = artifacts.write_run_artifacts(self.factory, self.run)
        job = {"id": "worker", "namespace": "infra", "region": "west", "version": 2}
        def row(source, data, extra=None):
            return {"source": source, "status": "observed", "observed_at": diagnostics.utc(NOW + 1),
                    "lineage": {**job, **(extra or {})}, "data": data}
        self.bundle = {"version": 1, "run_id": self.run.run_id, "target": "default", "commit": self.run.commit,
            "logs_enabled": False, "collected_at": diagnostics.utc(NOW + 1), "dropped_observations": 0,
            "window": {"known": True, "start": self.run.started_at, "end": self.run.completed_at},
            "observations": [
                row("nomad/job/worker/current", {"ID": "worker", "Namespace": "infra", "Version": 3,
                    "Status": "running", "Env": {"password": SECRET}}),
                row("nomad/job/worker/evaluations", [{"ID": EID, "JobID": "worker", "Namespace": "infra",
                    "Status": "blocked", "ModifyTime": (NOW - 30) * 10**9, "StatusDescription": SECRET,
                    "FailedTGAllocs": {SECRET: {"NodesAvailable": {SECRET: 3}, "NodesExhausted": 2,
                        "ConstraintFiltered": {SECRET: 2}, "DimensionExhausted": {"cpu": 2, "memory": 1, SECRET: 5}}}}]),
                row("nomad/job/worker/allocations", [{"ID": AID, "JobID": "worker", "Namespace": "infra",
                    "JobVersion": 2, "ClientStatus": "failed", "DesiredStatus": SECRET,
                    "CreateTime": (NOW - 40) * 10**9, "ModifyTime": (NOW - 10) * 10**9}]),
                row("nomad/allocation/" + AID, {"ID": AID, "JobID": "worker", "Namespace": "infra", "tasks": {
                    SECRET: {"State": "dead", "Failed": True, "Events": [{"Type": "Terminated", "OOMKilled": True,
                        "Time": (NOW - 20) * 10**9, "ExitCode": 137, "DisplayMessage": SECRET}]}}},
                    {"allocation": AID}),
                row("nomad/allocation/" + AID + "/main/stdout", {"text": SECRET}),
                {"source": "consul/health", "status": "observed", "observed_at": diagnostics.utc(NOW + 1),
                 "data": {"Output": SECRET}},
            ]}
        self.write_bundle()

    def tearDown(self):
        self.temp.cleanup()

    def write_bundle(self):
        artifacts.write_diagnostics(self.factory, self.run, self.bundle)

    def read(self, **kw):
        return evidence.read_evidence(self.factory, self.root_id, self.run.run_id, now=kw.get("now", NOW + 2))

    def result(self, projection, **kw):
        return json.dumps({"projection_sha256": projection.sha256, "outcome": "proposal",
            "findings": [{"code": "OOM_EVENT", "refs": ["e0004"]}], "action": "REVIEW_OOM", **kw}).encode()

    def test_projection_omits_unknown_secrets_all_free_text_and_original_ids(self):
        projection = self.read()
        text = projection.payload.decode()
        for secret in (SECRET, "worker", AID, EID, "infra", "west", "DisplayMessage", "StatusDescription", "Output"):
            self.assertNotIn(secret, text)
        rows = projection.data()["rows"]
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]["relation"], "current_state_only")
        self.assertEqual(rows[0]["current_version"], 3)
        self.assertEqual(rows[1]["constraints_filtered"], 2)
        self.assertEqual(rows[1]["cpu_exhausted"], 2)
        self.assertNotIn(SECRET, publication.render(projection, self.result(projection)))

    def test_reader_does_not_write_or_call_network(self):
        before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in self.factory.rglob("*") if p.is_file()}
        with mock.patch.object(diagnostics.HTTP, "get", side_effect=AssertionError("no network")):
            self.read()
        after = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in self.factory.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_manifest_hash_tampering_duplicate_entry_and_unlisted_file_refused(self):
        manifest_path = self.path / "manifest.json"
        original = manifest_path.read_bytes()
        for mode in ("tampered", "duplicate", "unlisted"):
            with self.subTest(mode=mode):
                manifest_path.write_bytes(original)
                manifest = json.loads(original)
                if mode == "tampered":
                    next(e for e in manifest["files"] if e["name"] == "diagnostics.json")["sha256"] = "0" * 64
                elif mode == "duplicate":
                    manifest["files"].append(copy.deepcopy(manifest["files"][-1]))
                else:
                    manifest["files"] = []
                manifest_path.write_text(json.dumps(manifest))
                with self.assertRaises(evidence.EvidenceRefused):
                    self.read()

    def test_symlink_root_parent_manifest_bundle_journal_and_incident_refused(self):
        paths = [self.factory, self.factory / "artifacts", self.path / "manifest.json", self.path / "diagnostics.json",
                 self.factory / "events.jsonl", self.factory / "incidents" / (self.root_id + ".json")]
        for path in paths:
            with self.subTest(path=path.name):
                real = path.with_name(path.name + "-real")
                path.rename(real)
                path.symlink_to(real, target_is_directory=real.is_dir())
                try:
                    with self.assertRaises(evidence.EvidenceRefused):
                        self.read()
                finally:
                    path.unlink()
                    real.rename(path)

    def test_mismatched_identity_and_cross_version_allocations_refused(self):
        original = copy.deepcopy(self.bundle)
        for field, value in (("commit", "f" * 40), ("run_id", "other"), ("target", "elsewhere")):
            self.bundle = copy.deepcopy(original)
            self.bundle[field] = value
            self.write_bundle()
            with self.assertRaises(evidence.EvidenceRefused):
                self.read()
        self.bundle = copy.deepcopy(original)
        self.bundle["observations"][2]["data"][0]["JobVersion"] = 3
        self.write_bundle()
        with self.assertRaises(evidence.EvidenceRefused):
            self.read()

    def test_unsafe_references_stale_future_unknown_time_and_logs_refused(self):
        with self.assertRaises(evidence.EvidenceRefused):
            evidence.read_evidence(self.factory, self.root_id, "../private", now=NOW + 2)
        old = self.read(now=NOW + 7200)
        self.assertEqual(old.data()["rows"][0]["status"], "stale")
        self.assertIn("explicit OOM event", publication.render(old, self.result(old)))
        original = copy.deepcopy(self.bundle)
        for key, value in (("logs_enabled", True), ("collected_at", diagnostics.utc(NOW + 10)), ("dropped_observations", 1)):
            self.bundle = copy.deepcopy(original)
            self.bundle[key] = value
            self.write_bundle()
            with self.assertRaises(evidence.EvidenceRefused):
                self.read()
        self.bundle = copy.deepcopy(original)
        self.bundle["window"]["known"] = False
        self.write_bundle()
        with self.assertRaises(evidence.EvidenceRefused):
            self.read()

    def test_missing_allocation_list_cannot_claim_version_matched_task_events(self):
        self.bundle["observations"].pop(2)
        self.write_bundle()
        with self.assertRaises(evidence.EvidenceRefused):
            self.read()

    def test_file_journal_row_and_projection_budgets_refused(self):
        with mock.patch.object(evidence, "MAX_FILE", 32):
            with self.assertRaises(evidence.EvidenceRefused):
                self.read()
        for limit in ("MAX_ROWS", "MAX_PROJECTION"):
            with self.subTest(limit=limit), mock.patch.object(evidence, limit, 1):
                with self.assertRaises(evidence.EvidenceRefused):
                    self.read()

    def test_rotated_committed_run_read_but_partial_tail_and_resolved_run_refused(self):
        import gzip
        journal = self.factory / "events.jsonl"
        original = journal.read_bytes()
        with gzip.open(self.factory / "events.jsonl.1.gz", "wb") as out:
            out.write(original)
        journal.write_bytes(b'{"event":"deploy_run"')
        self.read()
        journal.write_text(json.dumps({"event": "deploy_acknowledged", "target": "default", "run_id": self.run.run_id}) + "\n")
        with self.assertRaises(evidence.EvidenceRefused):
            self.read()

    def test_unknown_event_type_exit_137_and_current_state_never_prove_oom(self):
        event = self.bundle["observations"][3]["data"]["tasks"][SECRET]["Events"][0]
        for event_type, oom in (("Terminated", False), (SECRET, True)):
            event["Type"] = event_type
            event["OOMKilled"] = oom
            self.write_bundle()
            projection = self.read()
            with self.assertRaises(evidence.EvidenceRefused):
                publication.render(projection, self.result(projection))
        projection = self.read()
        with self.assertRaises(evidence.EvidenceRefused):
            publication.render(projection, self.result(projection, findings=[{"code": "OOM_EVENT", "refs": ["e0001"]}]))

    def test_model_prose_unknown_keys_refs_actions_and_stale_hash_never_render(self):
        projection = self.read()
        mutations = [{"text": SECRET}, {"action": SECRET}, {"projection_sha256": "0" * 64},
                     {"findings": [{"code": "OOM_EVENT", "refs": [SECRET]}]},
                     {"findings": [{"code": SECRET, "refs": ["e0004"]}]},
                     {"findings": [{"code": "OOM_EVENT", "refs": ["e0004"], "explanation": SECRET}]}]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(evidence.EvidenceRefused) as exc:
                publication.render(projection, self.result(projection, **mutation))
            self.assertNotIn(SECRET, str(exc.exception))

    def test_resource_placement_templates_validate_only_supporting_numeric_rows(self):
        projection = self.read()
        for code, action in (("PLACEMENT_CONSTRAINTS", "REVIEW_CONSTRAINTS"), ("RESOURCE_CPU", "REVIEW_CPU"), ("RESOURCE_MEMORY", "REVIEW_MEMORY")):
            body = publication.render(projection, self.result(projection, findings=[{"code": code, "refs": ["e0002"]}], action=action))
            self.assertNotIn(SECRET, body)
            self.assertIn("not proof of an exact deployed revision", body)
        with self.assertRaises(evidence.EvidenceRefused):
            publication.render(projection, self.result(projection, findings=[{"code": "RESOURCE_DISK", "refs": ["e0002"]}], action="REVIEW_DISK"))

    def test_publish_entrypoint_reloads_evidence_and_invalidates_changed_result(self):
        projection = self.read()
        body = publication.render_for_incident(self.factory, self.root_id, self.run.run_id,
                                              self.result(projection), now=NOW + 2)
        self.assertIn("explicit OOM event", body)
        self.bundle["observations"][1]["data"][0]["FailedTGAllocs"][SECRET]["NodesAvailable"] = {SECRET: 4}
        self.write_bundle()
        with self.assertRaises(evidence.EvidenceRefused):
            publication.render_for_incident(self.factory, self.root_id, self.run.run_id,
                                            self.result(projection), now=NOW + 2)

    def test_bad_numeric_boolean_and_allocation_window_refused(self):
        original = copy.deepcopy(self.bundle)
        self.bundle["observations"][1]["data"][0]["FailedTGAllocs"][SECRET]["NodesAvailable"] = True
        self.write_bundle()
        with self.assertRaises(evidence.EvidenceRefused):
            self.read()
        self.bundle = copy.deepcopy(original)
        self.bundle["observations"][2]["data"][0]["ModifyTime"] = (NOW - 3600) * 10**9
        self.write_bundle()
        with self.assertRaises(evidence.EvidenceRefused):
            self.read()

    def test_duplicate_manifest_json_and_malformed_projection_are_refused(self):
        manifest_path = self.path / "manifest.json"
        manifest_path.write_text('{"files":[],"files":[]}')
        with self.assertRaises(evidence.EvidenceRefused):
            self.read()
        malformed = evidence.Projection(b'{"policy_version":1,"commit":"' + self.run.commit.encode() + b'","rows":[{"ref":"' + SECRET.encode() + b'"}]}')
        with self.assertRaises(evidence.EvidenceRefused) as exc:
            publication.render(malformed, self.result(malformed))
        self.assertNotIn(SECRET, str(exc.exception))

    def test_publication_destination_is_trusted_incident_not_model_or_original_ticket(self):
        projection = self.read()
        with self.assertRaises(evidence.EvidenceRefused):
            publication.prepare_for_incident(self.factory, "acme/widgets", self.root_id,
                                             self.run.run_id, self.result(projection), now=NOW + 2)
        incident_path = self.factory / "incidents" / (self.root_id + ".json")
        incident = json.loads(incident_path.read_text())
        incident["issue"] = 11
        for status, uncertain in (("pending", False), ("delivered", True)):
            incident.update(status=status, uncertain=uncertain)
            incident_path.write_text(json.dumps(incident))
            with self.assertRaises(evidence.EvidenceRefused):
                publication.prepare_for_incident(self.factory, "acme/widgets", self.root_id,
                                                 self.run.run_id, self.result(projection), now=NOW + 2)
        incident.update(status="delivered", uncertain=False)
        incident_path.write_text(json.dumps(incident))
        envelope = publication.prepare_for_incident(self.factory, "acme/widgets", self.root_id,
                                                    self.run.run_id, self.result(projection), now=NOW + 2)
        self.assertEqual(envelope.issue, 11)
        self.assertNotEqual(envelope.issue, self.run.ticket)
        self.assertEqual(envelope.repository, "acme/widgets")
        with self.assertRaises(evidence.EvidenceRefused):
            publication.prepare_for_incident(self.factory, "else/where", self.root_id,
                                             self.run.run_id, self.result(projection), now=NOW + 2)
        with self.assertRaises(evidence.EvidenceRefused):
            publication.prepare_for_incident(self.factory, "acme/widgets", self.root_id,
                                             self.run.run_id, self.result(projection, issue=999), now=NOW + 2)

    def test_fixed_escalation_duplicate_json_and_output_budget(self):
        projection = self.read()
        result = {"projection_sha256": projection.sha256, "outcome": "escalate", "reason": "UNSUPPORTED"}
        body = publication.render(projection, json.dumps(result).encode())
        self.assertIn("needs human investigation", body)
        result["reason"] = SECRET
        with self.assertRaises(evidence.EvidenceRefused):
            publication.render(projection, json.dumps(result).encode())
        duplicate = ('{"projection_sha256":"' + projection.sha256 + '","outcome":"escalate","outcome":"proposal","reason":"UNSUPPORTED"}').encode()
        with self.assertRaises(evidence.EvidenceRefused):
            publication.render(projection, duplicate)
        with mock.patch.object(publication, "MAX_PUBLIC", 1):
            with self.assertRaises(evidence.EvidenceRefused):
                publication.render(projection, self.result(projection))

    def delivered(self):
        path = self.factory / "incidents" / (self.root_id + ".json")
        row = json.loads(path.read_text())
        row.update(issue=11, status="delivered", uncertain=False)
        path.write_text(json.dumps(row))

    def test_refusal_escalation_needs_no_bundle_or_projection(self):
        self.delivered()
        original = copy.deepcopy(self.bundle)
        for key, value, code in (("logs_enabled", True, "logs_not_allowed"),
                                 ("dropped_observations", 1, "partial_evidence"),
                                 ("commit", "f" * 40, "bundle_identity_mismatch")):
            self.bundle = copy.deepcopy(original)
            self.bundle[key] = value
            self.write_bundle()
            try:
                self.read()
            except evidence.EvidenceRefused as exc:
                self.assertEqual(str(exc), code)
                envelope = publication.prepare_refusal(self.factory, "acme/widgets", self.root_id, str(exc))
                self.assertEqual(envelope.issue, 11)
                self.assertIn("No diagnosis", envelope.body)
                self.assertNotIn(SECRET, envelope.body)
            else:
                self.fail("evidence must be refused")
        (self.path / "diagnostics.json").unlink()
        envelope = publication.prepare_refusal(self.factory, "acme/widgets", self.root_id, "unsafe_or_missing_file")
        self.assertEqual(envelope.issue, 11)
        with self.assertRaises(evidence.EvidenceRefused):
            publication.render_refusal(self.root_id, SECRET)
        with self.assertRaises(evidence.EvidenceRefused):
            publication.prepare_refusal(self.factory, "wrong/repo", self.root_id, "partial_evidence")

    def test_unknown_states_minimized_known_multiregion_states_retained(self):
        row = copy.deepcopy(self.bundle["observations"][2])
        row["source"] = "nomad/job/worker/deployments"
        row["data"][0]["Status"] = SECRET
        self.bundle["observations"].append(row)
        for value in (SECRET, "pending", "initializing", "unblocking", {"private": SECRET}):
            row["data"][0]["Status"] = value
            self.write_bundle()
            projection = self.read()
            state = projection.data()["rows"][-1]["state"]
            self.assertEqual(state, value if isinstance(value, str) and value in evidence.DEPLOY_STATES else "unknown")
            self.assertNotIn(SECRET, projection.payload.decode())

    def test_later_success_matches_incident_replay_resolution(self):
        later = copy.deepcopy(self.run)
        later.run_id = "deploy-default-01234567-2"
        later.attempt = 2
        later.status = deploy.DeployStatus.SUCCEEDED
        deploy.record_deploy_run(later, self.factory / "events.jsonl")
        state = deploy.replay_events(self.factory / "events.jsonl")["default"]
        self.assertNotIn(self.run.ticket, state.unacknowledged_failed_tickets)
        with self.assertRaisesRegex(evidence.EvidenceRefused, "run_already_resolved"):
            self.read()

    def test_large_journal_live_first_and_rotated_resolution(self):
        import gzip
        journal = self.factory / "events.jsonl"
        original = journal.read_bytes()
        # Over the old aggregate limit; realistic unrelated rows, not sparse data.
        line = json.dumps({"event": "heartbeat", "ticket": 900, "text": "x" * 950}).encode() + b"\n"
        with journal.open("wb") as out:
            for _ in range((65 * 1024 * 1024) // len(line) + 1):
                out.write(line)
            out.write(original)
        with gzip.open(self.factory / "events.jsonl.1.gz", "wb") as out:
            out.write(b"not a relevant journal\n")
        # Configured larger threshold, and no decompression when live contains run.
        with mock.patch.object(lifecycle, "MAX_BYTES", 80 * 1024 * 1024), mock.patch.object(evidence.gzip, "GzipFile", side_effect=AssertionError("archive unnecessary")):
            self.read()
        with mock.patch.object(lifecycle, "MAX_BYTES", 32 * 1024 * 1024):
            with self.assertRaisesRegex(evidence.EvidenceRefused, "journal_budget_exhausted"):
                self.read()
        # Aggregate exceeds 64 MiB: both files fit the configured per-file
        # limit. The live lookup is absent, so the large archive is opened.
        with journal.open("rb") as incoming, gzip.open(self.factory / "events.jsonl.1.gz", "wb") as out:
            import shutil
            shutil.copyfileobj(incoming, out)
        with journal.open("wb") as out:
            for _ in range((37 * 1024 * 1024) // len(line) + 1):
                out.write(line)
        with mock.patch.object(lifecycle, "MAX_BYTES", 80 * 1024 * 1024):
            self.read()
        # Run in archive; later live success must win after chronological replay.
        with gzip.open(self.factory / "events.jsonl.1.gz", "wb") as out:
            out.write(original)
        journal.write_bytes(b"")
        self.read()
        later = copy.deepcopy(self.run)
        later.run_id = "deploy-default-01234567-2"
        later.status = deploy.DeployStatus.SUCCEEDED
        deploy.record_deploy_run(later, journal)
        with self.assertRaisesRegex(evidence.EvidenceRefused, "run_already_resolved"):
            self.read()


if __name__ == "__main__":
    unittest.main()
