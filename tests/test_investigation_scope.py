"""No patch generation: source scope derives from reviewed policy and git blobs."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
from dataclasses import replace
from tests import test_investigation_boundary as fixtures
from factory import investigation_evidence as evidence, investigation_scope as scope


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.BoundaryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.projection = evidence.read_evidence(self.fixture.factory, self.fixture.root_id,
                                                self.fixture.run.run_id, now=fixtures.NOW + 2)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "terraform").mkdir()
        (self.root / "terraform/main.tf").write_text('# synthetic fixture\n')
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "-qm", "fixture"], check=True)
        self.commit = subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"]).decode().strip()
        data = self.projection.data()
        data["commit"] = self.commit
        self.projection = replace(self.projection, payload=evidence.encoded(data))
        # Projection.sha256 is computed from immutable payload, not supplied.
        row = next(r for r in data["rows"] if r["kind"] == "task_event")
        self.identity = (row["job"], row["namespace"])
        self.raw = evidence.encoded({"projection_sha256": self.projection.sha256, "outcome": "proposal",
            "findings": [{"code": "OOM_EVENT", "refs": [row["ref"]]}], "action": "REVIEW_OOM"})
        self.policy = scope.ScopePolicy(self.projection.repository,
                                       ((*self.identity, ("terraform/main.tf",)),), self.commit)

    def test_exact_revision_regular_file_scope(self):
        result = scope.prepare(self.root, self.projection, self.raw, self.policy)
        self.assertEqual(result["files"][0]["path"], "terraform/main.tf")
        self.assertFalse(result["patch_generated"])
        self.assertFalse(result["production_write"])
        self.assertNotIn(fixtures.SECRET, json.dumps(result))

    def test_unmapped_and_wrong_repository_refused(self):
        for policy in (replace(self.policy, bindings=()), replace(self.policy, repository="other/repo")):
            with self.assertRaises(evidence.EvidenceRefused):
                scope.prepare(self.root, self.projection, self.raw, policy)

    def test_paths_are_operator_allowlisted_and_tracked(self):
        for path in ("../private.tf", "secrets/main.tf", "terraform/missing.tf", "terraform/../main.tf", "terraform/run.py"):
            policy = replace(self.policy, bindings=((*self.identity, (path,)),))
            with self.assertRaises(evidence.EvidenceRefused):
                scope.prepare(self.root, self.projection, self.raw, policy)

    def test_untrusted_extra_fields_refused_before_scope(self):
        result = json.loads(self.raw)
        result["files"] = ["terraform/main.tf"]
        with self.assertRaises(evidence.EvidenceRefused):
            scope.prepare(self.root, self.projection, evidence.encoded(result), self.policy)

    def test_git_symlink_is_not_source_scope(self):
        (self.root / "terraform/link.tf").symlink_to("main.tf")
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "-qm", "symlink"], check=True)
        commit = subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"]).decode().strip()
        data = self.projection.data()
        data["commit"] = commit
        projection = replace(self.projection, payload=evidence.encoded(data))
        result = json.loads(self.raw)
        result["projection_sha256"] = projection.sha256
        policy = replace(self.policy, bindings=((*self.identity, ("terraform/link.tf",)),))
        with self.assertRaises(evidence.EvidenceRefused):
            scope.prepare(self.root, projection, evidence.encoded(result), policy)


    def policy_json(self):
        return {"version": 2, "approved": True, "repository": self.projection.repository,
                "approved_at": self.commit, "bindings": [{"job": self.identity[0],
                "namespace": self.identity[1], "paths": ["terraform/main.tf"]}]}

    def load(self, raw):
        from factory import publisher_credentials
        with mock.patch.object(publisher_credentials, "protected_read", return_value=evidence.encoded(raw)):
            return scope.load_policy("/operator/policy.json", repository=self.projection.repository)

    def test_load_approved_mapping(self):
        policy = self.load(self.policy_json())
        self.assertEqual(policy.bindings, self.policy.bindings)
        self.assertEqual(policy.approved_at, self.commit)

    def test_load_closed_schema_refusals(self):
        for patch in ({"extra": 1}, {"version": 1}, {"approved": False},
                      {"repository": "other/repo"}, {"approved_at": "bad"}, {"bindings": []}):
            with self.subTest(patch=patch), self.assertRaises(evidence.EvidenceRefused):
                self.load({**self.policy_json(), **patch})

    def test_load_binding_and_path_refusals(self):
        base = self.policy_json()
        for patch in ({"job": "raw-name"}, {"namespace": "default"}, {"extra": 1},
                      {"paths": []}, {"paths": ["../private.tf"]}, {"paths": ["secrets/main.tf"]},
                      {"paths": ["terraform/tool.py"]}, {"paths": ["terraform/main.tf"] * 2}):
            raw = self.policy_json()
            raw["bindings"][0].update(patch)
            with self.subTest(patch=patch), self.assertRaises(evidence.EvidenceRefused):
                self.load(raw)
        base["bindings"] *= 2
        with self.assertRaises(evidence.EvidenceRefused):
            self.load(base)

    def test_new_deploy_commit_and_changed_blob_stay_approved(self):
        policy = self.load(self.policy_json())
        (self.root / "terraform/main.tf").write_text('# changed deployment config\n')
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "-qm", "new deployment"], check=True)
        commit = subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"]).decode().strip()
        data = self.projection.data()
        data["commit"] = commit
        projection = replace(self.projection, payload=evidence.encoded(data))
        raw = json.loads(self.raw)
        raw["projection_sha256"] = projection.sha256
        result = scope.prepare(self.root, projection, evidence.encoded(raw), policy)
        self.assertEqual(result["commit"], commit)
        self.assertNotEqual(commit, policy.approved_at)

    def test_oversized_and_empty_files_refused(self):
        for content in ('', 'x' * (1024 * 1024 + 1)):
            (self.root / "terraform/main.tf").write_text(content)
            subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                            "commit", "-qm", "invalid size"], check=True)
            commit = subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"]).decode().strip()
            data = self.projection.data()
            data["commit"] = commit
            projection = replace(self.projection, payload=evidence.encoded(data))
            raw = json.loads(self.raw)
            raw["projection_sha256"] = projection.sha256
            with self.assertRaises(evidence.EvidenceRefused):
                scope.prepare(self.root, projection, evidence.encoded(raw), self.policy)

    def test_prepare_from_policy_uses_failed_revision(self):
        from factory import publisher_credentials
        with mock.patch.object(publisher_credentials, "protected_read", return_value=evidence.encoded(self.policy_json())):
            result = scope.prepare_from_policy(self.root, self.projection, self.raw, "/operator/policy.json")
        self.assertEqual(result["commit"], self.commit)
