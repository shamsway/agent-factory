"""Operator-approved job/file mappings checked against each failed revision."""
from dataclasses import dataclass
import json
import os
import re
import subprocess

from . import investigation_evidence as evidence, investigation_publication as publication


@dataclass(frozen=True)
class ScopePolicy:
    repository: str
    bindings: tuple
    approved_at: str  # review provenance only; never deployment authority


def allowed_path(path):
    return (isinstance(path, str) and len(path) <= 256
            and re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_.-]+)+", path)
            and all(part not in {".", "..", "secrets"} for part in path.split("/"))
            and path.endswith((".tf", ".nomad.hcl")))


def load_policy(path, *, repository):
    """Load a closed mapping policy from a protected operator-owned file."""
    from .publisher_credentials import protected_read
    try:
        raw = json.loads(protected_read(path), object_pairs_hook=evidence.unique_pairs)
        evidence.require(isinstance(raw, dict) and set(raw) ==
                         {"version", "approved", "repository", "approved_at", "bindings"}, "unsupported_scope")
        evidence.require(type(raw["version"]) is int and raw["version"] == 2
                         and raw["approved"] is True and raw["repository"] == repository
                         and isinstance(raw["approved_at"], str)
                         and re.fullmatch(r"[0-9a-f]{40}", raw["approved_at"]), "unsupported_scope")
        evidence.require(isinstance(raw["bindings"], list) and 1 <= len(raw["bindings"]) <= 32,
                         "unsupported_scope")
        bindings, identities = [], set()
        for row in raw["bindings"]:
            evidence.require(isinstance(row, dict) and set(row) == {"job", "namespace", "paths"},
                             "unsupported_scope")
            evidence.require(isinstance(row["job"], str) and re.fullmatch(r"job-[0-9a-f]{24}", row["job"])
                             and isinstance(row["namespace"], str)
                             and re.fullmatch(r"namespace-[0-9a-f]{24}", row["namespace"]), "unsupported_scope")
            identity = row["job"], row["namespace"]
            evidence.require(identity not in identities and isinstance(row["paths"], list)
                             and 1 <= len(row["paths"]) <= 8, "unsupported_scope")
            identities.add(identity)
            paths = row["paths"]
            evidence.require(all(allowed_path(p) for p in paths) and len(set(paths)) == len(paths),
                             "unsupported_scope")
            bindings.append((*identity, tuple(paths)))
        return ScopePolicy(repository, tuple(bindings), raw["approved_at"])
    except evidence.EvidenceRefused:
        raise
    except Exception:
        raise evidence.EvidenceRefused("unsupported_scope") from None


def prepare_from_policy(repository_root, projection, raw_result, policy_path):
    return prepare(repository_root, projection, raw_result,
                   load_policy(policy_path, repository=projection.repository))


def prepare(repository_root, projection, raw_result, policy):
    publication.render(projection, raw_result)
    result = json.loads(raw_result)
    evidence.require(result.get("outcome") == "proposal" and type(policy) is ScopePolicy,
                     "unsupported_scope")
    data = projection.data()
    commit = data["commit"]
    evidence.require(policy.repository == projection.repository and isinstance(commit, str)
                     and re.fullmatch(r"[0-9a-f]{40}", commit), "scope_revision_mismatch")
    refs = {ref for finding in result["findings"] for ref in finding["refs"]}
    identities = {(row["job"], row["namespace"]) for row in data["rows"] if row["ref"] in refs}
    evidence.require(isinstance(policy.bindings, tuple) and 1 <= len(policy.bindings) <= 32,
                     "unsupported_scope")
    mapped = {}
    for job, namespace, paths in policy.bindings:
        evidence.require((job, namespace) not in mapped and isinstance(paths, tuple), "unsupported_scope")
        mapped[(job, namespace)] = paths
    evidence.require(identities and all(identity in mapped for identity in identities), "scope_mapping_unavailable")
    paths = sorted({path for identity in identities for path in mapped[identity]})
    evidence.require(1 <= len(paths) <= 8, "unsupported_scope")
    files = []
    env = {"PATH": os.defpath, "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_NO_REPLACE_OBJECTS": "1"}
    for path in paths:
        evidence.require(allowed_path(path), "unsupported_scope")
        try:
            command = ["git", "--no-replace-objects", "-C", str(repository_root)]
            row = subprocess.run(command + ["ls-tree", "-z", commit, "--", path],
                                 env=env, capture_output=True, timeout=5, check=True).stdout
            mode, kind, blob = row.split(b"\t", 1)[0].split()
            evidence.require(mode in {b"100644", b"100755"} and kind == b"blob"
                             and row.split(b"\t", 1)[1] == path.encode() + b"\0", "scope_mapping_unavailable")
            size = subprocess.run(command + ["cat-file", "-s", blob.decode()], env=env,
                                  capture_output=True, timeout=5, check=True).stdout
            evidence.require(0 < int(size) <= 1024 * 1024, "scope_mapping_unavailable")
        except Exception:
            raise evidence.EvidenceRefused("scope_mapping_unavailable") from None
        files.append({"path": path, "git_blob": blob.decode()})
    return {"version": 1, "repository": policy.repository, "commit": commit,
            "projection_sha256": projection.sha256, "action": result["action"], "files": files,
            "production_write": False, "patch_generated": False,
            "validation": "repository_gates_plan_and_post_apply_health",
            "risk": "incorrect_scope_or_capacity", "rollback": "last_approved_deployment"}
