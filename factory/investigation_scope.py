"""Inactive repository scope validator; no model-selected paths or edits.

Reviewed bindings must come from operator policy. A supported finding alone does
not prove source ownership; absence/ambiguity of that mapping refuses a scope.
"""
from dataclasses import dataclass
import os
import re
import subprocess

from . import investigation_evidence as evidence, investigation_publication as publication


@dataclass(frozen=True)
class ScopePolicy:
    repository: str
    commit: str
    # Explicit operator-reviewed hashed job/namespace -> repository paths.
    bindings: tuple


def prepare(repository_root, projection, raw_result, policy):
    publication.render(projection, raw_result)
    import json
    result = json.loads(raw_result)
    evidence.require(result.get("outcome") == "proposal" and type(policy) is ScopePolicy,
                     "unsupported_scope")
    data = projection.data()
    evidence.require(policy.repository == projection.repository and policy.commit == data["commit"]
                     and re.fullmatch(r"[0-9a-f]{40}", policy.commit), "scope_revision_mismatch")
    refs = {ref for f in result["findings"] for ref in f["refs"]}
    identities = {(r["job"], r["namespace"]) for r in data["rows"] if r["ref"] in refs}
    evidence.require(isinstance(policy.bindings, tuple) and 1 <= len(policy.bindings) <= 32,
                     "unsupported_scope")
    mapped = {}
    for job, namespace, paths in policy.bindings:
        evidence.require((job, namespace) not in mapped and isinstance(paths, tuple), "unsupported_scope")
        mapped[(job, namespace)] = paths
    evidence.require(identities and all(i in mapped for i in identities), "unsupported_scope")
    paths = sorted({p for i in identities for p in mapped[i]})
    evidence.require(1 <= len(paths) <= 8, "unsupported_scope")
    files = []
    env = {"PATH": os.defpath, "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_NO_REPLACE_OBJECTS": "1"}
    for path in paths:
        evidence.require(isinstance(path, str) and len(path) <= 256
                         and re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_.-]+)+", path)
                         and all(p not in {".", "..", "secrets"} for p in path.split("/"))
                         and path.endswith((".tf", ".nomad.hcl")), "unsupported_scope")
        try:
            command = ["git", "--no-replace-objects", "-C", str(repository_root)]
            row = subprocess.run(command + ["ls-tree", "-z", policy.commit, "--", path],
                                 env=env, capture_output=True, timeout=5, check=True).stdout
            # Exact tracked regular blob only: no symlinks, submodules or dirs.
            mode, kind, blob = row.split(b"\t", 1)[0].split()
            evidence.require(mode in {b"100644", b"100755"} and kind == b"blob"
                             and row.split(b"\t", 1)[1] == path.encode() + b"\0", "unsupported_scope")
            size = subprocess.run(command + ["cat-file", "-s", blob.decode()], env=env,
                                  capture_output=True, timeout=5, check=True).stdout
            evidence.require(0 < int(size) <= 1024 * 1024, "unsupported_scope")
        except Exception:
            raise evidence.EvidenceRefused("unsupported_scope") from None
        files.append({"path": path, "git_blob": blob.decode()})
    return {"version": 1, "repository": policy.repository, "commit": policy.commit,
            "projection_sha256": projection.sha256, "action": result["action"], "files": files,
            "production_write": False, "patch_generated": False,
            "validation": "repository_gates_plan_and_post_apply_health",
            "risk": "incorrect_scope_or_capacity", "rollback": "last_approved_deployment"}
