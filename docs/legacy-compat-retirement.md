# Retiring the `agent_factory` compatibility layer

The upstream merge renamed the package from `agent_factory` to `factory`. This
fork keeps a thin compatibility layer so that deployments migrated from the old
name keep working. This document lists what that layer covers, what must be
true before each part can be removed, and the order to remove it in.

## What remains

| Compatibility item | Where | Who still needs it |
|---|---|---|
| `agent_factory` package (aliases of `config`, `dispatch`, `apply`, `deploy`, `verify_secrets`; CLI shim for `tf_plan_check`) | `agent_factory/`, `pyproject.toml` wheel `packages` | Gate checks that run `python3 -m agent_factory.tf_plan_check`, in a consumer's current `.factory.toml` **or in any existing worker worktree checked out before the consumer switched**; scripts that `import agent_factory` |
| Legacy host-config path `~/.config/agent-factory/config.toml` | `config.host_config_path()` | Hosts that have not moved their config to `~/.config/factory/config.toml` |
| Legacy shared lock directory `~/.local/state/agent-factory/locks` (or `$XDG_STATE_HOME/agent-factory/locks`, fallback `/tmp/agent-factory-locks`) | `deploy.preferred_lock_dir()` / `get_shared_lock_dir()` | Every process that deploys against a shared backend; also any rollback runtime |
| Distribution name `agent-factory` in runtime probes | `factory/inspection.py` | Inspecting a host that still has the old distribution installed |

The config path and the lock directory are different kinds of item. The config
path only chooses which file is read, so the fallback can be dropped once no
host relies on it. The lock directory is shared state: two processes that
disagree on it do not see each other's locks, and they can run concurrent applies
against one Terraform backend. Never change it in only one runtime.

## Preconditions and order

1. **Close the rollback window to any pre-rename runtime.** A rollback runtime
   imports the old names and uses the legacy config and lock paths, so none of
   the items above can go while a rollback to it is still possible.
2. **Retire the legacy gate command.**
   - Every consumer `.factory.toml` runs `python3 -m factory.tf_plan_check`.
   - No worker worktree still has a `.factory.toml` that runs
     `agent_factory.tf_plan_check`. Worktrees keep the gate command they were
     checked out with, so remove or rebase stale ones.
   - Nothing on the host imports `agent_factory`.
3. **Drop the package.** Remove `agent_factory/` and `"agent_factory"` from the
   wheel `packages`, along with the compatibility tests. Take the version bump
   and re-acceptance path that any runtime change takes.
4. **Config path (optional).** Move each host's config to
   `~/.config/factory/config.toml` with a secret-safe move, not a copy printed
   anywhere. Keep the file mode at 0600. Confirm `factory verify-secrets --scope all`
   and `factory inspect` report the new `config_path`. Only then remove the
   fallback from `host_config_path()`.
5. **Lock directory (optional, maintenance window).** If it is renamed:
   - Ship a release that uses the new directory.
   - Pause every scheduler, and drain until `factory inspect` shows every lock
     free or absent.
   - Switch every runtime on the host in the same window.
   - Never delete a held lock file, and never move lock files while a process
     could still open them.

   Keeping the legacy directory name indefinitely is an acceptable outcome.

Until a step's preconditions hold, keep that item and add no new callers of it.
