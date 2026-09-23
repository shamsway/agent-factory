"""Legacy import path: `agent_factory` is the retired pre-migration name for the
`factory` distribution (see docs/legacy-compat-retirement.md).

Every stateful submodule here (config, dispatch, apply, deploy, verify_secrets) is
installed as a true alias of its `factory.<name>` counterpart via `sys.modules`
substitution, not a copy of its globals -- state set through one import path (e.g.
`agent_factory.dispatch.configure(cfg)`) is visible through the other, because both
names resolve to the exact same module object. `agent_factory.tf_plan_check` is a
thin CLI-forwarding shim instead, matching the shape the old gate check invoked it
in (`python -m agent_factory.tf_plan_check ...`).

Kept only for callers still on the old path (an existing `.factory.toml` gate check,
a script's `import agent_factory`); add no new callers. Retirement preconditions and
order: docs/legacy-compat-retirement.md.
"""

from factory import __version__

__all__ = ["__version__"]
