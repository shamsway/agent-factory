# AGENTS.md

Guidance for Claude Code (or any agent) working in this repository.

## Never parse the host config by hand

`~/.config/agent-factory/config.toml` holds live secrets (`GH_TOKEN`,
`OP_SERVICE_ACCOUNT_TOKEN`, `ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, ...) in
`[repo."<slug>".apply].env` and `[repo."<slug>".install].env`. To check what's configured,
whether it matches what a repo's systemd units are actually running, or whether a credential
is still valid:

```
cd <repo>
factory verify-secrets          # sync check: host config vs. installed units
factory verify-secrets --live   # also spot-checks GH_TOKEN / OP_SERVICE_ACCOUNT_TOKEN live
```

Do not `cat`/`Read`/`grep -oE` the config file or a `systemctl --user cat <unit>` to compare
values by hand. It's fragile through nested shell quoting (see: several failed attempts before
this tool existed) and, worse, it's an easy way to print live secret values into a chat
transcript or log. If you need something `verify-secrets` doesn't cover, extend it
(`agent_factory/verify_secrets.py`) rather than reaching for `cat`/regex again.

**Why this exists:** `factory install` copies `[install].env` into every unit's `Environment=`
lines *at install time* — editing the host config alone does not touch a unit that's already
running. This bit twice in one afternoon (2026-09-12/13): SHA-182 (a `factory install` rerun
silently propagated an unscoped `GH_TOKEN` into the dispatcher unit for the first time, breaking
automated merge with no loud error anywhere except a dispatch-log line), and again during a
routine `octant-agent-ro`/`octant-factory` token rotation (host config updated, but all three
systemd units kept running on the pre-rotation values until `factory install` was rerun).
