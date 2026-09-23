# Read-only operational verification

Use these commands from the consumer repository with the intended Factory interpreter. They do not install/restart units, fetch Git, claim tickets, apply infrastructure, or write the deployment ledger.

```bash
factory verify-secrets --scope all --live --json
factory inspect --json
factory inspect --json --live --candidates --worker-cwd /absolute/existing/worktree
```

`verify-secrets` defaults to the existing install scope. `--scope apply` checks only configured apply keys and does not require dispatcher units; `--scope all` checks both roles. Live checks support configured `GH_TOKEN` and `OP_SERVICE_ACCOUNT_TOKEN`, each in a separate subprocess with only that token and PATH. Other configured keys are marked `not_checked`; configuration alone is not credential validity. An empty value is `empty` (a failure) for those supported credentials and `empty_allowed` for any other key, such as an intentionally empty `TF_VAR_onepassword_account` selector; this verdict is the same with and without `--live`. Missing required units, mismatched unit values, empty supported credentials, failed or unavailable supported live checks, and detected apply-secret leakage fail with exit 1. The dashboard is required only when configured. Loaded systemd Environment properties include drop-ins; EnvironmentFiles/UnsetEnvironment are explicitly unsupported and fail inspection rather than pretending to reconstruct them. Raw provider errors and values are never printed.

`verify-secrets` reports `apply_isolation` from configured apply/install value overlap only; the invoking shell is not evidence of dispatcher leakage. Use `inspect` for credential-boundary comparisons against observed unit/process environments.

`inspect` emits schema-versioned JSON:

- `units`: loaded/active/enabled state and invocation identity; configured environment comparisons contain names/statuses only. Configured interpreter, fresh runtime module paths/content hashes/distribution versions, and gate runtime are separate observations. A configured Python wins; otherwise a Python ExecStart path is used when recognizable. Every ExecStart command is collected (a unified unit runs triage then dispatch), and the interpreter matches only when all of them use the selected Python. Unknown wrapper launchers must be inspected separately.
- `process`: Linux `/proc` executable and argv[0] comparison, credential-boundary checks, and PID/start-time consistency. Full command lines and environments are never returned. Unit invocation identity is rechecked after reading the process. An inactive unit is `not_running`; an inaccessible or changing process is not healthy.
- `deployment`: a bounded, nonblocking shared-lock snapshot, its SHA-256, target run identifiers/statuses, unresolved runs and unacknowledged failures. Run output/error bodies are excluded. Missing, malformed and partially written ledgers are distinguished. Interrupted tails already quarantined by the journal writer are ignored consistently with that writer.
- `locks`: nonblocking probes of existing apply/target/ticket/gate/backend lock files, including preferred and fallback directories and directories resolved from observed service/process environments. Probes never create, truncate or delete files. `held` is actual flock contention, not a guess based on file existence; this is not a holder-PID inventory.
- `candidates`: opt-in read-only GitHub query, capped at 1000 merged PRs, filtered using existing local Git objects, configured targets/baseline and terminal tickets. Missing local objects or query failures are unavailable; a full-size result is explicitly truncated. This is discovery only: trusted-review authorization and direct-merge detection remain the deployment selector's responsibility. No Git fetch is performed.

`ok` means the required observations/comparisons succeeded, not permission to deploy. `complete` describes unit/ledger/lock/query coverage; inspect individual runtime and credential statuses too. `quiescent` additionally requires the observed units inactive, observed locks free/absent, and no unresolved or unacknowledged target failures. It covers only the inventoried Factory units/lock paths: custom apply units, cron, external triggers and unrelated processes still need operator inventory. A point-in-time probe cannot prevent a scheduler from starting work immediately afterward.

Python's already-loaded module bytes cannot be recovered reliably through `/proc`. Fresh module hashes describe files currently on disk, not code proven loaded inside another process. Correlate process/unit invocation identity with the immutable installed wheel and restart evidence; keep this distinction in acceptance records.

On a platform without systemd or readable `/proc`, expect partial/unavailable observations and nonzero status where required checks cannot be established. This is deliberate. `--live` makes provider reads; `--candidates` makes GitHub reads; neither publishes messages or mutates infrastructure. Keep host-config and service output out of transcripts; use these tools rather than printing TOML, Environment properties, or process environments by hand.
