# Bounded deployment diagnostics

SHA-200 adds read-only evidence collection. It does not diagnose a cause, execute
a repair, acknowledge a failed run, or change approval requirements.

## Enable a target

Diagnostics are off unless the target has a diagnostics table. Configure
explicit read-only endpoints and least-privilege credentials via the official
host Config API; never copy tokens into the project policy or a probe URL.

```toml
[apply.targets.default.diagnostics]
timeout = 20
call_timeout = 3
max_bytes = 262144
response_bytes = 65536
lookback = 600
nomad_addr = "http://nomad.service.consul:4646"
consul_addr = "http://127.0.0.1:8500"
services = ["collector-dependency"]
probes = ["http://127.0.0.1:9000/health"]
# Optional explicit allocation-relative application error logs; no discovery.
error_logs = ["collector/local/error.log"]
```

Use actual discovered endpoints for your environment. `nomad_addr` can fall
back to `NOMAD_ADDR` in the apply environment. Nomad uses `NOMAD_TOKEN`; Consul
uses `CONSUL_HTTP_TOKEN`. Credentials stay in memory and request headers.
URLs cannot contain userinfo, queries or fragments. Redirects are refused.
Only allowlist GET endpoints whose application semantics are read-only.
For an implicit default target, use `[apply.diagnostics]` instead.

A terminal failed execution or health verification collects evidence before
artifact publication. Collector errors cannot replace the durable deploy status
or suppress the ordinary incident escalation. Dry-run performs no collection.
Prepare/check failures may lack a public manifest; the manual command creates
one from the sanitized durable run record if needed:

```
factory diagnostics --target default --run-id deploy-default-01234567-1
```

The CLI holds the apply lock and refuses a busy apply pass. It writes local
artifacts only; it does not call the GitHub publication API. `diagnostics.json`
is listed with hash/size in the existing run manifest and served only through
the authenticated artifact lookup. The dashboard's artifact links include it.

## Correlation and coverage

Every bundle identifies run, target, source commit, observation timestamps and a
bounded failure window. Nomad jobs and versions come from persisted health
evidence, including namespace/region. The current job is separate context: a
new healthy version never supplies the failed version's allocations or logs.
Missing job/version evidence remains unavailable; the collector does not guess
that a current version corresponds to a Terraform commit. Apply failures before
health verification can therefore have only local apply evidence.

Evaluation evidence is filtered by job/namespace and failure time. Nomad's
evaluation list lacks a job-version field, so it is explicitly weaker evidence,
not a version assertion. Deployments and allocations must match the recorded
job/version/namespace. Retained stopped, failed and replaced allocations are
included when their lifetime intersects the window. Allocation details are
rechecked before reading task events/logs. The bundle links full evaluation,
deployment and previous/next allocation IDs when returned by Nomad.

The API calls use Nomad's [job state endpoints](https://developer.hashicorp.com/nomad/api-docs/jobs),
[bounded client logs/file reads](https://developer.hashicorp.com/nomad/api-docs/client)
and [Consul health checks](https://developer.hashicorp.com/consul/api-docs/health).
There are no variable, execute, restart, launch, registration or GC calls.

Task events are restricted to the failure window. Stdout/stderr and explicitly
allowlisted `.log` files are bounded tails. Nomad logs do not guarantee
timestamps; they are marked `untimestamped_bounded_tail`, not claimed as proof
that a line occurred during the failure window. GC, disabled logging, retention
and ACL denial may remove evidence: 404 is `absent_or_expired`, 410 `expired`,
401/403 `permission_denied`. No missing result is invented.

Consul and HTTP probes are explicitly current-state dependency context.
Probes retain success/failure metadata only, never their response body.
Error-log access is restricted to explicit relative `.log` paths; there is no
allocation filesystem browsing or arbitrary file request.

## Budgets and safety

All built-in collectors share a total wall-clock deadline, bounded request/socket
timeouts and download/output byte budgets. Limits appear in the bundle: up to
8 jobs, 50 state rows per source, 8 allocations with logs, 8 tasks each, 50 task
events each and 8 KiB per log tail. These are bounded samples, not exhaustive
cluster history. Oversized responses are rejected instead of stored. Output
overflow increments `dropped_observations`; partial observations survive.
Total timeout is at most 120s, per call 10s, lookback one hour, output 1 MiB and
response 256 KiB. Local serialization/scheduling overhead is outside the network
deadline. Trusted plugins are Python callables receiving Context; they must use
its budgeted `get` and safe `add` and must not perform writes or blocking work
outside that contract. Exceptions retain earlier evidence and subsequent
collectors continue.

Only allowlisted job/allocation/check fields are retained. Job specs, environment
maps, driver configuration, host config, raw plans, state and Nomad variables
are excluded. Known credential values and existing recognized token patterns
are redacted before storage. Logs are untrusted input for the future investigator.
Unknown secret shapes remain a limitation: SHA-238 is not solved.

Collection is opt-in and read-only but can add up to its budget to a failed
apply while locks are held. Keep the timeout small. Public artifact retention
is independent of private plan retention. Collecting evidence does not authorize
publication, production changes or repair.

## Acceptance boundary

Fixtures cover placement, startup, health-check, dependency and resource
symptoms, version/namespace contamination, replacement linkage, expired/denied
logs, budgets, redaction, authenticated manifests and deployment-outcome
preservation. Source/test success is separate from installed/live acceptance.
Use a reviewed disposable workload for any intentional live failure; do not
break a healthy production workload to demonstrate collection.
