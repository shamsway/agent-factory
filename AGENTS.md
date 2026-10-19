# Agent guidance

Never parse the host configuration or systemd Environment values by hand: they
contain credentials. Use the intended installed interpreter with `factory
verify-secrets --scope all --json` and `factory inspect --json` for names/statuses.
Scopes are `install` (default), `apply`, `investigation`, `publisher`, and `all`.
Live checks are explicit; model keys remain not checked. Editing host config does
not update installed unit environments; inspect observed configuration and runtime.

The dedicated broker's App key is a systemd encrypted credential outside host
config. verify-secrets/inspect cannot inspect it. Use the local-only
`factory.publisher_key_check` in the reviewed credential unit and explicit
`investigation-broker --verify-token` / `--status` for broker verification.
Never run `systemd-creds decrypt`. Never print credentials, provider bodies, host
configuration or service environments. Host values belong in your private host operator notes.
# AGENTS.md

Factory is a label-driven ticket pipeline for GitHub repos. Commands, configuration,
and contracts live in [README.md](README.md); setup, ticket writing, and escalation
diagnosis live in [skills/factory/SKILL.md](skills/factory/SKILL.md). Read those
rather than copying them here. The native Atlas (`factory/workspace-tools.js`,
dashboard `/?view=atlas`) draws the pipeline; Codebase links extracted relationships.

**Publication privacy:** this repository is public. Source, tests, docs, commit
messages, branch names, tags and PR text never carry operator hostnames, private
repository names, private tracker issue keys, private IPs or home-directory paths;
use generic fixtures (`acme/widgets`, `example.invalid`) and keep deployment
receipts in private operator notes. Before pushing, run
`scripts/privacy-check.py --range origin/main...HEAD --branch "$(git branch --show-current)"`
and `--text` on the PR body; operator terms go in the private denylist it reads
(never committed). CI runs the generic rules on every non-sync PR.

**Evidence of done:** the dispatcher runs the gate itself after every worker attempt
and before review; that run is the evidence, not a worker's claim to have run
anything (`experiments/verification-claims/REPORT.md`).

## Feature map

Gate checks come from `.factory.toml`: `test` runs `unittest discover -s tests`, so
it exercises every test listed below. The built-in `conflict-markers`,
`protected-paths` and `leak-scan` (default pattern) checks run on every diff.
`tests/test_agents_map.py` fails when a `factory/` module is missing from this
map or a path in it does not exist; update the map in the same change.

| Feature | Entry files | Tests | Gate checks |
|---|---|---|---|
| CLI and package | `factory/cli.py`, `factory/__main__.py`, `factory/__init__.py`, `factory/launch.py` | `tests/test_runtime.py`, `tests/test_chat.py`, `tests/test_factory.py`, `tests/test_trusted_launch.py` | `test` |
| Configuration | `factory/config.py`, `factory/templates/factory.toml` | `tests/test_factory.py`, `tests/test_settings.py`, `tests/test_dashboard_port.py`, `tests/test_add_only_override.py` | `test` |
| Onboarding (`init`, `doctor`, `install`) | `factory/onboard.py`, `factory/templates/ci.yml` | `tests/test_factory.py`, `tests/test_dashboard_port.py`, `tests/test_plan.py` | `test` |
| Triage | `factory/triage.py` | `tests/test_factory.py`, `tests/test_llm_usage.py`, `tests/test_idle_lifecycle.py`, `tests/test_triage.py`, `tests/test_watch_lifecycle.py` | `test` |
| Dispatcher and worker brief | `factory/dispatch.py`, `factory/brief.py`, `factory/gitguard.py`, `factory/templates/agent_task.md`, `scripts/bwrap-sandbox.sh` | `tests/test_factory.py`, `tests/test_dispatch_lifecycle.py`, `tests/test_wait_decisions.py`, `tests/test_idle_lifecycle.py`, `tests/test_frontier.py`, `tests/test_add_only_override.py`, `tests/test_gitguard.py`, `tests/test_sandbox.py` | `test` |
| Quality gate | `factory/gate.py` | `tests/test_factory.py`, `tests/test_gate.py`, `tests/test_gate_resources.py`, `tests/test_fixture_isolation.py`, `tests/test_add_only_override.py` | `test`; implements `conflict-markers`, `protected-paths` (with `[gate].add_only_paths`), `leak-scan` |
| Post-ship monitor (`watch`) | `factory/watch.py` | `tests/test_watch.py`, `tests/test_watch_lifecycle.py`, `tests/test_factory.py` | `test` |
| Manager and human handoffs | `factory/manage.py`, `factory/handoff.py` | `tests/test_viability.py`, `tests/test_handoff.py`, `tests/test_manager_binding.py`, `tests/test_manager_resolve.py`, `tests/test_frontier.py`, `tests/test_add_only_override.py` | `test` |
| Lifecycle journal (`events.jsonl`) | `factory/lifecycle.py` | `tests/test_lifecycle.py`, `tests/test_lifecycle_consumers.py`, `tests/test_events_rotation.py`, `tests/test_resources.py` | `test` |
| Initiatives, bindings, roadmap and outcomes | `factory/plan.py`, `factory/binding.py`, `factory/roadmap.py`, `factory/outcomes.py`, `factory/templates/initiative.md` | `tests/test_plan.py`, `tests/test_binding.py`, `tests/test_binding_cli.py`, `tests/test_roadmap.py`, `tests/test_outcomes.py` | `test` |
| Project evidence and PR feedback | `factory/evidence.py`, `factory/feedback.py` | `tests/test_evidence.py`, `tests/test_evidence_budget.py`, `tests/test_evidence_transport.py`, `tests/test_feedback.py`, `tests/test_viability_evidence.py` | `test` |
| Operator workspace | `factory/dashboard.py`, `factory/dashboard.html`, `factory/workspace.py`, `factory/workspace.js`, `factory/workspace-api.js`, `factory/workspace.css`, `factory/themes.css`, `factory/motion.js` | `tests/test_workspace.py`, `tests/test_dashboard_passive.py`, `tests/test_dashboard_bind.py`, `tests/test_dashboard_port.py`, `tests/test_factory.py`, `tests/test_sync_requeue.py` | `test` |
| Guarded human decisions and named actions | `factory/decisions.py`, `factory/actions.py`, `factory/workspace-decisions.js` | `tests/test_decisions.py`, `tests/test_actions.py` | `test` |
| Runtime and flow projections | `factory/runtime_events.py`, `factory/runtime_local.py`, `factory/flow.py` | `tests/test_runtime.py`, `tests/test_flow.py`, `tests/test_factory.py` | `test` |
| Inbox briefing | `factory/briefing.py` | `tests/test_briefing.py`, `tests/test_viability_evidence.py` | `test` |
| Settings | `factory/settings.py`, `factory/workspace-settings.js` | `tests/test_settings.py` | `test` |
| Manager console (`chat`) | `factory/chat.py`, `console/app` | `tests/test_chat.py` | `test` |
| Stdio MCP server (`mcp`) | `factory/mcp.py` | `tests/test_mcp.py`, `tests/test_actions.py` | `test` |
| Codebase history and Atlas | `factory/codebase.py`, `factory/workspace-codebase.js`, `factory/workspace-codebase.css`, `factory/workspace-tools.js` | `tests/test_codebase.py` | `test` |
| Accepted handoff retention | `factory/results.py` | `tests/test_results.py` | `test` |
| Metrics (`stats`) | `factory/stats.py` | `tests/test_factory.py`, `tests/test_human_corrections.py`, `tests/test_escapes.py` | `test` |
| Lessons (`learn`) | `factory/learn.py` | `tests/test_factory.py`, `tests/test_lifecycle_consumers.py`, `tests/test_escapes.py`, `tests/test_auto_learn.py` | `test` |
| Attempt scoring (`score`) | `factory/score.py` | `tests/test_score.py` | `test` |
| Automatic releases | `factory/release.py` | `tests/test_release.py` | `test` |
| Eval promotion | `factory/promotion.py`, `docs/eval-promotion-contract.md` | `tests/test_promotion.py` | `test` |
| Deploy and apply (`apply`, `verify-secrets`) | `factory/apply.py`, `factory/deploy.py`, `factory/health.py`, `factory/artifacts.py`, `factory/retention.py`, `factory/plan_summary.py`, `factory/tf_plan_check.py`, `factory/verify_secrets.py`, `docs/deployment-lifecycle.md` | `tests/test_apply.py`, `tests/test_deploy.py`, `tests/test_health.py`, `tests/test_artifacts.py`, `tests/test_retention.py`, `tests/test_plan_summary.py`, `tests/test_tf_plan_check.py`, `tests/test_verify_secrets.py` | `test` |
| Deployment views, diagnostics and incidents | `factory/deployment_view.py`, `factory/diagnostics.py`, `factory/incidents.py`, `factory/inspection.py`, `docs/deployment-diagnostics.md`, `docs/deployment-incidents.md` | `tests/test_deployment_view.py`, `tests/test_diagnostics.py`, `tests/test_incidents.py`, `tests/test_inspection.py` | `test` |
| Deployment investigation lane | `factory/investigation_routing.py`, `factory/investigation_scope.py`, `factory/investigation_evidence.py`, `factory/investigation_isolation.py`, `factory/investigation_model.py`, `factory/investigation_outbox.py`, `factory/investigation_publication.py`, `factory/investigation_transfer.py`, `docs/deployment-investigation.md` | `tests/test_investigation.py`, `tests/test_investigation_boundary.py`, `tests/test_investigation_routing.py`, `tests/test_investigation_scope.py`, `tests/test_investigation_isolation.py`, `tests/test_investigation_model.py`, `tests/test_investigation_outbox.py`, `tests/test_investigation_transfer.py` | `test` |
| Investigation publisher | `factory/investigation_publisher.py`, `factory/investigation_broker.py`, `factory/publisher_credentials.py`, `factory/publisher_key_check.py`, `factory/publisher_status.py`, `docs/investigation-publisher-setup.md` | `tests/test_investigation_publisher.py`, `tests/test_investigation_broker.py`, `tests/test_publisher_credentials.py`, `tests/test_publisher_operator_reads.py` | `test` |
| Experiments | `experiments/b1-build/build.py`, `experiments/o1-observation/observer.py`, `experiments/escalation-reasons/classify.py` | `tests/test_b1_build.py`, `tests/test_o1_observation.py`, `tests/test_escalation_reasons.py` | `test` |
