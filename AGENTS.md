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
