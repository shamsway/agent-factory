"""Apply's GitHub identity guard: one approved, token-pinned account for every apply GitHub call.

A fake `gh` on PATH maps tokens to logins and journals every invocation with the token
it ran under, so the tests see who would have authored each read and write.

Run: python -m unittest discover -s tests
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from factory import apply, artifacts, config, dispatch, github_identity, incidents, verify_secrets
from tests.test_factory import make_repo

BOT, ALICE = "factory-bot", "alice"
EMU = "factory-bot_acme"  # Enterprise Managed User: login plus `_<shortcode>`
TOKENS = {"bot-token-0001": BOT, "alice-token-0001": ALICE, "emu-token-0001": EMU,
          "bad-login-0001": "not a login!"}

FAKE_GH = textwrap.dedent('''\
    #!/usr/bin/env python3
    import json, os, sys
    args = sys.argv[1:]
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token and os.environ.get("GH_CONFIG_DIR"):
        path = os.path.join(os.environ["GH_CONFIG_DIR"], "token")
        token = open(path).read().strip() if os.path.exists(path) else None
    accounts = json.loads(os.environ["FAKE_GH_ACCOUNTS"])
    with open(os.environ["FAKE_GH_LOG"], "a") as log:
        log.write(json.dumps({"args": args, "token": token}) + "\\n")
    if not token:
        sys.exit(4)
    if args[:2] == ["auth", "token"]:
        print(token)
    elif token not in accounts:
        print("gh: Bad credentials (HTTP 401)", file=sys.stderr)
        sys.exit(1)
    elif args[:2] == ["api", "user"]:
        print(json.dumps({"login": accounts[token]}))
    elif args[:2] == ["pr", "list"]:
        print("[]")
    elif args[:2] == ["api", "graphql"]:
        print(json.dumps({"data": {"repository": {"pullRequests": {
            "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}}}}))
    elif args[:1] == ["api"] and "POST" in args:
        print(json.dumps({"number": 1}))
    elif args[:1] == ["api"]:
        print("[]")
''')


def verified(login: str = BOT) -> github_identity.Identity:
    return github_identity.Identity("verified", login, (login,), f"authenticated as {login}", "test-token-0001")


def pin_for_module() -> None:
    """For modules that exercise apply/incident paths, not the guard: every resolution
    succeeds and an identity is pinned for direct calls (apply_one, deliver)."""
    identity = verified()
    patcher = mock.patch.object(github_identity, "resolve", return_value=identity)
    patcher.start()
    unittest.addModuleCleanup(patcher.stop)
    prior = github_identity._pinned
    github_identity._pinned = identity
    unittest.addModuleCleanup(setattr, github_identity, "_pinned", prior)


class FakeGitHub:
    """A fake gh on PATH plus two gh config dirs: the machine account and a human's."""

    def __init__(self, test: unittest.TestCase):
        temporary = tempfile.TemporaryDirectory()
        test.addCleanup(temporary.cleanup)
        self.dir = Path(temporary.name)
        (self.dir / "bin").mkdir()
        gh = self.dir / "bin" / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(0o755)
        self.log = self.dir / "gh.log"
        self.bot_config = self.login_dir("bot", "bot-token-0001")
        self.human_config = self.login_dir("human", "alice-token-0001")
        env = mock.patch.dict(os.environ, {
            "PATH": f"{self.dir / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}",
            "FAKE_GH_ACCOUNTS": json.dumps(TOKENS), "FAKE_GH_LOG": str(self.log),
            # The operator's shell: a human account, by config dir and by token.
            "GH_CONFIG_DIR": str(self.human_config), "GH_TOKEN": "alice-token-0001",
        })
        env.start()
        test.addCleanup(env.stop)

    def login_dir(self, name: str, token: str) -> Path:
        path = self.dir / name
        path.mkdir()
        (path / "token").write_text(token + "\n")
        return path

    def calls(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def authors(self) -> set[str | None]:
        """Login of every call other than the guard's own token lookup."""
        return {TOKENS.get(c["token"]) for c in self.calls() if c["args"][:2] != ["auth", "token"]}


def cfg_for(root: Path, *, logins=(BOT,), dispatch_env: dict | None = None) -> config.Config:
    cfg = config.load(make_repo(root, "[apply]\nenabled = true\n"))
    cfg.apply_github_logins = tuple(logins)
    if dispatch_env is not None:
        cfg.install["dispatch_env"] = dispatch_env
    return cfg


class ResolveTest(unittest.TestCase):
    def setUp(self) -> None:
        self.gh = FakeGitHub(self)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_expected_account_is_verified_and_pinned_by_token(self) -> None:
        cfg = cfg_for(self.root, dispatch_env={"GH_CONFIG_DIR": str(self.gh.bot_config)})
        identity = github_identity.resolve(cfg)
        self.assertTrue(identity.verified)
        self.assertEqual((identity.status, identity.login), ("verified", BOT))
        self.assertEqual(identity.token, "bot-token-0001")
        self.assertNotIn("bot-token-0001", repr(identity))
        self.assertNotIn("bot-token-0001", json.dumps(identity.metadata()))

    def test_wrong_account_is_a_mismatch(self) -> None:
        cfg = cfg_for(self.root, dispatch_env={"GH_CONFIG_DIR": str(self.gh.human_config)})
        identity = github_identity.resolve(cfg)
        self.assertEqual((identity.status, identity.login), ("mismatch", ALICE))
        self.assertFalse(identity.verified)
        self.assertEqual(identity.token, "")
        with self.assertRaisesRegex(github_identity.IdentityRefused, "alice, not an approved login"):
            github_identity.require(cfg)

    def test_ambient_token_cannot_override_the_configured_identity(self) -> None:
        # The shell carries GH_TOKEN and GH_CONFIG_DIR for alice; only host config selects.
        cfg = cfg_for(self.root, dispatch_env={"GH_CONFIG_DIR": str(self.gh.bot_config)})
        self.assertEqual(os.environ["GH_TOKEN"], "alice-token-0001")
        self.assertEqual(github_identity.resolve(cfg).login, BOT)

    def test_configured_token_selects_the_account(self) -> None:
        cfg = cfg_for(self.root, logins=(ALICE,), dispatch_env={"GH_TOKEN": "alice-token-0001"})
        self.assertEqual(github_identity.resolve(cfg).status, "verified")

    def test_auth_failure_is_unavailable(self) -> None:
        cfg = cfg_for(self.root, dispatch_env={"GH_CONFIG_DIR": str(self.gh.dir / "logged-out")})
        self.assertEqual(github_identity.resolve(cfg).status, "unavailable")
        cfg.install["dispatch_env"] = {"GH_TOKEN": "revoked-token-0001"}
        identity = github_identity.resolve(cfg)
        self.assertEqual((identity.status, identity.login), ("unavailable", ""))

    def test_missing_gh_is_unavailable(self) -> None:
        cfg = cfg_for(self.root, dispatch_env={"GH_CONFIG_DIR": str(self.gh.bot_config)})
        with mock.patch.dict(os.environ, {"PATH": str(self.gh.dir / "nothing")}):
            self.assertEqual(github_identity.resolve(cfg).status, "unavailable")

    def test_malformed_login_and_token_are_refused(self) -> None:
        cfg = cfg_for(self.root, dispatch_env={"GH_TOKEN": "bad-login-0001"})
        self.assertEqual(github_identity.resolve(cfg).status, "malformed")
        cfg.install["dispatch_env"] = {"GH_TOKEN": "two words"}
        self.assertEqual(github_identity.resolve(cfg).status, "malformed")

    def test_enterprise_managed_user_login_is_verified(self) -> None:
        cfg = cfg_for(self.root, logins=(EMU,), dispatch_env={"GH_TOKEN": "emu-token-0001"})
        identity = github_identity.resolve(cfg)
        self.assertEqual((identity.status, identity.login), ("verified", EMU))

    def test_unconfigured_allowlist_fails_closed_but_names_the_login(self) -> None:
        cfg = cfg_for(self.root, logins=(), dispatch_env={"GH_CONFIG_DIR": str(self.gh.bot_config)})
        identity = github_identity.resolve(cfg)
        self.assertEqual((identity.status, identity.login), ("unconfigured", BOT))
        self.assertFalse(identity.verified)

    def test_login_comparison_ignores_case(self) -> None:
        cfg = cfg_for(self.root, logins=("Factory-Bot",), dispatch_env={"GH_CONFIG_DIR": str(self.gh.bot_config)})
        self.assertTrue(github_identity.resolve(cfg).verified)

    def test_manual_and_scheduled_runs_resolve_the_same_account(self) -> None:
        cfg = cfg_for(self.root, dispatch_env={"GH_CONFIG_DIR": str(self.gh.bot_config)})
        cfg.install["env"] = {"UV_EXCLUDE_NEWER": "7 days"}
        # The apply unit: PATH, [install].env and [install].dispatch_env (onboard.units).
        unit = {"PATH": os.environ["PATH"], "FAKE_GH_ACCOUNTS": os.environ["FAKE_GH_ACCOUNTS"],
                "FAKE_GH_LOG": os.environ["FAKE_GH_LOG"], **cfg.install["env"], **cfg.install["dispatch_env"]}
        scheduled = github_identity.resolve(cfg, base=unit)
        manual = github_identity.resolve(cfg)  # the operator shell, signed in as alice
        self.assertEqual((scheduled.login, scheduled.token), (manual.login, manual.token))
        selectors = [{k: env.get(k) for k in github_identity.SELECTORS}
                     for env in (github_identity.identity_env(cfg, unit), github_identity.identity_env(cfg))]
        self.assertEqual(selectors[0], selectors[1])

    def test_pinned_token_survives_a_later_account_switch(self) -> None:
        cfg = cfg_for(self.root, dispatch_env={"GH_CONFIG_DIR": str(self.gh.bot_config)})
        identity = github_identity.require(cfg)
        with github_identity.pinned(identity):
            # `gh auth switch` in the machine config and a new token in the process env.
            (self.gh.bot_config / "token").write_text("alice-token-0001\n")
            with mock.patch.dict(os.environ, {"GH_TOKEN": "alice-token-0001", "GITHUB_TOKEN": "alice-token-0001"}):
                dispatch.run(["gh", "api", "user"], check=False)
                dispatch.run(["gh", "api", "user"], check=False, env={**os.environ, "GH_TOKEN": "alice-token-0001"})
        self.assertIsNone(github_identity.current())
        used = [c["token"] for c in self.gh.calls() if c["args"] == ["api", "user"]]
        self.assertEqual(used[-2:], ["bot-token-0001", "bot-token-0001"])

    def test_unverified_identity_cannot_be_pinned(self) -> None:
        with self.assertRaises(github_identity.IdentityRefused), \
                github_identity.pinned(github_identity.Identity("mismatch", ALICE, (BOT,), "x")):
            pass
        self.assertIsNone(github_identity.current())


class ApplyGuardTest(unittest.TestCase):
    """`factory apply` refuses before retention, publication retries, discovery,
    comments, incident delivery and any deployment effect."""

    def setUp(self) -> None:
        self.gh = FakeGitHub(self)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def run_apply(self, cfg: config.Config, argv: list[str], retry_pending=None):
        real_run = dispatch.run

        def run(cmd, cwd=None, check=True, **kwargs):
            if cmd[0] == "gh":
                return real_run(cmd, cwd=cwd, check=check, **kwargs)
            return subprocess.CompletedProcess(cmd, 0, "", "")  # git fetch: no remote here

        with (
            mock.patch.object(config, "load", return_value=cfg),
            mock.patch.object(dispatch, "run", side_effect=run),
            mock.patch("factory.retention.prune", return_value={"removed": [], "retained": [], "errors": []}) as prune,
            mock.patch.object(artifacts, "retry_pending", side_effect=retry_pending or (lambda *a: {})) as retry,
            mock.patch.object(incidents, "deliver", return_value=[]) as deliver,
            mock.patch.object(apply, "apply_one") as apply_one,
            mock.patch.object(apply, "log") as log,
        ):
            code = apply.main(argv)
        return code, {"prune": prune, "retry": retry, "deliver": deliver, "apply_one": apply_one,
                      "log": " ".join(str(c.args[0]) for c in log.call_args_list)}

    def assert_refused_before_side_effects(self, code: int, seen: dict) -> None:
        self.assertEqual(code, 1)
        for name in ("prune", "retry", "deliver", "apply_one"):
            seen[name].assert_not_called()
        self.assertFalse((self.root / "repo" / ".factory" / "apply.lock").exists())
        # Only the guard's own lookups ran: no discovery, comment or incident request.
        self.assertTrue(all(c["args"][:2] in (["auth", "token"], ["api", "user"]) for c in self.gh.calls()))
        self.assertIn("refused: GitHub identity", seen["log"])

    def test_wrong_account_refuses_the_pass(self) -> None:
        cfg = cfg_for(self.root, dispatch_env={"GH_CONFIG_DIR": str(self.gh.human_config)})
        code, seen = self.run_apply(cfg, [])
        self.assert_refused_before_side_effects(code, seen)
        self.assertIn("mismatch", seen["log"])
        self.assertNotIn("alice-token-0001", seen["log"])

    def test_unconfigured_allowlist_refuses_the_pass_and_dry_run(self) -> None:
        cfg = cfg_for(self.root, logins=(), dispatch_env={"GH_CONFIG_DIR": str(self.gh.bot_config)})
        for argv in ([], ["--dry-run"]):
            with self.subTest(argv=argv):
                code, seen = self.run_apply(cfg, argv)
                self.assert_refused_before_side_effects(code, seen)
                self.assertIn("unconfigured", seen["log"])

    def test_auth_failure_refuses_the_pass(self) -> None:
        cfg = cfg_for(self.root, dispatch_env={"GH_TOKEN": "revoked-token-0001"})
        code, seen = self.run_apply(cfg, [])
        self.assert_refused_before_side_effects(code, seen)
        self.assertIn("unavailable", seen["log"])

    def test_pending_publication_retry_is_blocked_on_refusal(self) -> None:
        cfg = cfg_for(self.root, dispatch_env={"GH_CONFIG_DIR": str(self.gh.human_config)})
        code, seen = self.run_apply(cfg, [], retry_pending=lambda factory, post: {"r": {"issue": post("issue", 7, "x")}})
        self.assert_refused_before_side_effects(code, seen)
        # Outside a pinned pass, the publication sink itself refuses without calling gh.
        before = len(self.gh.calls())
        self.assertEqual(apply.post_comment("issue", 7, "body"), (False, "no verified apply GitHub identity"))
        self.assertEqual(len(self.gh.calls()), before)

    def test_expected_account_authors_every_call_despite_the_shell(self) -> None:
        cfg = cfg_for(self.root, dispatch_env={"GH_CONFIG_DIR": str(self.gh.bot_config)})
        posted = []

        def retry_pending(factory, post):
            # A switch between the check and the use does not change authorship.
            (self.gh.bot_config / "token").write_text("alice-token-0001\n")
            posted.append(post("issue", 7, "retried result"))
            return {}

        code, seen = self.run_apply(cfg, [], retry_pending=retry_pending)
        self.assertEqual(code, 0)
        self.assertEqual(posted, [(True, "")])
        seen["retry"].assert_called_once()
        seen["deliver"].assert_called_once()
        self.assertEqual(self.gh.authors(), {BOT})
        commands = [c["args"][:2] for c in self.gh.calls()]
        self.assertIn(["issue", "comment"], commands)
        self.assertIn(["api", "graphql"], commands)
        self.assertIsNone(github_identity.current())

    def test_dispatcher_identity_is_used_without_the_unit_environment(self) -> None:
        # A manual run from a human shell posts as the dispatcher, exactly like the unit.
        cfg = cfg_for(self.root, dispatch_env={"GH_CONFIG_DIR": str(self.gh.bot_config)})
        code, _ = self.run_apply(cfg, [], retry_pending=lambda factory, post: {"r": {"issue": post("issue", 7, "x")}})
        self.assertEqual(code, 0)
        self.assertEqual(self.gh.authors(), {BOT})

    def test_escalation_and_supersession_comments_need_a_pinned_identity(self) -> None:
        cfg = cfg_for(self.root)
        apply.configure(cfg)
        with mock.patch.object(dispatch, "run") as run, mock.patch.object(apply, "log"):
            apply.apply_escalate(7, 3, "boom", commit="abcdef12")
            apply.supersede({"ticket": 6, "pr": 2, "commit": "a" * 40}, {"ticket": 7, "commit": "b" * 40}, "default")
        self.assertFalse([c for c in run.call_args_list if c.args[0][0] == "gh"])

    def test_authorize_revision_refuses_without_an_approved_identity(self) -> None:
        cfg = cfg_for(self.root, dispatch_env={"GH_CONFIG_DIR": str(self.gh.human_config)})
        code, seen = self.run_apply(cfg, ["--authorize-revision", "5", "--reason", "solo operator"])
        self.assertEqual(code, 1)
        self.assertIn("refused: GitHub identity", seen["log"])
        self.assertFalse([c for c in self.gh.calls() if c["args"][:2] == ["pr", "view"]])

    def test_local_recovery_paths_need_no_github_identity(self) -> None:
        cfg = cfg_for(self.root, logins=())
        with mock.patch.object(github_identity, "resolve") as resolve:
            code, _ = self.run_apply(cfg, ["--acknowledge-failure", "999"])
            self.assertEqual(code, 1)  # nothing to acknowledge; but no identity was required
            code, _ = self.run_apply(cfg, ["--reconcile-run", "deploy-default-x-1", "--dry-run"])
            self.assertEqual(code, 1)
        resolve.assert_not_called()

    def test_disabled_apply_needs_no_identity(self) -> None:
        cfg = cfg_for(self.root, logins=())
        cfg.apply_enabled = False
        with mock.patch.object(github_identity, "resolve") as resolve:
            code, _ = self.run_apply(cfg, [])
        self.assertEqual(code, 0)
        resolve.assert_not_called()


class IncidentGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.gh = FakeGitHub(self)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def queued(self, cfg: config.Config) -> str:
        from tests.test_incidents import failed
        return incidents.enqueue(cfg.factory, cfg.repo, failed())

    def test_delivery_without_a_pinned_identity_touches_nothing(self) -> None:
        cfg = cfg_for(self.root)
        rid = self.queued(cfg)
        path = cfg.factory / "incidents" / f"{rid}.json"
        before = path.read_bytes()
        client = incidents.GitHub(cfg)
        with self.assertRaises(github_identity.IdentityRefused):
            incidents.deliver(cfg.factory, client)
        with self.assertRaises(github_identity.IdentityRefused):
            incidents.recover(cfg.factory, rid, client)
        row = incidents.read(path)
        for write in (lambda: client.create(row), lambda: client.update(row, {"body": ""})):
            with self.assertRaises(github_identity.IdentityRefused):
                write()
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.gh.calls(), [])

    def test_cli_delivery_refuses_a_wrong_account_before_any_incident_request(self) -> None:
        cfg = cfg_for(self.root, dispatch_env={"GH_CONFIG_DIR": str(self.gh.human_config)})
        rid = self.queued(cfg)
        with mock.patch.object(config, "load", return_value=cfg), \
             mock.patch("builtins.print") as printed:
            self.assertEqual(incidents.main(["--deliver"]), 1)
            self.assertEqual(incidents.main(["--retry", rid]), 1)
        out = [json.loads(c.args[0]) for c in printed.call_args_list]
        self.assertEqual({o["status"] for o in out}, {"refused"})
        self.assertIn("mismatch", out[0]["reason"])
        self.assertNotIn("alice-token-0001", json.dumps(out))
        self.assertTrue(all(c["args"][:2] in (["auth", "token"], ["api", "user"]) for c in self.gh.calls()))
        self.assertEqual(incidents.read(cfg.factory / "incidents" / f"{rid}.json")["status"], "pending")

    def test_cli_delivery_creates_the_incident_as_the_approved_account(self) -> None:
        cfg = cfg_for(self.root, dispatch_env={"GH_CONFIG_DIR": str(self.gh.bot_config)})
        rid = self.queued(cfg)
        with mock.patch.object(config, "load", return_value=cfg), mock.patch("builtins.print"):
            self.assertEqual(incidents.main(["--deliver"]), 0)
        self.assertEqual(incidents.read(cfg.factory / "incidents" / f"{rid}.json")["status"], "delivered")
        self.assertIn("POST", [a for c in self.gh.calls() for a in c["args"]])
        self.assertEqual(self.gh.authors(), {BOT})

    def test_local_incident_views_need_no_identity(self) -> None:
        cfg = cfg_for(self.root, logins=())
        rid = self.queued(cfg)
        with mock.patch.object(config, "load", return_value=cfg), mock.patch("builtins.print"), \
             mock.patch.object(github_identity, "resolve") as resolve:
            self.assertEqual(incidents.main(["--id", rid]), 0)
        resolve.assert_not_called()


class ConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.xdg = self.root / "xdg"
        (self.xdg / "factory").mkdir(parents=True)
        env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.xdg)})
        env.start()
        self.addCleanup(env.stop)

    def host(self, text: str) -> None:
        (self.xdg / "factory" / "config.toml").write_text(text)

    def test_logins_are_host_owned(self) -> None:
        repo = make_repo(self.root, "[apply]\nenabled = true\n")
        self.assertEqual(config.load(repo).apply_github_logins, ())
        self.host('[repo."acme/widgets".apply]\ngithub_logins = ["factory-bot"]\n')
        self.assertEqual(config.load(repo).apply_github_logins, (BOT,))
        self.assertIn("github_logins", config.HOST_KEYS["apply"])

    def test_enterprise_managed_user_logins_are_accepted(self) -> None:
        repo = make_repo(self.root, "[apply]\nenabled = true\n")
        self.host(f'[defaults.apply]\ngithub_logins = ["{EMU}"]\n')
        self.assertEqual(config.load(repo).apply_github_logins, (EMU,))

    def test_committed_logins_are_refused(self) -> None:
        repo = make_repo(self.root, '[apply]\nenabled = true\ngithub_logins = ["alice"]\n')
        with self.assertRaisesRegex(config.ConfigError, "host-only"):
            config.load(repo)

    def test_malformed_logins_are_refused(self) -> None:
        repo = make_repo(self.root, "[apply]\nenabled = true\n")
        for bad in ('"factory-bot"', '["@acme/ops"]', '["bad login"]', "[1]", '["bot_"]', '["_acme"]',
                    '["bot__acme"]', '["bot_acme_ops"]'):
            with self.subTest(bad=bad):
                self.host(f"[defaults.apply]\ngithub_logins = {bad}\n")
                with self.assertRaisesRegex(config.ConfigError, "github_logins"):
                    config.load(repo)


class MetadataTest(unittest.TestCase):
    def setUp(self) -> None:
        self.gh = FakeGitHub(self)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_verify_secrets_reports_names_and_status_only(self) -> None:
        cfg = cfg_for(self.root, dispatch_env={"GH_CONFIG_DIR": str(self.gh.bot_config)})
        offline = verify_secrets.identity_row(cfg, live=False)
        self.assertEqual((offline["status"], offline["allowed"]), ("configured", [BOT]))
        live = verify_secrets.identity_row(cfg, live=True)
        self.assertEqual((live["status"], live["login"]), ("valid", BOT))
        cfg.install["dispatch_env"] = {"GH_CONFIG_DIR": str(self.gh.human_config)}
        wrong = verify_secrets.identity_row(cfg, live=True)
        self.assertEqual((wrong["status"], wrong["login"]), ("mismatch", ALICE))
        self.assertIn("mismatch", verify_secrets.BAD_STATUSES)
        cfg.apply_github_logins = ()
        self.assertEqual(verify_secrets.identity_row(cfg, live=False)["status"], "unconfigured")
        self.assertIn("unconfigured", verify_secrets.BAD_STATUSES)
        rows = verify_secrets.credential_rows(cfg, "apply", live=True)
        text = json.dumps(rows)
        for token in TOKENS:
            self.assertNotIn(token, text)
        self.assertNotIn(str(self.gh.dir), text)

    def test_identity_row_only_for_apply_enabled_repos(self) -> None:
        cfg = cfg_for(self.root)
        self.assertTrue([r for r in verify_secrets.credential_rows(cfg, "apply", False) if r["key"] == "github_identity"])
        cfg.apply_enabled = False
        self.assertFalse([r for r in verify_secrets.credential_rows(cfg, "all", False) if r["key"] == "github_identity"])


if __name__ == "__main__":
    unittest.main()
