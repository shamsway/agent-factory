"""Contract checks: config resolution and the gate, against a throwaway git repo.

Run: python -m unittest discover -s tests
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# Never read the operator's real host config; HostConfigTest writes its own here.
XDG = Path(tempfile.mkdtemp())
os.environ["XDG_CONFIG_HOME"] = str(XDG)

from agent_factory import __version__, config  # noqa: E402


def host_file(text: str) -> None:
    path = XDG / "agent-factory" / "config.toml"
    if text:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    elif path.exists():
        path.unlink()


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True).stdout.strip()


def make_repo(tmp: Path, toml: str = "") -> Path:
    repo = tmp / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "t@example.com")
    git(repo, "config", "user.name", "T")
    git(repo, "remote", "add", "origin", "git@github.com:acme/widgets.git")
    (repo / "README.md").write_text("hello\n")
    if toml:
        (repo / config.CONFIG_NAME).write_text(toml)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "init")
    # The gate diffs against origin/<main>; a local ref stands in for the remote.
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    return repo


def factory(cwd: Path, *argv: str, path: str | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    if path:
        env["PATH"] = f"{path}:{env['PATH']}"
    return subprocess.run(
        [sys.executable, "-m", "agent_factory", *argv], cwd=cwd, capture_output=True, text=True, env=env, check=False,
    )


def stub_bin(tmp: Path, **scripts: str) -> str:
    """Fake executables first on PATH: name -> sh body; each appends its argv to <bin>/<name>.log."""
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    for name, body in scripts.items():
        exe = bindir / name
        exe.write_text(f'#!/bin/sh\necho "$@" >> "{bindir / name}.log"\n{body}\n')
        exe.chmod(0o755)
    return str(bindir)


def gate(cwd: Path, *args: str) -> tuple[int, str, str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    proc = subprocess.run(
        [sys.executable, "-m", "agent_factory", "gate", *args],
        cwd=cwd, capture_output=True, text=True, env=env, check=False,
    )
    report = cwd / ".factory" / "gate-report.md"
    return proc.returncode, proc.stdout + proc.stderr, report.read_text() if report.exists() else ""


class ConfigTest(unittest.TestCase):
    def test_defaults_from_origin(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d).resolve())
            cfg = config.load(repo)
            self.assertEqual(cfg.repo, "acme/widgets")
            self.assertEqual(cfg.name, "widgets")
            self.assertEqual(cfg.unit, "factory-widgets")
            self.assertIsNone(cfg.upstream)
            self.assertEqual(cfg.checks, [])
            self.assertEqual(cfg.factory, repo / ".factory")
            self.assertEqual(cfg.worker({"chore"}, Path("/p"), Path("/w"))[0], "droid")
            self.assertEqual(cfg.worker(set(), Path("/p"), Path("/w")), ["omp", "-p", "--cwd", "/w", "@/p"])

    def test_overrides_and_worktree_root(self) -> None:
        toml = """
[repo]
slug = "other/name"
upstream = "up"
main = "trunk"
[dispatch]
max_active = 5
signoff = false
[workers]
default = ["agent", "{prompt}"]
[review]
command = ["rev", "--ask", "{prompt}"]
[gate]
timeout = 7
lock = "/tmp/x.lock"
[[gate.check]]
name = "unit"
run = ["true"]
exclusive = true
[leak_scan]
pattern = ""
exclude = ["vendor"]
[triage]
model = "m"
key = "sk-abc"
[dashboard]
port = 1
"""
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d).resolve(), toml)
            cfg = config.load(repo)
            self.assertEqual((cfg.repo, cfg.upstream, cfg.main), ("other/name", "up", "trunk"))
            self.assertEqual((cfg.max_active, cfg.signoff, cfg.check_timeout), (5, False, 7))
            self.assertEqual(cfg.review_cmd("hi {x}"), ["rev", "--ask", "hi {x}"])
            self.assertEqual([(c.name, c.exclusive) for c in cfg.checks], [("unit", True)])
            self.assertIsNone(cfg.leak_pattern)
            self.assertEqual((cfg.leak_exclude, cfg.llm_model, cfg.llm_key, cfg.dashboard_port), (["vendor"], "m", "sk-abc", 1))
            # A worktree resolves to the main checkout, not itself.
            wt = Path(d).resolve() / "wt"
            git(repo, "worktree", "add", "-q", str(wt), "-b", "agent/1")
            self.assertEqual(config.load(wt).root, repo)

    def test_rejects_reserved_check_names(self) -> None:
        toml = '[[gate.check]]\nname = "leak-scan"\nrun = ["true"]\n'
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml)
            with self.assertRaises(SystemExit):
                config.load(repo)


class HostConfigTest(unittest.TestCase):
    """`$XDG_CONFIG_HOME/agent-factory/config.toml` layers under the repo file."""

    def tearDown(self) -> None:
        host_file("")

    def test_precedence_and_filter(self) -> None:
        host_file(
            '[defaults.triage]\nurl = "http://h/v1/chat/completions"\nmodel = "d"\nkey = "sk-default"\n'
            '[defaults.dashboard]\nport = 9000\ntheme = "host.css"\n'
            '[defaults.gate]\nlock = "/tmp/host.lock"\n[[defaults.gate.check]]\nname = "evil"\nrun = ["true"]\n'
            '[defaults.leak_scan]\npattern = ""\n[defaults.repo]\nupstream = "evil"\n'
            '[defaults.install]\nevery = "5min"\ndashboard = true\n[defaults.install.env]\nA = "1"\n'
            '[repo."acme/widgets"]\npath = "/x"\n[repo."acme/widgets".triage]\nmodel = "r"\n'
            '[repo."acme/widgets".dashboard]\nport = 9001\n'
        )
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), '[triage]\nmodel = "f"\n')
            cfg = config.load(repo)
            # defaults < per-repo < repo file; key comes only from defaults here
            # (a per-repo/committed key would be a real secret leaking into git).
            self.assertEqual((cfg.llm_url, cfg.llm_model, cfg.llm_key, cfg.dashboard_port), ("http://h/v1/chat/completions", "f", "sk-default", 9001))
            self.assertEqual(cfg.lock, Path("/tmp/host.lock"))
            self.assertEqual(cfg.install, {"every": "5min", "dashboard": True, "host": "127.0.0.1", "env": {"A": "1"}})
            # repo-owned keys never come from the host
            self.assertEqual(cfg.checks, [])
            self.assertEqual(cfg.leak_pattern, config.DEFAULT_LEAK_PATTERN)
            self.assertIsNone(cfg.upstream)
            self.assertIsNone(cfg.dashboard_theme)
            self.assertEqual(cfg.raw_repo, {"triage": {"model": "f"}})

    def test_missing_host_file_is_current_behaviour(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            cfg = config.load(make_repo(Path(d)))
            self.assertEqual((cfg.llm_url, cfg.dashboard_port, cfg.install), (config.DEFAULT_LLM_URL, 8765, config.DEFAULT_INSTALL))

    def test_repo_table_matched_by_resolved_slug(self) -> None:
        host_file('[repo."other/name".dashboard]\nport = 7\n[repo."acme/widgets".dashboard]\nport = 8\n')
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), '[repo]\nslug = "other/name"\n')
            self.assertEqual(config.load(repo).dashboard_port, 7)

    def test_unknown_keys(self) -> None:
        raw = {"triage": {"mdoel": "x"}, "gate": {"check": [{"name": "a", "run": [], "exclusiv": True}]}, "bogus": {}}
        self.assertEqual(config.unknown_keys(raw), ["triage.mdoel", "gate.check[0].exclusiv", "bogus"])
        # triage.key (the Authorization-header bearer token) is loader-known,
        # not drift -- regression check for the gap where config.load() read
        # it fine but doctor's "host config: ignored (not host-owned)" check
        # flagged it as unknown anyway (KNOWN_KEYS wasn't updated alongside).
        self.assertEqual(config.unknown_keys({"triage": {"key": "sk-x"}}), [])

    def test_install_print_uses_host_defaults_and_env(self) -> None:
        host_file('[defaults.install]\nevery = "5min"\ndashboard = true\n[defaults.install.env]\nUV_EXCLUDE_NEWER = "2026-01-01T00:00:00Z"\n')
        with tempfile.TemporaryDirectory() as d:
            proc = factory(make_repo(Path(d)), "install", "--print")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("OnUnitActiveSec=5min", proc.stdout)
            self.assertIn("Environment=UV_EXCLUDE_NEWER=2026-01-01T00:00:00Z", proc.stdout)
            self.assertIn("# factory-widgets-dashboard.service", proc.stdout)
            self.assertIn("# factory-widgets-triage.service", proc.stdout)
            self.assertIn("# factory-widgets-triage.timer", proc.stdout)
            self.assertIn("ExecStart=", proc.stdout)
            self.assertIn(" triage\n", proc.stdout)  # triage service actually invokes `factory triage`
            self.assertIn("--host 127.0.0.1", proc.stdout)
            (Path(d) / "b").mkdir()
            proc = factory(make_repo(Path(d) / "b"), "install", "--print", "--no-dashboard")
            self.assertNotIn("dashboard.service", proc.stdout)
            self.assertIn("# factory-widgets-triage.service", proc.stdout)  # triage isn't gated by --dashboard

    def test_init_labels_only_touches_nothing_and_fails_on_gh(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            proc = factory(repo, "init", "--labels-only", path=stub_bin(Path(d), gh="exit 0"))
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(git(repo, "status", "--porcelain"), "")
            calls = (Path(d) / "bin" / "gh.log").read_text().splitlines()
            self.assertEqual(len(calls), len(config.LABELS))
            self.assertTrue(all(c.startswith("label create ") and "--repo acme/widgets" in c for c in calls))
            proc = factory(repo, "init", "--labels-only", path=stub_bin(Path(d), gh="echo nope >&2; exit 1"))
            self.assertEqual(proc.returncode, 1)
            self.assertIn("nope", proc.stdout)

    def test_doctor_json_reports_drift(self) -> None:
        host_file('[defaults.triage]\nurl = "http://127.0.0.1:1/v1/chat/completions"\n[defaults.leak_scan]\npattern = ""\n[repo."acme/widgets"]\npath = "/x"\n[repo."acme/widgets".dashboard]\nport = 1\ntheme = "no"\n')
        gh = 'case "$1 $2" in "repo view") echo ADMIN;; "label list") echo "[]";; esac\nexit 0'
        toml = '[triage]\nmodel = "m"\n[dashboard]\ntheme = "t.css"\n[gate]\nlock = "/tmp/l"\ntimeout = 5\n[dispatch]\nmax_atempts = 2\n'
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d).resolve(), toml)
            (repo / ".github/ISSUE_TEMPLATE").mkdir(parents=True)
            (repo / ".github/ISSUE_TEMPLATE/agent_task.md").write_text("custom\n")
            proc = factory(repo, "doctor", "--json", path=stub_bin(Path(d), gh=gh, systemctl="echo inactive"))
            out = json.loads(proc.stdout)
            self.assertEqual((out["repo"], out["root"], out["version"]), ("acme/widgets", str(repo), __version__))
            rows = {r["label"]: r for r in out["rows"]}
            self.assertEqual(rows[".factory.toml keys"]["status"], "WARN")
            self.assertIn("dispatch.max_atempts", rows[".factory.toml keys"]["detail"])
            self.assertEqual(rows["host settings committed"]["status"], "WARN")
            self.assertIn("triage, gate.lock", rows["host settings committed"]["detail"])
            self.assertNotIn("dashboard", rows["host settings committed"]["detail"])  # theme is repo-owned
            self.assertEqual(rows["defaults in effect"]["status"], "INFO")
            self.assertIn("dispatch.review_rounds", rows["defaults in effect"]["detail"])
            self.assertNotIn("gate.timeout", rows["defaults in effect"]["detail"])
            self.assertEqual(rows[".github/ISSUE_TEMPLATE/agent_task.md"]["status"], "WARN")
            self.assertEqual(rows["host config"]["status"], "WARN")
            self.assertIn('defaults.leak_scan, repo."acme/widgets".dashboard.theme', rows["host config"]["detail"])
            self.assertEqual(rows["push access to acme/widgets"]["status"], "PASS")
            self.assertEqual(out["ok"], proc.returncode == 0)

    def test_doctor_flags_non_loopback_dashboard_bind(self) -> None:
        """SHA-176: policy is loopback-only + SSH tunnel; doctor should FAIL a
        non-loopback [install].host with no escape hatch, and only WARN (not
        pass silently) once FACTORY_DASHBOARD_ALLOW_REMOTE is set."""
        gh = 'case "$1 $2" in "repo view") echo ADMIN;; "label list") echo "[]";; esac\nexit 0'
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            host_file('[repo."acme/widgets".install]\nhost = "0.0.0.0"\n')
            proc = factory(repo, "doctor", "--json", path=stub_bin(Path(d), gh=gh, systemctl="echo inactive"))
            rows = {r["label"]: r for r in json.loads(proc.stdout)["rows"]}
            self.assertEqual(rows["dashboard bind"]["status"], "FAIL")
            self.assertIn("FACTORY_DASHBOARD_ALLOW_REMOTE", rows["dashboard bind"]["detail"])

            host_file(
                '[repo."acme/widgets".install]\nhost = "0.0.0.0"\n'
                '[repo."acme/widgets".install.env]\nFACTORY_DASHBOARD_ALLOW_REMOTE = "1"\n'
            )
            proc = factory(repo, "doctor", "--json", path=stub_bin(Path(d), gh=gh, systemctl="echo inactive"))
            rows = {r["label"]: r for r in json.loads(proc.stdout)["rows"]}
            self.assertEqual(rows["dashboard bind"]["status"], "WARN")

    def test_doctor_flags_leaked_apply_credential(self) -> None:
        from unittest import mock

        gh = 'case "$1 $2" in "repo view") echo ADMIN;; "label list") echo "[]";; esac\nexit 0'
        toml = '[apply]\nenabled = true\n[apply.env]\nFAKE_CRED = "x"\n'
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml)
            with mock.patch.dict(os.environ, {"FAKE_CRED": "leaked"}):
                proc = factory(repo, "doctor", "--json", path=stub_bin(Path(d), gh=gh, systemctl="echo inactive"))
            out = json.loads(proc.stdout)
            rows = {r["label"]: r for r in out["rows"]}
            self.assertIn("terraform on PATH (required: [apply].enabled)", rows)  # checked only when apply.enabled
            leak_row = rows["apply credentials isolated from this shell"]
            self.assertEqual(leak_row["status"], "FAIL")
            self.assertIn("FAKE_CRED", leak_row["detail"])


class DashboardTest(unittest.TestCase):
    def test_dashboard_refuses_non_loopback_bind_without_escape_hatch(self) -> None:
        """SHA-176: /api/act mutates GitHub with the operator's own `gh`
        credentials and the dashboard has no auth of its own -- binding
        beyond loopback must be a hard refusal, not just a --help warning."""
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            proc = factory(repo, "dashboard", "--host", "0.0.0.0", "--no-open")
            self.assertEqual(proc.returncode, 1)
            self.assertIn("refusing to bind", proc.stderr)
            self.assertIn("FACTORY_DASHBOARD_ALLOW_REMOTE", proc.stderr)

    def test_dashboard_allows_non_loopback_with_escape_hatch(self) -> None:
        from unittest import mock

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            env = {**os.environ, "PYTHONPATH": str(ROOT), "FACTORY_DASHBOARD_ALLOW_REMOTE": "1"}
            proc = subprocess.Popen(
                [sys.executable, "-m", "agent_factory", "dashboard", "--host", "127.0.0.1", "--port", "0", "--no-open"],
                cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
            )
            try:
                line = proc.stdout.readline()
                self.assertIn("listening on 127.0.0.1:0", line)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)

    def test_triage_llm_online_sends_bearer_header_only_when_key_configured(self) -> None:
        """Same gap as call_llm() and doctor()'s endpoint check, found in a
        third place: a gated endpoint (e.g. LiteLLM) 401s without a bearer
        header, so this reported "offline" in the dashboard even while
        triage was working fine through the (correctly authenticated)
        call_llm() path. Confirmed live: the dashboard showed the triage LLM
        as offline against a real, healthy, authenticated LiteLLM endpoint."""
        from unittest import mock

        from agent_factory import dashboard

        class FakeResponse:
            status = 200

            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *exc: object) -> bool:
                return False

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), '[triage]\nurl = "http://h/v1/chat/completions"\nkey = "sk-secret"\n')
            dashboard.configure(config.load(repo))
            captured = {}

            def fake_urlopen(req, timeout=None):
                captured["auth"] = req.get_header("Authorization")
                return FakeResponse()

            with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
                self.assertTrue(dashboard.triage_llm_online())
            self.assertEqual(captured["auth"], "Bearer sk-secret")

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), '[triage]\nurl = "http://h/v1/chat/completions"\n')
            dashboard.configure(config.load(repo))
            with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
                dashboard.triage_llm_online()
            self.assertIsNone(captured["auth"])

    def test_metrics_from_synthetic_tickets(self) -> None:
        from agent_factory import dashboard

        dashboard.MAX_ATTEMPTS = 3
        att = lambda *ns: [{"attempt": n} for n in ns]  # noqa: E731
        tickets = [
            {"pr": {"number": 1}, "attempts": att(1), "events": []},  # first-gate pass
            {"pr": {"number": 2}, "attempts": att(1, 2, 4), "events": [{"kind": "escalated"}]},  # 2 gate rounds + review bounce
            {"pr": None, "attempts": att(1, 2, 3), "events": [{"kind": "escalated"}, {"kind": "comment"}]},
            {"pr": None, "attempts": [], "events": []},
        ]
        m = dashboard.metrics(tickets)
        self.assertEqual(m, {"first_pass": 0.5, "bounce_rate": 0.5, "escalations": 2, "med_attempts": 2})
        self.assertEqual(dashboard.metrics([]), {"first_pass": None, "bounce_rate": None, "escalations": 0, "med_attempts": None})

    def test_consecutive_failures_from_journal(self) -> None:
        from agent_factory import dashboard

        def entry(msg: str, ident: str = "systemd") -> str:
            return json.dumps({"MESSAGE": msg, "SYSLOG_IDENTIFIER": ident, "__REALTIME_TIMESTAMP": "1700000000000000"})

        unit = "factory-widgets.service"
        seq = [
            ("Starting agent-factory dispatcher...", "systemd"), ("Finished agent-factory dispatcher.", "systemd"),
            ("Starting agent-factory dispatcher...", "systemd"), ("Failed to start agent-factory dispatcher.", "systemd"),
            ("Starting agent-factory dispatcher...", "systemd"), ("Traceback", "python"), (f"{unit}: Failed with result 'exit-code'.", "systemd"),
            ("Starting agent-factory dispatcher...", "systemd"), ("Failed to start agent-factory dispatcher.", "systemd"),
            ("Starting agent-factory dispatcher...", "systemd"),  # still running: not counted either way
        ]
        runs = dashboard.parse_journal("\n".join(entry(m, i) for m, i in seq) + "\nnot json\n")
        self.assertEqual([r["result"] for r in runs], ["done", "failed", "failed", "failed", "running"])
        self.assertEqual(runs[2]["lines"], ["Traceback"])
        self.assertEqual(dashboard.consecutive_failures(runs), 3)
        self.assertEqual(dashboard.consecutive_failures(runs[:1]), 0)
        self.assertEqual(dashboard.consecutive_failures([]), 0)


class GateTest(unittest.TestCase):
    def test_pass_fail_skip_and_leak(self) -> None:
        toml = (
            '[[gate.check]]\nname = "ok"\nrun = ["true"]\n'
            '[[gate.check]]\nname = "bad"\nrun = ["sh", "-c", "echo boom; exit 3"]\nexclusive = true\n'
            '[gate]\nlock = "{lock}"\n'
        )
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml.replace("{lock}", str(Path(d) / "lock")))
            code, out, report = gate(repo)
            self.assertEqual(code, 1, out)
            self.assertIn("- conflict-markers: PASS", report)
            self.assertIn("- ok: PASS", report)
            self.assertIn("- bad: FAIL", report)
            self.assertIn("- leak-scan: PASS", report)
            self.assertIn("boom", report)

            code, out, report = gate(repo, "--skip", "bad")
            self.assertEqual(code, 0, out)
            self.assertIn("- bad: SKIP", report)

            # An added line matching the leak pattern fails the scan.
            (repo / "notes.md").write_text("see the CONFIDENTIAL doc\n")
            git(repo, "add", "-A")
            git(repo, "commit", "-q", "-m", "leak")
            code, out, report = gate(repo, "--skip", "bad")
            self.assertEqual(code, 1, out)
            self.assertIn("- leak-scan: FAIL", report)
            self.assertIn("CONFIDENTIAL", report)

    def test_timeout_fails_instead_of_hanging(self) -> None:
        toml = '[gate]\ntimeout = 1\n[[gate.check]]\nname = "slow"\nrun = ["sleep", "5"]\n'
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml)
            code, out, report = gate(repo)
            self.assertEqual(code, 1, out)
            self.assertIn("- slow: FAIL", report)
            self.assertIn("timed out", report)

    def test_timeout_kills_the_whole_process_tree(self) -> None:
        # A check that spawns a grandchild which outlives its parent: the gate
        # must FAIL and the grandchild must be gone (it held the GPU lock once).
        toml = (
            '[gate]\ntimeout = 1\n[[gate.check]]\nname = "slow"\n'
            'run = ["sh", "-c", "sleep 30 & echo $! > gc.pid; sleep 30"]\n'
        )
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml)
            code, out, report = gate(repo)
            self.assertEqual(code, 1, out)
            self.assertIn("- slow: FAIL", report)
            self.assertIn("timed out", report)
            pid = int((repo / "gc.pid").read_text())
            import time
            time.sleep(0.2)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)


class DispatchTest(unittest.TestCase):
    def test_prompt_carries_handoff_and_events_append(self) -> None:
        from unittest import mock

        from agent_factory import dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            dispatch.configure(config.load(repo))
            wt = dispatch.FACTORY / "wt-7"
            (wt / ".factory").mkdir(parents=True)
            (wt / ".factory" / "handoff-7.md").write_text("left the migration unverified")
            issue = {"title": "t", "body": "b", "comments": []}
            with mock.patch.object(dispatch, "gh_json", return_value=issue):
                prompt = dispatch.build_prompt(7, wt, "## extra")
            self.assertIn("## Handoff from the previous attempt", prompt)
            self.assertIn("left the migration unverified", prompt)
            self.assertIn("handoff-7.md", prompt)
            self.assertIn("git commit -s", prompt)
            self.assertTrue(prompt.rstrip().endswith("## extra"))

            dispatch.record("claimed", ticket=7)
            dispatch.record("attempt", ticket=7, attempt=1, gate="FAIL")
            rows = [json.loads(line) for line in dispatch.EVENTS.read_text().splitlines()]
            self.assertEqual([r["event"] for r in rows], ["claimed", "attempt"])
            self.assertEqual(rows[1]["gate"], "FAIL")
            self.assertTrue(all("at" in r for r in rows))

    def test_learn_writes_lessons_from_events(self) -> None:
        from unittest import mock

        from agent_factory import dispatch, learn, triage

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            cfg = config.load(repo)
            dispatch.configure(cfg)
            triage.configure(cfg)
            dispatch.record("claimed", ticket=3, title="fix parser")
            dispatch.record("attempt", ticket=3, attempt=1, gate="FAIL", seconds=5, log=str(repo / "nope.log"))
            dispatch.record("escalate", ticket=3, reason="gate failed 3 times")
            dispatch.record("claimed", ticket=4, title="in flight")  # unfinished: excluded
            tickets, ev = learn.evidence(10)
            self.assertEqual(tickets, [3])
            self.assertIn("gate failed 3 times", ev)
            reply = json.dumps({"lessons": ["Run `make test` before the gate."]})
            with mock.patch.object(triage, "call_llm", return_value=reply), \
                 mock.patch.object(config, "load", return_value=cfg):
                self.assertEqual(learn.main([]), 0)
            lessons = (repo / config.LESSONS_NAME).read_text()
            self.assertIn("- Run `make test` before the gate.", lessons)
            # The next worker prompt carries the lessons.
            wt = dispatch.FACTORY / "wt-3"
            wt.mkdir(parents=True, exist_ok=True)
            with mock.patch.object(dispatch, "gh_json", return_value={"title": "t", "body": "b", "comments": []}):
                self.assertIn("## Lessons from previous tickets", dispatch.build_prompt(3, wt))

    def test_review_prompt_inlines_issue_text(self) -> None:
        """The review command runs sandboxed (no --dangerously-skip-permissions),
        so it can't fetch the issue itself -- confirmed live on ticket #45,
        where the reviewer stalled asking for `gh issue view` approval it
        could never get non-interactively, twice, then escalated. The issue's
        title/body must be inlined into the prompt instead."""
        from unittest import mock

        from agent_factory import dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            dispatch.configure(config.load(repo))
            issue = {"title": "Add a widget", "body": "Acceptance: widget exists."}
            captured = {}

            def fake_run(cmd, cwd=None, capture_output=None, text=None):
                captured["prompt"] = cmd[-1]
                return subprocess.CompletedProcess(cmd, 0, stdout="VERDICT: APPROVE", stderr="")

            with mock.patch.object(dispatch, "gh_json", return_value=issue) as gh_mock, \
                 mock.patch("subprocess.run", side_effect=fake_run):
                verdict, findings = dispatch.review(repo, 45, "gate report")
            self.assertEqual(verdict, "APPROVE")
            self.assertIn("Add a widget", captured["prompt"])
            self.assertIn("Acceptance: widget exists.", captured["prompt"])
            self.assertIn("do not try to fetch it yourself", captured["prompt"])
            gh_mock.assert_called_once_with(
                ["issue", "view", "45", "--repo", dispatch.REPO, "--json", "title,body"]
            )

    def test_review_reports_error_verdict_when_reviewer_process_fails(self) -> None:
        """SHA-177: a reviewer process failure (auth, crash, network -- not a
        genuine review) must not be silently treated as REVISE, which would
        burn a worker round chasing findings that were never produced."""
        from unittest import mock

        from agent_factory import dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            dispatch.configure(config.load(repo))

            def fake_run(cmd, cwd=None, capture_output=None, text=None):
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="OAuth 401: token expired")

            with mock.patch.object(dispatch, "gh_json", return_value={"title": "t", "body": "b"}), \
                 mock.patch("subprocess.run", side_effect=fake_run):
                verdict, findings = dispatch.review(repo, 45, "gate report")
            self.assertEqual(verdict, "ERROR")
            self.assertIn("OAuth 401", findings)

            # A genuine REVISE (reviewer ran fine, just found problems) is unaffected.
            def fake_revise(cmd, cwd=None, capture_output=None, text=None):
                return subprocess.CompletedProcess(cmd, 0, stdout="some findings\nVERDICT: REVISE", stderr="")

            with mock.patch.object(dispatch, "gh_json", return_value={"title": "t", "body": "b"}), \
                 mock.patch("subprocess.run", side_effect=fake_revise):
                verdict, findings = dispatch.review(repo, 45, "gate report")
            self.assertEqual(verdict, "REVISE")

    def test_approve_pr_uses_resolved_pr_number_not_branch_name(self) -> None:
        """Confirmed live (ticket #45): `gh pr edit agent/{n}` silently no-ops
        from the dispatcher's cwd (always `main`, never the branch), so the
        factory-approved label never lands even though dispatch logs
        "done (approved)". Must resolve the PR number first, same as
        push_and_pr/merge_pass_locked already do, and log on failure."""
        from unittest import mock

        from agent_factory import dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            dispatch.configure(config.load(repo))
            calls = []

            def fake_run(cmd, cwd=None, check=True):
                calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            with mock.patch.object(dispatch, "gh_json", return_value=[{"number": 46}]), \
                 mock.patch.object(dispatch, "run", side_effect=fake_run):
                dispatch.approve_pr(45)
            edit_call = next(c for c in calls if c[:3] == ["gh", "pr", "edit"])
            self.assertEqual(edit_call[3], "46")
            self.assertNotIn("agent/45", edit_call)

            # No open PR found: logs instead of calling gh pr edit at all.
            with mock.patch.object(dispatch, "gh_json", return_value=[]), \
                 mock.patch.object(dispatch, "run", side_effect=fake_run) as run_mock:
                dispatch.approve_pr(99)
            run_mock.assert_not_called()

    def test_cost_pattern_sums_worker_log(self) -> None:
        from agent_factory import dispatch

        toml = "[dispatch]\ncost_pattern = 'Total cost:\\s*\\$([0-9.]+)'\nreview_rounds = 3\n"
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            self.assertEqual(cfg.review_rounds, 3)
            dispatch.configure(cfg)
            log = Path(d) / "w.log"
            log.write_text("... Total cost: $0.25\nmore\nTotal cost: $1.00\n")
            self.assertEqual(dispatch.log_cost(log), 1.25)


class TriageTest(unittest.TestCase):
    def test_call_llm_sends_bearer_header_only_when_key_configured(self) -> None:
        """A gated OpenAI-compatible endpoint (e.g. LiteLLM) needs an
        Authorization header -- without one, call_llm's request looks
        identical to a plain unauthenticated local-Ollama call and the
        endpoint 401s. The header must appear iff a key is configured, and
        never for the (still-supported) no-auth local-model case."""
        from unittest import mock

        from agent_factory import triage

        class FakeResponse:
            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *exc: object) -> bool:
                return False

            def read(self) -> bytes:
                return json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()

        captured: dict = {}

        def fake_urlopen(req: object, timeout: int | None = None) -> FakeResponse:
            captured["auth"] = req.get_header("Authorization")  # type: ignore[attr-defined]
            return FakeResponse()

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), '[triage]\nurl = "http://h/v1/chat/completions"\nkey = "sk-secret"\n')
            triage.configure(config.load(repo))
            with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
                self.assertEqual(triage.call_llm([{"role": "user", "content": "hi"}]), "ok")
            self.assertEqual(captured["auth"], "Bearer sk-secret")

        with tempfile.TemporaryDirectory() as d:
            repo2 = make_repo(Path(d), '[triage]\nurl = "http://h/v1/chat/completions"\n')
            triage.configure(config.load(repo2))
            with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
                triage.call_llm([{"role": "user", "content": "hi"}])
            self.assertIsNone(captured["auth"])


class ApplyConfigTest(unittest.TestCase):
    def test_apply_table_parses(self) -> None:
        toml = '[apply]\nenabled = true\ndir = "terraform/prod"\n[apply.env]\nAWS_PROFILE = "infra-apply"\n'
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            self.assertEqual((cfg.apply_enabled, cfg.apply_dir), (True, "terraform/prod"))
            self.assertEqual(cfg.apply_env, {"AWS_PROFILE": "infra-apply"})

    def test_apply_env_is_host_owned_dir_and_enabled_are_not(self) -> None:
        # Matches the dashboard.port split: [apply].env is credential-shaped
        # and host-owned (never in the committed repo file); enabled/dir are
        # policy about this repo and stay repo-owned.
        self.assertEqual(config.HOST_KEYS["apply"], ("env",))
        self.assertNotIn("apply", config.HOST_TABLES)


class ApplyTest(unittest.TestCase):
    def test_applied_tickets_from_events(self) -> None:
        from agent_factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            dispatch.record("applied", ticket=7, pr=1, ok=True)
            dispatch.record("claimed", ticket=8, title="x")
            self.assertEqual(apply.applied_tickets(), {7})

    def test_merged_tickets_parses_agent_branch_prs_only(self) -> None:
        from unittest import mock

        from agent_factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            prs = [
                {"number": 5, "headRefName": "agent/9", "mergeCommit": {"oid": "abc123"}},
                {"number": 6, "headRefName": "not-agent-branch", "mergeCommit": {"oid": "def456"}},
                {"number": 7, "headRefName": "agent/10", "mergeCommit": None},
            ]
            with mock.patch.object(dispatch, "gh_json", return_value=prs):
                tickets = apply.merged_tickets()
            self.assertEqual(tickets, [{"pr": 5, "ticket": 9, "commit": "abc123"}])

    def test_apply_fetches_main_before_scanning_merged_tickets(self) -> None:
        """touches_apply_dir() diffs {commit}~1..commit locally; if main
        hasn't independently fetched since the merge (`factory apply`
        invoked standalone, not right after a dispatch pass), the merge
        commit doesn't exist locally yet, the diff silently fails
        (check=False), and touches_apply_dir wrongly reports False.
        Confirmed live on ticket #45: a real apply-dir-touching merge was
        skipped as "doesn't touch ...; nothing to apply". The fetch must
        happen unconditionally, before merged_tickets/touches_apply_dir
        ever run -- not only inside fresh_checkout(), which runs after."""
        from unittest import mock

        from agent_factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            toml = "[apply]\nenabled = true\n"
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            calls: list[tuple] = []

            def fake_run(cmd, cwd=None, check=True):
                calls.append(("run", cmd))
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            def fake_gh_json(args):
                calls.append(("gh_json", args))
                return []

            with mock.patch.object(config, "load", return_value=cfg), \
                 mock.patch.object(dispatch, "run", side_effect=fake_run), \
                 mock.patch.object(dispatch, "gh_json", side_effect=fake_gh_json):
                self.assertEqual(apply.main([]), 0)

            fetch_idx = next(
                i for i, c in enumerate(calls) if c[0] == "run" and c[1][:3] == ["git", "fetch", "origin"]
            )
            prlist_idx = next(i for i, c in enumerate(calls) if c[0] == "gh_json")
            self.assertLess(fetch_idx, prlist_idx)

    def test_merge_stage_waits_for_human_review_when_apply_enabled(self) -> None:
        from unittest import mock

        from agent_factory import dispatch

        toml = "[apply]\nenabled = true\n"
        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml)
            cfg = config.load(repo)
            dispatch.configure(cfg)
            prs = [
                {
                    "number": 3,
                    "headRefName": "agent/9",
                    "isDraft": False,
                    "labels": [{"name": config.LABEL_APPROVED}],
                    "reviewDecision": "REVIEW_REQUIRED",
                }
            ]
            with mock.patch.object(dispatch, "gh_json", return_value=prs), \
                 mock.patch.object(dispatch, "pr_checks") as checks:
                dispatch.merge_pass_locked(dry_run=True)
            # No candidates survive the human-review gate, so the CI-check
            # stage (and anything past it) is never reached.
            checks.assert_not_called()

    def test_merge_stage_proceeds_when_apply_disabled_and_only_llm_approved(self) -> None:
        from unittest import mock

        from agent_factory import dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d))
            cfg = config.load(repo)
            self.assertFalse(cfg.apply_enabled)
            dispatch.configure(cfg)
            prs = [
                {
                    "number": 3,
                    "headRefName": "agent/9",
                    "isDraft": False,
                    "labels": [{"name": config.LABEL_APPROVED}],
                    "reviewDecision": "REVIEW_REQUIRED",
                }
            ]
            with mock.patch.object(dispatch, "gh_json", return_value=prs), \
                 mock.patch.object(dispatch, "pr_checks", return_value=[]) as checks:
                dispatch.merge_pass_locked(dry_run=True)
            # apply.enabled is unset for this (software) repo, so the LLM's
            # factory-approved label is still enough to reach the CI-check
            # stage even without a human review yet.
            checks.assert_called_once_with(3)

    def test_apply_one_posts_to_issue_and_pr_on_success(self) -> None:
        from unittest import mock

        from agent_factory import apply, dispatch, tf_plan_check

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), "[apply]\nenabled = true\n")
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)
            wt = Path(d) / "checkout"
            (wt / cfg.apply_dir).mkdir(parents=True, exist_ok=True)

            calls: list[list[str]] = []

            def fake_run(cmd, cwd=None, check=True):
                calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            apply_output = "Apply complete! Resources: 1 added, 0 changed, 0 destroyed."

            def fake_subproc_run(cmd, **kwargs):
                if cmd[:2] == ["terraform", "apply"]:
                    return subprocess.CompletedProcess(cmd, 0, stdout=apply_output, stderr="")
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            ticket = {"ticket": 42, "pr": 10, "commit": "c0ffee"}

            with mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "fresh_checkout", return_value=wt), \
                 mock.patch.object(tf_plan_check, "run_plan", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")), \
                 mock.patch.object(dispatch, "gh_json", return_value={"body": ""}), \
                 mock.patch.object(tf_plan_check, "show_json", return_value={}), \
                 mock.patch.object(tf_plan_check, "unexpected_changes", return_value=[]), \
                 mock.patch("subprocess.run", side_effect=fake_subproc_run), \
                 mock.patch.object(dispatch, "run", side_effect=fake_run), \
                 mock.patch.object(dispatch, "pr_comment", wraps=dispatch.pr_comment) as mock_pr_comment:
                apply.apply_one(ticket, dry_run=False)

            # Issue comment
            issue_calls = [c for c in calls if c[:3] == ["gh", "issue", "comment"]]
            self.assertEqual(len(issue_calls), 1)
            self.assertEqual(issue_calls[0][3], "42")
            summary = issue_calls[0][issue_calls[0].index("--body") + 1]
            self.assertIn("`terraform apply` succeeded for the merged change:", summary)
            self.assertIn(apply_output, summary)

            # PR comment via dispatch.pr_comment
            mock_pr_comment.assert_called_once_with(42, summary)

            # PR comment via gh pr comment call
            pr_calls = [c for c in calls if c[:3] == ["gh", "pr", "comment"]]
            self.assertEqual(len(pr_calls), 1)
            self.assertEqual(pr_calls[0][3], "agent/42")
            body_file = Path(pr_calls[0][pr_calls[0].index("--body-file") + 1])
            self.assertEqual(body_file.read_text().strip(), summary.strip())

    def test_apply_one_posts_to_issue_and_pr_on_failure(self) -> None:
        from unittest import mock

        from agent_factory import apply, dispatch, tf_plan_check

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), "[apply]\nenabled = true\n")
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)
            wt = Path(d) / "checkout"
            (wt / cfg.apply_dir).mkdir(parents=True, exist_ok=True)

            calls: list[list[str]] = []

            def fake_run(cmd, cwd=None, check=True):
                calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            error_output = "Error: provider failed to apply changes"

            def fake_subproc_run(cmd, **kwargs):
                if cmd[:2] == ["terraform", "apply"]:
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=error_output)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            ticket = {"ticket": 42, "pr": 10, "commit": "c0ffee"}

            with mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "fresh_checkout", return_value=wt), \
                 mock.patch.object(tf_plan_check, "run_plan", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")), \
                 mock.patch.object(dispatch, "gh_json", return_value={"body": ""}), \
                 mock.patch.object(tf_plan_check, "show_json", return_value={}), \
                 mock.patch.object(tf_plan_check, "unexpected_changes", return_value=[]), \
                 mock.patch("subprocess.run", side_effect=fake_subproc_run), \
                 mock.patch.object(dispatch, "run", side_effect=fake_run), \
                 mock.patch.object(dispatch, "pr_comment", wraps=dispatch.pr_comment) as mock_pr_comment:
                apply.apply_one(ticket, dry_run=False)

            # Issue comments: 1 for apply result (FAILED), 1 for escalation
            issue_calls = [c for c in calls if c[:3] == ["gh", "issue", "comment"]]
            self.assertEqual(len(issue_calls), 2)
            self.assertEqual(issue_calls[0][3], "42")
            summary = issue_calls[0][issue_calls[0].index("--body") + 1]
            self.assertIn("`terraform apply` FAILED for the merged change:", summary)
            self.assertIn(error_output, summary)

            self.assertEqual(issue_calls[1][3], "42")
            escalate_body = issue_calls[1][issue_calls[1].index("--body") + 1]
            self.assertEqual(escalate_body, "`factory apply` did not proceed: terraform apply failed.")

            # Both comments were also posted to the PR
            self.assertEqual(mock_pr_comment.call_count, 2)
            mock_pr_comment.assert_has_calls([
                mock.call(42, summary),
                mock.call(42, escalate_body),
            ])

            pr_calls = [c for c in calls if c[:3] == ["gh", "pr", "comment"]]
            self.assertEqual(len(pr_calls), 2)
            self.assertEqual(pr_calls[0][3], "agent/42")
            self.assertEqual(pr_calls[1][3], "agent/42")

    def test_apply_escalate_posts_to_issue_and_pr_when_called_directly(self) -> None:
        from unittest import mock

        from agent_factory import apply, dispatch

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), "[apply]\nenabled = true\n")
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)

            calls: list[list[str]] = []

            def fake_run(cmd, cwd=None, check=True):
                calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            with mock.patch.object(dispatch, "run", side_effect=fake_run), \
                 mock.patch.object(dispatch, "pr_comment", wraps=dispatch.pr_comment) as mock_pr_comment:
                apply.apply_escalate(42, 10, "fresh plan failed: syntax error")

            expected_body = "`factory apply` did not proceed: fresh plan failed: syntax error."

            issue_calls = [c for c in calls if c[:3] == ["gh", "issue", "comment"]]
            self.assertEqual(len(issue_calls), 1)
            self.assertEqual(issue_calls[0][3], "42")
            self.assertEqual(issue_calls[0][issue_calls[0].index("--body") + 1], expected_body)

            mock_pr_comment.assert_called_once_with(42, expected_body)

            pr_calls = [c for c in calls if c[:3] == ["gh", "pr", "comment"]]
            self.assertEqual(len(pr_calls), 1)
            self.assertEqual(pr_calls[0][3], "agent/42")
            body_file = Path(pr_calls[0][pr_calls[0].index("--body-file") + 1])
            self.assertEqual(body_file.read_text().strip(), expected_body.strip())

    def test_apply_one_posts_to_issue_and_pr_on_fresh_plan_failure(self) -> None:
        from unittest import mock

        from agent_factory import apply, dispatch, tf_plan_check

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), "[apply]\nenabled = true\n")
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)
            wt = Path(d) / "checkout"
            (wt / cfg.apply_dir).mkdir(parents=True, exist_ok=True)

            calls: list[list[str]] = []

            def fake_run(cmd, cwd=None, check=True):
                calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            ticket = {"ticket": 42, "pr": 10, "commit": "c0ffee"}
            plan_proc = subprocess.CompletedProcess([], 1, stdout="Error: invalid configuration", stderr="")

            with mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "fresh_checkout", return_value=wt), \
                 mock.patch.object(tf_plan_check, "run_plan", return_value=plan_proc), \
                 mock.patch.object(dispatch, "run", side_effect=fake_run), \
                 mock.patch.object(dispatch, "pr_comment", wraps=dispatch.pr_comment) as mock_pr_comment, \
                 mock.patch("subprocess.run") as mock_subproc_run:
                apply.apply_one(ticket, dry_run=False)

            # terraform apply should NOT have been reached
            mock_subproc_run.assert_not_called()

            # Escalation should have been posted to both issue and PR
            issue_calls = [c for c in calls if c[:3] == ["gh", "issue", "comment"]]
            self.assertEqual(len(issue_calls), 1)
            self.assertIn("fresh terraform plan failed", issue_calls[0][issue_calls[0].index("--body") + 1])

            self.assertEqual(mock_pr_comment.call_count, 1)
            self.assertIn("fresh terraform plan failed", mock_pr_comment.call_args[0][1])

            pr_calls = [c for c in calls if c[:3] == ["gh", "pr", "comment"]]
            self.assertEqual(len(pr_calls), 1)

    def test_apply_one_posts_to_issue_and_pr_on_unexpected_destroy(self) -> None:
        from unittest import mock

        from agent_factory import apply, dispatch, tf_plan_check

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), "[apply]\nenabled = true\n")
            cfg = config.load(repo)
            dispatch.configure(cfg)
            apply.configure(cfg)
            cfg.factory.mkdir(parents=True, exist_ok=True)
            wt = Path(d) / "checkout"
            (wt / cfg.apply_dir).mkdir(parents=True, exist_ok=True)

            calls: list[list[str]] = []

            def fake_run(cmd, cwd=None, check=True):
                calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            ticket = {"ticket": 42, "pr": 10, "commit": "c0ffee"}

            with mock.patch.object(apply, "touches_apply_dir", return_value=True), \
                 mock.patch.object(apply, "fresh_checkout", return_value=wt), \
                 mock.patch.object(tf_plan_check, "run_plan", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr="")), \
                 mock.patch.object(dispatch, "gh_json", return_value={"body": ""}), \
                 mock.patch.object(tf_plan_check, "show_json", return_value={}), \
                 mock.patch.object(tf_plan_check, "unexpected_changes", return_value=[("aws_s3_bucket.logs", ["delete"])]), \
                 mock.patch.object(dispatch, "run", side_effect=fake_run), \
                 mock.patch.object(dispatch, "pr_comment", wraps=dispatch.pr_comment) as mock_pr_comment, \
                 mock.patch("subprocess.run") as mock_subproc_run:
                apply.apply_one(ticket, dry_run=False)

            # terraform apply should NOT have been reached
            mock_subproc_run.assert_not_called()

            # Escalation should have been posted to both issue and PR
            issue_calls = [c for c in calls if c[:3] == ["gh", "issue", "comment"]]
            self.assertEqual(len(issue_calls), 1)
            self.assertIn("fresh plan destroys/replaces aws_s3_bucket.logs (delete)", issue_calls[0][issue_calls[0].index("--body") + 1])

            self.assertEqual(mock_pr_comment.call_count, 1)
            self.assertIn("fresh plan destroys/replaces aws_s3_bucket.logs (delete)", mock_pr_comment.call_args[0][1])

            pr_calls = [c for c in calls if c[:3] == ["gh", "pr", "comment"]]
            self.assertEqual(len(pr_calls), 1)


class TfPlanCheckTest(unittest.TestCase):
    """Pure-function checks against a canned `terraform show -json` shape;
    no terraform binary needed."""

    def test_run_plan_passes_env_to_both_subprocess_calls(self) -> None:
        """apply_env()'s credentials (e.g. OP_SERVICE_ACCOUNT_TOKEN) were
        computed but never actually passed to the plan subprocess -- run_plan
        had no env parameter at all, always inheriting the calling process's
        plain environment. Confirmed live: factory apply's fresh re-plan
        401'd against 1Password's interactive desktop-app flow because of
        this, even with apply_env() correctly populated. env=None (the
        gate's own CLI use, which already has install.env baked into its
        process by the dispatcher's systemd unit) must keep inheriting."""
        from unittest import mock

        from agent_factory import tf_plan_check

        calls = []

        def fake_run(cmd, cwd=None, capture_output=None, text=None, env=None):
            calls.append(env)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with mock.patch("subprocess.run", side_effect=fake_run):
            tf_plan_check.run_plan(Path("/tmp"), Path("/tmp/plan"), env={"FAKE": "1"})
        self.assertEqual(calls, [{"FAKE": "1"}, {"FAKE": "1"}])

        calls.clear()
        with mock.patch("subprocess.run", side_effect=fake_run):
            tf_plan_check.run_plan(Path("/tmp"), Path("/tmp/plan"))
        self.assertEqual(calls, [None, None])

    CLEAN_PLAN = {
        "resource_changes": [
            {"address": "aws_instance.foo", "change": {"actions": ["no-op"]}},
            {"address": "aws_s3_bucket.logs", "change": {"actions": ["create"]}},
        ]
    }
    DESTRUCTIVE_PLAN = {
        "resource_changes": [
            {"address": "aws_instance.foo", "change": {"actions": ["no-op"]}},
            {"address": "aws_instance.bar", "change": {"actions": ["delete", "create"]}},
            {"address": "aws_db_instance.main", "change": {"actions": ["delete"]}},
        ]
    }

    def test_clean_plan_has_no_destructive_changes(self) -> None:
        from agent_factory import tf_plan_check

        self.assertEqual(tf_plan_check.destructive_changes(self.CLEAN_PLAN), [])
        self.assertEqual(tf_plan_check.unexpected_changes(self.CLEAN_PLAN, ""), [])

    def test_destructive_plan_flags_delete_and_replace(self) -> None:
        from agent_factory import tf_plan_check

        changes = tf_plan_check.destructive_changes(self.DESTRUCTIVE_PLAN)
        self.assertEqual(
            {addr for addr, _ in changes}, {"aws_instance.bar", "aws_db_instance.main"}
        )

    def test_allowed_destroy_line_exempts_one_address(self) -> None:
        from agent_factory import tf_plan_check

        ticket = "Upgrade the DB.\n\nAllowedDestroy: aws_db_instance.main\n"
        unexpected = tf_plan_check.unexpected_changes(self.DESTRUCTIVE_PLAN, ticket)
        self.assertEqual([addr for addr, _ in unexpected], ["aws_instance.bar"])

    def test_no_allow_list_flags_everything_destructive(self) -> None:
        from agent_factory import tf_plan_check

        unexpected = tf_plan_check.unexpected_changes(self.DESTRUCTIVE_PLAN, "no allow lines here")
        self.assertEqual(
            {addr for addr, _ in unexpected}, {"aws_instance.bar", "aws_db_instance.main"}
        )

    def test_plan_out_directory_created_under_dir_not_invocation_cwd(self) -> None:
        """--plan-out is a path relative to --dir (that's what run_plan's
        subprocess, cwd=--dir, actually resolves it against), so the mkdir
        must create it there too -- not relative to wherever the check
        itself happens to be invoked from (the worktree root)."""
        from unittest import mock

        from agent_factory import tf_plan_check

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d).resolve()
            tf_root = tmp / "terraform" / "homelab-collectors"
            tf_root.mkdir(parents=True)
            invocation_cwd = tmp / "worktree-root"
            invocation_cwd.mkdir()

            original_cwd = Path.cwd()
            os.chdir(invocation_cwd)
            self.addCleanup(os.chdir, original_cwd)

            clean_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
            with mock.patch.object(tf_plan_check, "run_plan", return_value=clean_proc) as run_plan, \
                 mock.patch.object(tf_plan_check, "show_json", return_value=self.CLEAN_PLAN):
                rc = tf_plan_check.main(
                    ["--dir", str(tf_root), "--plan-out", ".factory/tfplan"]
                )

            self.assertEqual(rc, 0)
            self.assertTrue((tf_root / ".factory").is_dir())
            self.assertFalse((invocation_cwd / ".factory").exists())
            run_plan.assert_called_once_with(Path(str(tf_root)), Path(".factory/tfplan"))


class VerifySecretsTest(unittest.TestCase):
    def test_parse_environment_lines_ignores_other_unit_content(self) -> None:
        from agent_factory import verify_secrets

        unit_text = (
            "[Unit]\nDescription=agent-factory dispatcher for acme/widgets (one pass)\n\n"
            "[Service]\nType=oneshot\nWorkingDirectory=/home/t/widgets\n"
            "Environment=PATH=/usr/bin:/bin\n"
            "Environment=GH_TOKEN=ghp_abc123\n"
            "Environment=OP_SERVICE_ACCOUNT_TOKEN=ops_xyz==\n"
            "ExecStart=/usr/bin/python3 -m agent_factory dispatch\n"
        )
        self.assertEqual(
            verify_secrets.parse_environment_lines(unit_text),
            {"PATH": "/usr/bin:/bin", "GH_TOKEN": "ghp_abc123", "OP_SERVICE_ACCOUNT_TOKEN": "ops_xyz=="},
        )

    def test_sync_rows_flags_stale_and_missing_against_installed_units(self) -> None:
        """A key whose host-config value has moved on from what's baked into a unit reads STALE
        (the SHA-182 / 2026-09-13 rotation shape); a unit `systemctl` can't find reads not installed."""
        from agent_factory import verify_secrets

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml='[install]\nenv = { GH_TOKEN = "new-token", FOO = "bar" }\n')
            cfg = config.load(repo)

        installed = {
            f"{cfg.unit}.service": {"GH_TOKEN": "new-token", "FOO": "bar"},  # in sync
            f"{cfg.unit}-triage.service": {"GH_TOKEN": "old-token", "FOO": "bar"},  # stale
            f"{cfg.unit}-dashboard.service": None,  # never installed
        }
        rows = verify_secrets.sync_rows(cfg, unit_env_fn=lambda unit: installed[unit])

        by_unit_key = {(u, k): s for u, k, s in rows}
        self.assertEqual(by_unit_key[(f"{cfg.unit}.service", "GH_TOKEN")], "in sync")
        self.assertEqual(by_unit_key[(f"{cfg.unit}.service", "FOO")], "in sync")
        self.assertEqual(by_unit_key[(f"{cfg.unit}-triage.service", "GH_TOKEN")], "STALE -- rerun `factory install`")
        self.assertEqual(by_unit_key[(f"{cfg.unit}-dashboard.service", "*")], "not installed")

    def test_main_exits_nonzero_when_any_unit_is_stale(self) -> None:
        from unittest import mock

        from agent_factory import verify_secrets

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), toml='[install]\nenv = { GH_TOKEN = "new-token" }\n')
            original_cwd = Path.cwd()
            os.chdir(repo)
            self.addCleanup(os.chdir, original_cwd)

            def fake_unit_env(unit: str) -> dict[str, str] | None:
                return {"GH_TOKEN": "old-token"}

            with mock.patch.object(verify_secrets, "unit_env", side_effect=fake_unit_env):
                rc = verify_secrets.main([])
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
