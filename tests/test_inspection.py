"""Metadata verification must not leak credentials or mutate observed state."""
from contextlib import redirect_stdout
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from factory import config, deploy, inspection, verify_secrets

SECRET = "credential-sentinel-do-not-render"


class InspectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = config.Config(self.root, "example/repo")
        self.cfg.install = dict(config.DEFAULT_INSTALL, env={"GH_TOKEN": "read-token", "PATH": "/usr/bin"})
        self.cfg.apply_env = {"GH_TOKEN": SECRET, "OP_SERVICE_ACCOUNT_TOKEN": SECRET}
        self.cfg.targets = {"default": config.DeployTarget(name="default", dir="terraform", enabled=True)}

    def test_scoped_live_checks_do_not_export_or_render_values(self):
        seen = []
        def check(token):
            seen.append(token)
            return "FAILED: " + token
        original = dict(os.environ)
        with patch.dict(verify_secrets.LIVE_CHECKS, {"GH_TOKEN": check, "OP_SERVICE_ACCOUNT_TOKEN": check}, clear=True):
            rows = verify_secrets.credential_rows(self.cfg, "all", True)
        self.assertEqual(seen, ["read-token", SECRET, SECRET])
        self.assertNotIn(SECRET, json.dumps(rows))
        self.assertEqual(original, dict(os.environ))
        self.assertTrue(all(r["status"] == "invalid" for r in rows if r["key"] != "PATH"))

    def test_live_checker_timeout_is_unknown_without_raw_exception(self):
        with patch.dict(verify_secrets.LIVE_CHECKS, {"GH_TOKEN": lambda _: (_ for _ in ()).throw(OSError(SECRET))}, clear=True):
            rows = verify_secrets.credential_rows(self.cfg, "apply", True)
        self.assertEqual(rows[0]["status"], "unavailable")
        self.assertNotIn(SECRET, json.dumps(rows))

    def test_op_rejection_does_not_print_provider_stderr(self):
        with patch.object(verify_secrets.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", SECRET)):
            self.assertNotIn(SECRET, verify_secrets.check_op_token(SECRET))

    def test_apply_scope_does_not_require_dispatcher_and_uses_only_apply_token(self):
        output = io.StringIO()
        with patch.object(config, "load", return_value=self.cfg), patch.object(verify_secrets, "sync_rows") as sync, \
             patch.dict(verify_secrets.LIVE_CHECKS, {"GH_TOKEN": lambda _: "OK", "OP_SERVICE_ACCOUNT_TOKEN": lambda _: "OK"}, clear=True), \
             redirect_stdout(output):
            code = verify_secrets.main(["--scope", "apply", "--json", "--live"])
        self.assertEqual(code, 0)
        sync.assert_not_called()
        self.assertNotIn(SECRET, output.getvalue())

    def test_boundary_allows_distinct_role_tokens_but_detects_apply_value(self):
        safe = inspection.boundary(self.cfg, {"GH_TOKEN": "read-token", "PATH": "/usr/bin"})
        self.assertFalse(any(r["status"] == "leaked" for r in safe))
        bad = inspection.boundary(self.cfg, {"GH_TOKEN": SECRET, "OP_SERVICE_ACCOUNT_TOKEN": SECRET})
        self.assertEqual(sum(r["status"] == "leaked" for r in bad), 2)
        self.assertNotIn(SECRET, json.dumps(bad))

    def test_empty_apply_selector_is_not_a_leaked_credential(self):
        self.cfg.apply_env = {"TF_VAR_onepassword_account": ""}
        self.cfg.install["env"]["TF_VAR_onepassword_account"] = ""
        rows = inspection.boundary(self.cfg, self.cfg.install["env"])
        self.assertEqual([r["status"] for r in rows if r["scope"] == "apply"], ["isolated"])
        del self.cfg.install["env"]["TF_VAR_onepassword_account"]
        rows = inspection.boundary(self.cfg, {"TF_VAR_onepassword_account": "unexpected"})
        self.assertEqual([r["status"] for r in rows if r["scope"] == "apply"], ["leaked"])

    def test_empty_selector_verdict_does_not_depend_on_live(self):
        self.cfg.install["env"]["TF_VAR_onepassword_account"] = ""
        self.cfg.apply_env = {"OP_SERVICE_ACCOUNT_TOKEN": SECRET, "TF_VAR_onepassword_account": ""}
        checks = {"GH_TOKEN": lambda _: "OK", "OP_SERVICE_ACCOUNT_TOKEN": lambda _: "OK"}
        for live in ([], ["--live"]):
            with self.subTest(live=bool(live)), patch.object(config, "load", return_value=self.cfg), \
                 patch.object(verify_secrets, "sync_rows", return_value=[]), \
                 patch.dict(verify_secrets.LIVE_CHECKS, checks, clear=True), redirect_stdout(io.StringIO()) as out:
                code = verify_secrets.main(["--scope", "all", "--json", *live])
                report = json.loads(out.getvalue())
                self.assertEqual(code, 0)
                self.assertTrue(report["ok"])
                self.assertEqual({r["status"] for r in report["credentials"] if r["key"] == "TF_VAR_onepassword_account"},
                                 {"empty_allowed"})

    def test_empty_known_credential_fails_with_and_without_live(self):
        self.cfg.install["env"]["GH_TOKEN"] = ""
        with patch.dict(verify_secrets.LIVE_CHECKS, {"GH_TOKEN": lambda _: "OK", "OP_SERVICE_ACCOUNT_TOKEN": lambda _: "OK"}, clear=True):
            for live in (False, True):
                with self.subTest(live=live):
                    rows = verify_secrets.credential_rows(self.cfg, "install", live)
                    self.assertEqual([r["status"] for r in rows if r["key"] == "GH_TOKEN"], ["empty"])

    def test_required_dashboard_missing_fails(self):
        self.cfg.install["dashboard"] = True
        rows = [(self.cfg.unit + '.service', 'GH_TOKEN', 'in sync'),
                (self.cfg.unit + '-dashboard.service', '*', 'not installed')]
        with patch.object(config, "load", return_value=self.cfg), patch.object(verify_secrets, "sync_rows", return_value=rows), redirect_stdout(io.StringIO()):
            self.assertEqual(verify_secrets.main(["--json"]), 1)

    def test_lock_probe_identifies_held_lock_without_changing_file(self):
        path = self.root / "apply.lock"
        path.write_bytes(b"preserved")
        before = path.stat().st_mtime_ns
        with path.open('rb') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(inspection.lock_snapshot(path)["status"], "held")
        self.assertEqual(inspection.lock_snapshot(path)["status"], "free")
        self.assertEqual(path.read_bytes(), b"preserved")
        self.assertEqual(path.stat().st_mtime_ns, before)
        absent = self.root / 'absent.lock'
        self.assertEqual(inspection.lock_snapshot(absent)["status"], "absent")
        self.assertFalse(absent.exists())

    def test_lock_probe_rejects_symlinks_and_never_creates_directories(self):
        target = self.root / 'target'
        target.write_text('data')
        link = self.root / 'link.lock'
        link.symlink_to(target)
        self.assertEqual(inspection.lock_snapshot(link)["status"], 'unavailable')
        override = self.root / 'not-created'
        with patch.dict(os.environ, {'AGENT_FACTORY_LOCK_DIR': str(override)}):
            self.assertEqual(deploy.preferred_lock_dir(), override)
            inspection.locks(self.cfg)
        self.assertFalse(override.exists())
        self.assertFalse(self.cfg.factory.exists())

    def test_mixed_ledger_reports_recovery_without_output_or_writes(self):
        path = self.cfg.factory / 'events.jsonl'
        run = deploy.DeployRun(run_id='r1', target='default', commit='a'*40, ticket=1,
                              attempt=1, status=deploy.DeployStatus.RUNNING,
                              started_at='2026-09-21T00:00:00Z', output=SECRET)
        deploy.record_deploy_run(run, events_path=path)
        before = path.read_bytes()
        report = inspection.deployment_snapshot(self.cfg)
        self.assertEqual(report['status'], 'observed')
        self.assertEqual(report['targets'][0]['unresolved_runs'], ['r1'])
        self.assertNotIn(SECRET, json.dumps(report))
        self.assertEqual(path.read_bytes(), before)

    def test_missing_partial_and_invalid_ledger_are_distinguished(self):
        self.assertEqual(inspection.deployment_snapshot(self.cfg)['status'], 'absent')
        path = self.cfg.factory / 'events.jsonl'
        path.parent.mkdir()
        for data in (b'{"event":', b'{"event":"deploy_run"}\n'):
            path.write_bytes(data)
            self.assertEqual(inspection.deployment_snapshot(self.cfg)['status'], 'unavailable')
            self.assertEqual(path.read_bytes(), data)

    def test_unit_environment_files_are_unknown_not_guessed(self):
        text = '\n'.join(['LoadState=loaded', 'ActiveState=inactive', 'MainPID=0',
                          'Environment=GH_TOKEN=read-token', 'EnvironmentFiles=/hidden',
                          'ExecStart={ path=/python ; argv[]=/python -m factory ; }'])
        with patch.object(inspection, 'command', return_value=text), patch.object(inspection, 'runtime_probe') as probe:
            report = inspection.unit_snapshot(self.cfg, self.cfg.unit+'.service', {})
        self.assertEqual(report['runtime']['status'], 'unavailable')
        probe.assert_not_called()

    def test_missing_systemd_and_probe_failures_never_render_stderr(self):
        with patch.object(inspection, 'command', side_effect=inspection.Unavailable(SECRET)):
            result = inspection.inspect(self.cfg)
        self.assertFalse(result['ok'])
        self.assertEqual(result['configured_targets'][0]['target'], 'default')
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertFalse(self.cfg.factory.exists())

    def test_assignments_handle_spaces_and_equals(self):
        self.assertEqual(inspection.assignments('"TOKEN=a b==" PATH=/bin'), {'TOKEN': 'a b==', 'PATH': '/bin'})
        with self.assertRaises(inspection.Unavailable):
            inspection.assignments('"broken')

    def test_candidate_preview_reads_only_and_excludes_terminal(self):
        prs = [{'number': 2, 'headRefName': 'agent/8', 'mergeCommit': {'oid': 'a'*40}},
               {'number': 3, 'headRefName': 'agent/9', 'mergeCommit': {'oid': 'b'*40}}]
        ledger = {'status': 'observed', 'targets': [{'target': 'default', 'terminal_tickets': [8]}]}
        with patch.object(inspection, 'command', side_effect=[json.dumps(prs), 'terraform/main.tf\n']) as call:
            result = inspection.candidate_snapshot(self.cfg, ledger)
        self.assertEqual([r['ticket'] for r in result['candidates']], [9])
        self.assertEqual(result['authorization'], 'not_evaluated')
        self.assertFalse(result['git_fetched'])
        self.assertNotIn('fetch', str(call.call_args_list))
        self.assertFalse(self.cfg.factory.exists())

    def test_candidate_missing_git_objects_is_unavailable(self):
        prs = [{'number': 3, 'headRefName': 'agent/9', 'mergeCommit': {'oid': 'b'*40}}]
        with patch.object(inspection, 'command', side_effect=[json.dumps(prs), inspection.Unavailable('missing')]):
            report = inspection.candidate_snapshot(self.cfg, {'status': 'absent', 'targets': []})
        self.assertEqual(report['status'], 'unavailable')

    def test_process_identity_failure_is_not_success(self):
        with patch.object(inspection, 'read', side_effect=inspection.Unavailable('missing')):
            self.assertEqual(inspection.process_snapshot(123, self.cfg, '/python')['status'], 'unavailable')

    def test_cli_configuration_exception_is_sanitized(self):
        output = io.StringIO()
        with patch.object(config, 'load', side_effect=config.ConfigError(SECRET)), redirect_stdout(output):
            code = inspection.main(['--json'])
        self.assertEqual(code, 1)
        self.assertNotIn(SECRET, output.getvalue())

    def test_loaded_unit_quoted_environment_is_compared_without_rendering(self):
        output = 'LoadState=loaded\nEnvironment="TOKEN=a b==" GH_TOKEN=read-token\n'
        with patch.object(verify_secrets.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output, '')):
            self.assertEqual(verify_secrets.unit_env('factory-example.service'), {'TOKEN': 'a b==', 'GH_TOKEN': 'read-token'})

    def test_unit_environment_read_error_is_not_absence(self):
        with patch.object(verify_secrets.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', SECRET)):
            with self.assertRaises(OSError) as caught:
                verify_secrets.unit_env('factory-example.service')
        self.assertNotIn(SECRET, str(caught.exception))

    def test_process_environment_and_identity_are_observed_without_argv(self):
        fake_stat = b'123 (python worker) ' + b' '.join([b'1'] * 20)
        env = b'GH_TOKEN=read-token\0PATH=/usr/bin\0OP_SERVICE_ACCOUNT_TOKEN=' + SECRET.encode() + b'\0'
        with patch.object(inspection, 'read', side_effect=[fake_stat, b'/expected/python\0-m\0factory\0', env, fake_stat]), \
             patch.object(inspection.os, 'readlink', return_value='/expected/python'):
            result = inspection.process_snapshot(123, self.cfg, '/expected/python')
        self.assertEqual(result['status'], 'observed')
        self.assertTrue(result['invocation_matches'])
        self.assertTrue(any(r['status'] == 'leaked' for r in result['environment']))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn('argv', result)

    def test_process_reuse_during_snapshot_is_unavailable(self):
        before = b'123 (worker) ' + b' '.join([b'1'] * 20)
        after = b'123 (worker) ' + b' '.join([b'2'] * 20)
        with patch.object(inspection, 'read', side_effect=[before, b'/python\0', b'', after]), \
             patch.object(inspection.os, 'readlink', return_value='/python'):
            result = inspection.process_snapshot(123, self.cfg, '/python')
        self.assertEqual(result['status'], 'unavailable')

    def test_gate_interpreter_mismatch_is_explicit(self):
        text = '\n'.join(['LoadState=loaded', 'ActiveState=inactive', 'MainPID=0',
                          'Environment=GH_TOKEN=read-token PATH=/usr/bin',
                          f'ExecStart={{ path={sys.executable} ; argv[]={sys.executable} -m factory ; }}'])
        service = {'status': 'observed', 'prefix': '/service', 'modules': {}}
        gate = {'status': 'observed', 'prefix': '/wrong-python', 'modules': {}}
        with patch.object(inspection, 'command', return_value=text), \
             patch.object(inspection, 'runtime_probe', side_effect=[service, gate]):
            result = inspection.unit_snapshot(self.cfg, self.cfg.unit+'.service', {}, self.root)
        self.assertFalse(result['gate_matches_service'])
        self.assertEqual(result['gate_cwd'], str(self.root))

    def test_every_repeated_execstart_stage_is_inspected(self):
        # Unified unit: `ExecStart=-<python> -m factory triage` then dispatch;
        # systemctl show prints one ExecStart= line per command.
        def unit(triage_python):
            return '\n'.join(['LoadState=loaded', 'ActiveState=inactive', 'MainPID=0',
                              'Environment=GH_TOKEN=read-token PATH=/usr/bin',
                              f'ExecStart={{ path={triage_python} ; argv[]={triage_python} -m factory triage ; ignore_errors=yes ; }}',
                              f'ExecStart={{ path={sys.executable} ; argv[]={sys.executable} -m factory dispatch ; ignore_errors=no ; }}'])
        self.cfg.install["python"] = sys.executable
        with patch.object(inspection, 'command', return_value=unit('/old/python')), \
             patch.object(inspection, 'runtime_probe', return_value={'status': 'observed'}):
            stale = inspection.unit_snapshot(self.cfg, self.cfg.unit+'.service', {}, self.root)
        self.assertEqual(stale['configured_executables'], ['/old/python', sys.executable])
        self.assertFalse(stale['configured_interpreter_matches'])
        with patch.object(inspection, 'command', return_value=unit(sys.executable)), \
             patch.object(inspection, 'runtime_probe', return_value={'status': 'observed'}):
            current = inspection.unit_snapshot(self.cfg, self.cfg.unit+'.service', {}, self.root)
        self.assertEqual(current['configured_executables'], [sys.executable, sys.executable])
        self.assertTrue(current['configured_interpreter_matches'])

    def test_kernel_lock_on_journal_returns_unknown_instead_of_waiting(self):
        path = self.cfg.factory / 'events.jsonl'
        path.parent.mkdir()
        path.write_text('')
        with path.open('rb') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = inspection.deployment_snapshot(self.cfg)
        self.assertEqual(result['status'], 'unavailable')

    def test_candidate_preview_strips_inherited_apply_environment(self):
        with patch.dict(os.environ, {'OP_SERVICE_ACCOUNT_TOKEN': SECRET}), \
             patch.object(inspection, 'command', return_value='[]') as call:
            inspection.candidate_snapshot(self.cfg, {'status': 'absent', 'targets': []})
        self.assertNotIn('OP_SERVICE_ACCOUNT_TOKEN', call.call_args.kwargs['env'])
        self.assertEqual(call.call_args.kwargs['env']['GH_TOKEN'], 'read-token')


if __name__ == '__main__':
    unittest.main()
