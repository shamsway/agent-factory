"""Deployment history contracts, independent of GitHub ticket visibility."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from factory import artifacts, deploy, deployment_view


def row(rid, status, **kw):
    return dict(event='deploy_run', run_id=rid, target='default', commit='a'*40,
                ticket=1, attempt=1, status=status, started_at='2026-10-01T00:00:00Z', **kw)


class DeploymentViewTest(unittest.TestCase):
    def test_states_and_legacy_output_are_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = [row('pending', 'pending'), {**row('failed', 'failed'), 'ticket': 2, 'output': 'unknown old secret'},
                    {**row('success', 'succeeded', duration_sec=0), 'ticket': 3},
                    {**row('superseded', 'failed'), 'ticket': 4},
                    {'event': 'deploy_superseded', 'run_id': 'superseded', 'target': 'default'}]
            data = deployment_view.project(Path(tmp), rows)
            self.assertNotIn('unknown old secret', json.dumps(data))
            self.assertEqual({r['status'] for r in data['runs']}, {'pending','failed','succeeded','superseded'})
            self.assertEqual(data['metrics']['success_denominator'], 3)
            self.assertEqual(data['metrics']['duration_denominator'], 1)
            self.assertTrue(next(r for r in data['runs'] if r['run_id']=='failed')['unresolved'])

    def test_running_phase_and_interruption_and_replay_health(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = [row('run', 'running'), row('run', 'running', phase='verifying')]
            with mock.patch.object(deployment_view.dispatch, 'lock_held', return_value=True):
                self.assertEqual(deployment_view.project(Path(tmp), rows)['runs'][0]['status'], 'verifying')
            with mock.patch.object(deployment_view.dispatch, 'lock_held', return_value=False):
                self.assertEqual(deployment_view.project(Path(tmp), rows)['runs'][0]['status'], 'interrupted')
            rows.append(row('run','succeeded',verification={'verdict':'healthy'},duration_sec=0))
            state = deploy.replay_rows(rows)['default']
            self.assertEqual(state.runs[0].verification, {'verdict':'healthy'})

    def test_unresolved_runs_survive_history_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = [{**row('failed','failed'), 'ticket': 2}]
            rows += [row(f'r{i}','succeeded') for i in range(250)]
            data = deployment_view.project(Path(tmp),rows)
            self.assertEqual(len(data['runs']),201)
            self.assertTrue(data['history']['truncated'])
            self.assertIn('failed',[r['run_id'] for r in data['runs']])

    def test_journals_are_private_including_rotated_segments(self):
        for name in ['events.jsonl','events.jsonl.1.gz','events.jsonl.8.gz']:
            self.assertTrue(artifacts.is_private_path(name))

    def test_queue_timing_has_explicit_denominator(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = [row('timed', 'succeeded', queued_at='2026-09-30T23:59:00Z'),
                    row('legacy', 'succeeded')]
            data = deployment_view.project(Path(tmp), rows)
            self.assertEqual(data['metrics']['mean_queue_sec'], 60)
            self.assertEqual(data['metrics']['queue_denominator'], 1)

    def test_executing_run_is_visible_while_target_lock_is_owned(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(deployment_view.dispatch, 'lock_held', return_value=True):
            data = deployment_view.project(Path(tmp), [row('run', 'running')])
            self.assertEqual(data['runs'][0]['status'], 'executing')

    def test_compatibility_success_cannot_turn_skipped_run_into_success(self):
        rows = [row('skip', 'skipped'), {'event': 'applied', 'run_id': 'skip', 'ticket': 1, 'ok': True}]
        state = deploy.replay_rows(rows)['default']
        self.assertEqual(state.runs[0].status, deploy.DeployStatus.SKIPPED)

    def test_verified_manifest_summary_is_visible_but_old_raw_output_is_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            run=deploy.DeployRun.from_dict(row('safe','succeeded'))
            run.output='sanitized result'
            artifacts.write_run_artifacts(root,run)
            data=deployment_view.project(root,[row('safe','succeeded',output='unknown old secret')])
            self.assertEqual(data['runs'][0]['result']['output_tail'],'sanitized result')
            self.assertNotIn('unknown old secret',json.dumps(data))


class HistoryAvailabilityTest(unittest.TestCase):
    def test_optional_projection_failure_is_isolated(self):
        with mock.patch.object(
            deployment_view, "project", side_effect=PermissionError("lock")
        ), self.assertLogs("factory.deployment_view", level="WARNING"):
            self.assertIsNone(deployment_view.safe_project(Path("."), []))

    def test_missing_start_timestamp_does_not_break_history(self):
        event = row("missing-start", "succeeded")
        event["started_at"] = None
        event["queued_at"] = "2026-10-03T00:00:00Z"
        with tempfile.TemporaryDirectory() as tmp:
            data = deployment_view.project(Path(tmp), [event])
        self.assertIsNone(data["runs"][0]["queue_sec"])

    def test_target_lock_retries_a_transient_observer(self):
        import errno

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(
                deploy.fcntl,
                "flock",
                side_effect=[BlockingIOError(errno.EAGAIN, "busy"), None],
            ):
                acquired, handle = deploy.acquire_target_lock(Path(tmp), "default")
            self.assertTrue(acquired)
            handle.close()

    def test_target_lock_retry_is_bounded(self):
        import errno

        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(
                    deploy.fcntl,
                    "flock",
                    side_effect=BlockingIOError(errno.EAGAIN, "busy"),
                ),
                mock.patch.object(deploy.time, "monotonic", side_effect=[0, 1]),
            ):
                acquired, handle = deploy.acquire_target_lock(Path(tmp), "default")
            self.assertFalse(acquired)
            self.assertIsNone(handle)


if __name__ == "__main__":
    unittest.main()


class JournalRowsTest(unittest.TestCase):
    """Deployment history comes from the whole journal, not the dashboard's
    bounded tail window, and refreshes parse only what was appended."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.factory = Path(self.tmp.name)
        self.path = self.factory / 'events.jsonl'
        deployment_view._journal_cache.clear()
        self.addCleanup(deployment_view._journal_cache.clear)

    def write(self, *rows):
        with self.path.open('ab') as handle:
            for item in rows:
                handle.write(json.dumps(item).encode() + b'\n')

    def test_deploys_older_than_the_bounded_window_are_projected(self):
        old = {**row('deploy-default-aaaaaaaa-1', 'succeeded', duration_sec=3), 'at': '2026-10-01T00:00:00Z'}
        self.write(old)
        filler = {'event': 'lifecycle', 'stage': 'scheduling', 'pad': 'x' * 900}
        with self.path.open('ab') as handle:  # well past the 1 MiB dashboard window
            handle.write((json.dumps(filler) + '\n').encode() * 2000)
        self.assertGreater(self.path.stat().st_size, 1024 * 1024)
        data = deployment_view.safe_project_journal(self.factory)
        self.assertEqual([r['run_id'] for r in data['runs']], ['deploy-default-aaaaaaaa-1'])
        self.assertEqual(data['history']['total'], 1)
        rows = deployment_view.journal_rows(self.path)
        self.assertTrue(all(r.get('event') != 'lifecycle' for r in rows))  # filtered before parse

    def test_refresh_reads_only_appended_complete_lines(self):
        self.write(row('deploy-default-aaaaaaaa-1', 'succeeded'))
        self.assertEqual(len(deployment_view.journal_rows(self.path)), 1)
        offset = deployment_view._journal_cache[str(self.path)]['offset']
        torn = json.dumps(row('deploy-default-bbbbbbbb-1', 'succeeded'))
        with self.path.open('ab') as handle:
            handle.write(torn[:20].encode())  # a writer mid-line
        self.assertEqual(len(deployment_view.journal_rows(self.path)), 1)
        with self.path.open('ab') as handle:
            handle.write(torn[20:].encode() + b'\n')
        rows = deployment_view.journal_rows(self.path)
        self.assertEqual([r['run_id'] for r in rows], ['deploy-default-aaaaaaaa-1', 'deploy-default-bbbbbbbb-1'])
        self.assertGreater(deployment_view._journal_cache[str(self.path)]['offset'], offset)

    def test_rotation_rereads_segments_and_the_new_live_file(self):
        import gzip
        self.write(row('deploy-default-aaaaaaaa-1', 'succeeded'))
        deployment_view.journal_rows(self.path)
        # Rotate: the live file moves into segment 1 and a new live file starts.
        with self.path.open('rb') as live, gzip.open(self.factory / 'events.jsonl.1.gz', 'wb') as segment:
            segment.write(live.read())
        self.path.unlink()
        self.write(row('deploy-default-bbbbbbbb-1', 'failed'))
        rows = deployment_view.journal_rows(self.path)
        self.assertEqual([r['run_id'] for r in rows], ['deploy-default-aaaaaaaa-1', 'deploy-default-bbbbbbbb-1'])

    def test_a_journal_read_failure_is_isolated(self):
        self.write(row('deploy-default-aaaaaaaa-1', 'succeeded'))
        with mock.patch.object(deployment_view, 'journal_rows', side_effect=OSError('denied')):
            self.assertIsNone(deployment_view.safe_project_journal(self.factory))
        self.path.unlink()
        self.assertEqual(deployment_view.safe_project_journal(self.factory)['runs'], [])


class SnapshotDeploymentsTest(unittest.TestCase):
    def test_dashboard_snapshot_shows_deploys_beyond_the_bounded_window(self):
        from factory import config, dashboard, dispatch
        from tests.test_factory import make_repo

        with tempfile.TemporaryDirectory() as d:
            repo = make_repo(Path(d), '[repo]\nslug = "example/project"\n')
            state = repo / '.factory'
            state.mkdir()
            filler = json.dumps({'event': 'lifecycle', 'stage': 'scheduling', 'pad': 'x' * 900}) + '\n'
            (state / 'events.jsonl').write_text(
                json.dumps(row('deploy-default-aaaaaaaa-1', 'succeeded', duration_sec=3)) + '\n' + filler * 2000)
            empty = {'repository': {'id': 'R_1', 'issues': {'nodes': []}, 'pullRequests': {'nodes': []}}}
            deployment_view._journal_cache.clear()
            self.addCleanup(deployment_view._journal_cache.clear)
            with mock.patch.dict(dashboard.__dict__), mock.patch.dict(dispatch.__dict__):
                dashboard.configure(config.load(repo))
                with mock.patch.object(dashboard, 'github', return_value=empty), \
                     mock.patch.object(dashboard, 'dispatcher', return_value={}), \
                     mock.patch.object(dashboard, 'upstream_state', return_value={}), \
                     mock.patch.object(dashboard, 'triage_llm_online', return_value=False):
                    snapshot = dashboard.snapshot()
            self.assertEqual([r['run_id'] for r in snapshot['deployments']['runs']], ['deploy-default-aaaaaaaa-1'])
