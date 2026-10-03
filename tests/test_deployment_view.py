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
                    dict(event='deploy_superseded', run_id='superseded', target='default')]
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
        rows = [row('skip', 'skipped'), dict(event='applied', run_id='skip', ticket=1, ok=True)]
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
