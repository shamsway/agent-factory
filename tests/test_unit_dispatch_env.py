"""Unit diagnostics must use the same role-specific environment as installation."""
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from factory import config, inspection, verify_secrets


class DispatchEnvironmentTest(unittest.TestCase):
    def setUp(self):
        self.cfg = config.Config(Path('/nonexistent'), 'acme/widgets')
        self.cfg.install = dict(config.DEFAULT_INSTALL, apply=True, env={
            'GH_CONFIG_DIR': '/profiles/human', 'PATH': '/usr/bin'}, dispatch_env={
            'GH_CONFIG_DIR': '/profiles/automation', 'GH_TOKEN': 'dispatch-sentinel'})
        self.cfg.apply_enabled = True
        self.cfg.apply_env = {'GH_TOKEN': 'adapter-sentinel'}
        self.dispatch = f'{self.cfg.unit}.service'
        self.dashboard = f'{self.cfg.unit}-dashboard.service'
        self.bot = {**self.cfg.install['env'], **self.cfg.install['dispatch_env']}

    def test_sync_applies_dispatch_overrides_only_to_dispatch_and_apply(self):
        installed = {self.dispatch: self.bot, self.cfg.apply_unit: self.bot,
                     self.dashboard: self.cfg.install['env']}
        rows = verify_secrets.sync_rows(self.cfg, unit_env_fn=installed.get)
        self.assertTrue(all(status == 'in sync' for _, _, status in rows), rows)
        self.assertIn((self.dispatch, 'GH_TOKEN', 'in sync'), rows)
        self.assertIn((self.cfg.apply_unit, 'GH_TOKEN', 'in sync'), rows)
        self.assertNotIn((self.dashboard, 'GH_TOKEN', 'in sync'), rows)
        self.assertNotIn('sentinel', json.dumps(rows))

    def test_old_or_missing_dispatch_values_are_still_stale(self):
        rows = verify_secrets.sync_rows(self.cfg, unit_env_fn=lambda _: self.cfg.install['env'])
        self.assertIn((self.dispatch, 'GH_CONFIG_DIR', 'STALE -- rerun `factory install`'), rows)
        self.assertIn((self.dispatch, 'GH_TOKEN', 'missing from unit'), rows)
        self.assertIn((self.cfg.apply_unit, 'GH_CONFIG_DIR', 'STALE -- rerun `factory install`'), rows)

    def test_boundaries_respect_unit_role_and_keep_adapter_credentials_isolated(self):
        for unit in (self.dispatch, self.cfg.apply_unit):
            with self.subTest(unit=unit):
                rows = inspection.boundary(self.cfg, self.bot, unit=unit)
                self.assertTrue(all(row['status'] in {'match', 'isolated'} for row in rows), rows)
                leaked = inspection.boundary(self.cfg, {**self.bot, 'GH_TOKEN': 'adapter-sentinel'}, unit=unit)
                self.assertIn({'scope': 'apply', 'key': 'GH_TOKEN', 'status': 'leaked'}, leaked)
                self.assertNotIn('sentinel', json.dumps(rows + leaked))
        rows = inspection.boundary(self.cfg, self.cfg.install['env'], unit=self.dashboard)
        self.assertTrue(all(row['status'] in {'match', 'isolated'} for row in rows), rows)

    def test_unit_snapshot_passes_role_to_configured_effective_and_process_checks(self):
        env = ' '.join(f'{key}={value}' for key, value in self.bot.items())
        props = ('LoadState=loaded\nActiveState=active\nMainPID=123\nInvocationID=test\n'
                 'ExecStart={ path=/usr/bin/python3 ; }\nWorkingDirectory=/nonexistent\n'
                 f'Environment={env}\n')
        observed = {'status': 'observed', 'prefix': '/runtime', 'modules': {}}
        with patch.object(inspection, 'command', return_value=props), \
             patch.object(inspection, 'runtime_probe', return_value=observed), \
             patch.object(inspection, 'process_snapshot', return_value={'status': 'not_running'}) as process:
            result = inspection.unit_snapshot(self.cfg, self.dispatch, {})
        for name in ('configured_environment', 'effective_environment'):
            self.assertTrue(all(row['status'] in {'match', 'isolated'} for row in result[name]), result)
        self.assertEqual(process.call_args.kwargs['unit'], self.dispatch)
        self.assertNotIn('sentinel', json.dumps(result))
