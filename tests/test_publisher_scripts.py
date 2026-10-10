"""Linux shell cleanup regressions; no system manager or network calls."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class PublisherScriptCleanupTests(unittest.TestCase):
    def check_cleanup(self, name, *, override_exists=True, failed=True):
        script = Path(__file__).resolve().parents[1] / 'scripts' / name
        text = script.read_text()
        cleanup = text[text.index('cleanup() {'):text.index("\ntrap cleanup EXIT")]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            override = root / 'override'
            if override_exists:
                override.touch()
            harness = r'''set -euo pipefail
unit=factory-publisher.service
check=factory-publisher-check.service
work=$1
override=$work/override
owned_override=true
python=fixture_python
fixture_python() { return 0; }
set_switches() { echo "switch:$1" >> "$work/calls"; }
systemctl() {
  echo "$*" >> "$work/calls"
  case "$1" in
    stop) :;;
    is-failed) [[ $(cat "$work/state") == failed ]];;
    reset-failed) [[ $(cat "$work/state") == failed ]] || return 1; echo inactive > "$work/state";;
    is-active) cat "$work/state";;
  esac
}
''' + ('echo failed' if failed else 'echo inactive') + ' > "$work/state"\n' + cleanup + "\ntrap cleanup EXIT\nexit " + ("7" if failed else "0") + "\n"
            result = subprocess.run(['bash', '-c', harness, 'cleanup-test', directory],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 7 if failed else 0, result.stderr)
            calls = (root / 'calls').read_text().splitlines()
            if failed:
                self.assertLess(calls.index('stop factory-publisher.service'),
                                calls.index('reset-failed factory-publisher.service'))
            else:
                self.assertNotIn('reset-failed factory-publisher.service', calls)
            self.assertEqual((root / 'state').read_text().strip(), 'inactive')
            self.assertFalse(override.exists())
            if override_exists:
                self.assertIn('daemon-reload', calls)

    def test_failed_a2_resets_unit_after_stop(self):
        self.check_cleanup('manual-verify-publisher.sh')

    def test_failed_publication_resets_unit_after_stop(self):
        self.check_cleanup('manual-publish-investigation.sh')

    def test_failed_publication_resets_even_if_override_missing(self):
        self.check_cleanup('manual-publish-investigation.sh', override_exists=False)

    def test_unpinned_a2_runtime_is_refused_before_network_capable_start(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/manual-verify-publisher.sh'
        text = script.read_text()
        self.assertLess(text.index('installed_service_runtime_required'), text.index('systemctl start --wait'))

    def test_successful_a2_unloaded_unit_needs_no_reset(self):
        self.check_cleanup('manual-verify-publisher.sh', failed=False)

    def test_successful_publish_unloaded_unit_needs_no_reset(self):
        self.check_cleanup('manual-publish-investigation.sh', failed=False)
