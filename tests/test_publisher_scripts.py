"""Linux shell cleanup regressions; no system manager or network calls."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class PublisherScriptCleanupTests(unittest.TestCase):
    def check_cleanup(self, name):
        script = Path(__file__).resolve().parents[1] / 'scripts' / name
        text = script.read_text()
        cleanup = text[text.index('cleanup() {'):text.index("\ntrap cleanup EXIT")]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            override = root / 'override'
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
    stop) echo failed > "$work/state";;
    reset-failed) echo inactive > "$work/state";;
    is-active) cat "$work/state";;
  esac
}
echo failed > "$work/state"
''' + cleanup + "\ntrap cleanup EXIT\nexit 7\n"
            result = subprocess.run(['bash', '-c', harness, 'cleanup-test', directory],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 7, result.stderr)
            calls = (root / 'calls').read_text().splitlines()
            self.assertLess(calls.index('stop factory-publisher.service'),
                            calls.index('reset-failed factory-publisher.service'))
            self.assertEqual((root / 'state').read_text().strip(), 'inactive')
            self.assertFalse(override.exists())
            self.assertIn('daemon-reload', calls)

    def test_failed_a2_resets_unit_after_stop(self):
        self.check_cleanup('manual-verify-publisher.sh')

    def test_failed_publication_resets_unit_after_stop(self):
        self.check_cleanup('manual-publish-investigation.sh')
