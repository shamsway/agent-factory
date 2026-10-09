"""Operator mirror helper must work with its deliberately narrow PATH."""
import ast
from pathlib import Path
import subprocess
import unittest


class MirrorHelperTests(unittest.TestCase):
    def test_runuser_is_absolute_and_resolves_under_sanitized_path(self):
        source = Path('scripts/refresh-publisher-mirror.py').read_text()
        tree = ast.parse(source)
        commands = [node.args[0].elts[0].value for node in ast.walk(tree)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == 'run' and node.args
                    and isinstance(node.args[0], ast.List)
                    and node.args[0].elts and isinstance(node.args[0].elts[0], ast.Constant)]
        self.assertIn('/usr/sbin/runuser', commands)
        self.assertNotIn('runuser', commands)
        result = subprocess.run(['/usr/sbin/runuser', '--version'],
                                env={'PATH': '/usr/bin:/bin'}, capture_output=True)
        self.assertEqual(result.returncode, 0)
