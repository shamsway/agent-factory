"""CI shards (scripts/test-shard.py) run every discovered test exactly once."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("test_shard_script", ROOT / "scripts" / "test-shard.py")
shard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shard)


class AssignTest(unittest.TestCase):
    def test_every_module_lands_in_exactly_one_shard(self):
        names = [f"test_{i}" for i in range(30)]
        weights = {name: float(i % 7 + 1) for i, name in enumerate(names[:25])}  # five unweighted
        for shards in (1, 2, 4, 7, 40):
            with self.subTest(shards=shards):
                plan = shard.assign(names, weights, shards)
                self.assertEqual(len(plan), shards)
                flat = [name for names_ in plan for name in names_]
                self.assertEqual(sorted(flat), sorted(names))

    def test_assignment_is_deterministic_and_balanced(self):
        weights = {"a": 10, "b": 6, "c": 5, "d": 4, "e": 1}
        plan = shard.assign(list(weights), weights, 2)
        self.assertEqual(plan, shard.assign(list(reversed(weights)), weights, 2))
        loads = [sum(weights[n] for n in names) for names in plan]
        self.assertLessEqual(max(loads) - min(loads), max(weights.values()))


class SuiteTest(unittest.TestCase):
    def test_shards_partition_the_real_suite(self):
        groups = shard.discover()
        everything = sorted(t.id() for tests in groups.values() for t in tests)
        loader = unittest.TestLoader()
        expected = sorted(t.id() for t in shard.flatten(loader.discover(str(ROOT / "tests"))))
        self.assertEqual(everything, expected)
        plan = shard.assign(list(groups), shard.load_weights(), 4)
        ran = sorted(t.id() for names in plan for name in names for t in groups[name])
        self.assertEqual(ran, expected)

    def test_import_failures_are_their_own_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "test_broken.py").write_text("import module_that_does_not_exist\n")
            [test] = shard.flatten(unittest.TestLoader().discover(tmp))
        self.assertTrue(type(test).__module__.startswith("unittest."))
        self.assertEqual(shard.group(test), test.id())
        self.assertIn("test_broken", shard.group(test))

    def test_weights_file_names_current_modules(self):
        weights = json.loads((ROOT / "tests" / "shard-weights.json").read_text())
        modules = {p.stem for p in (ROOT / "tests").glob("test_*.py")}
        self.assertTrue(weights)
        self.assertLessEqual(set(weights), modules, "stale module in tests/shard-weights.json; rerun --measure")


if __name__ == "__main__":
    unittest.main()
