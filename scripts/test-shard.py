#!/usr/bin/env python3
"""Run one shard of the unittest suite, so CI can split it across parallel jobs.

Discovers `tests/` exactly as `python -m unittest discover -s tests` does, groups
the tests by module, and deals the modules into N shards, heaviest first, using
the per-module seconds in tests/shard-weights.json. A module missing from the
weights (a new test file) gets the median weight, so it still runs somewhere:
every discovered test lands in exactly one shard. A module that fails to import
is its own group and fails in whichever shard gets it.

    scripts/test-shard.py --shards 4 --index 0     # run shard 0 of 4
    scripts/test-shard.py --shards 4 --list        # show the assignment
    scripts/test-shard.py --measure tests/shard-weights.json   # refresh weights

Exit 0: the shard passed; 1: a test failed or errored; 2: usage error.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEIGHTS = ROOT / "tests" / "shard-weights.json"


def flatten(suite: unittest.TestSuite) -> list[unittest.TestCase]:
    out = []
    for item in suite:
        out += flatten(item) if isinstance(item, unittest.TestSuite) else [item]
    return out


def group(test: unittest.TestCase) -> str:
    """The module a test belongs to; an import failure is a group of its own."""
    module = type(test).__module__
    return test.id() if module.startswith("unittest.") else module


def discover() -> dict[str, list[unittest.TestCase]]:
    # Same call as `python -m unittest discover -s tests`: tests/ is the top level, so
    # modules import as `test_x` and can import their siblings.
    suite = unittest.TestLoader().discover(str(ROOT / "tests"))
    groups: dict[str, list[unittest.TestCase]] = {}
    for test in flatten(suite):
        groups.setdefault(group(test), []).append(test)
    return groups


def assign(names: list[str], weights: dict[str, float], shards: int) -> list[list[str]]:
    """Longest-processing-time first: each module goes to the lightest shard so far."""
    default = statistics.median(weights.values()) if weights else 1.0
    load = [0.0] * shards
    out: list[list[str]] = [[] for _ in range(shards)]
    for name in sorted(names, key=lambda n: (-weights.get(n, default), n)):
        index = min(range(shards), key=lambda i: (load[i], i))
        out[index].append(name)
        load[index] += weights.get(name, default)
    return out


def load_weights() -> dict[str, float]:
    return json.loads(WEIGHTS.read_text()) if WEIGHTS.is_file() else {}


class TimingResult(unittest.TextTestResult):
    """Adds each test's wall time to its module's total."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.seconds: dict[str, float] = {}

    def startTest(self, test) -> None:
        self._started = time.monotonic()
        super().startTest(test)

    def stopTest(self, test) -> None:
        super().stopTest(test)
        key = group(test)
        self.seconds[key] = self.seconds.get(key, 0.0) + time.monotonic() - self._started


def run(tests: list[unittest.TestCase], result_class=unittest.TextTestResult) -> unittest.TestResult:
    runner = unittest.TextTestRunner(verbosity=1, resultclass=result_class)
    return runner.run(unittest.TestSuite(tests))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="scripts/test-shard.py", description=__doc__.splitlines()[0])
    parser.add_argument("--shards", type=int, default=1)
    parser.add_argument("--index", type=int)
    parser.add_argument("--list", action="store_true", help="print each shard's modules and weight")
    parser.add_argument("--measure", type=Path, metavar="OUT", help="run the whole suite and write per-module seconds")
    args = parser.parse_args(argv)
    sys.path.insert(0, str(ROOT))
    groups = discover()

    if args.measure:
        result = run([t for tests in groups.values() for t in tests], TimingResult)
        weights = {name: round(seconds, 2) for name, seconds in sorted(result.seconds.items())}
        args.measure.write_text(json.dumps(weights, indent=1, sort_keys=True) + "\n")
        return 0 if result.wasSuccessful() else 1

    if args.shards < 1 or (not args.list and (args.index is None or not 0 <= args.index < args.shards)):
        parser.error("--index must be in [0, --shards) unless --list")
    weights = load_weights()
    plan = assign(list(groups), weights, args.shards)
    if args.list:
        default = statistics.median(weights.values()) if weights else 1.0
        for i, names in enumerate(plan):
            total = sum(weights.get(n, default) for n in names)
            tests = sum(len(groups[n]) for n in names)
            print(f"shard {i}: {len(names)} modules, {tests} tests, ~{total:.0f}s")
            for name in names:
                print(f"  {name}")
        return 0
    chosen = plan[args.index]
    tests = [t for name in chosen for t in groups[name]]
    print(f"shard {args.index}/{args.shards}: {len(chosen)} modules, {len(tests)} of "
          f"{sum(map(len, groups.values()))} tests", flush=True)
    return 0 if run(tests).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
