from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from factory import config, onboard, triage

SECOND_MODEL = "openai-codex/gpt-6-astra"
TOOLS_FLAGS = ("--no-tools", "--no-extensions", "--no-skills", "--no-rules")


class DefaultSecondReviewerTest(unittest.TestCase):
    def test_default_second_review_argv_disables_tools_and_keeps_model(self) -> None:
        argv = config.Config(Path("."), "acme/widgets").second_review_cmd("PROMPT")
        for flag in TOOLS_FLAGS:
            self.assertIn(flag, argv)
        self.assertEqual(config.command_model(argv), SECOND_MODEL)
        self.assertEqual(argv[-1], "PROMPT")

    def test_default_second_review_matches_primary_flag_order(self) -> None:
        self.assertEqual(config.DEFAULT_SECOND_REVIEWER[:7], config.DEFAULT_REVIEWER[:7])
        self.assertEqual(config.DEFAULT_SECOND_REVIEWER[7:], ["--model", SECOND_MODEL, "{prompt}"])


class ToolsProblemTest(unittest.TestCase):
    def test_omp_without_no_tools_is_reported(self) -> None:
        problem = onboard.tools_problem(["omp", "-p", "--model", "other/model", "{prompt}"])
        self.assertIsNotNone(problem)
        self.assertIn("--no-tools", problem)

    def test_omp_path_without_no_tools_is_reported(self) -> None:
        self.assertIsNotNone(onboard.tools_problem(["/usr/bin/omp", "-p", "{prompt}"]))

    def test_default_reviewers_are_clean(self) -> None:
        self.assertIsNone(onboard.tools_problem(list(config.DEFAULT_REVIEWER)))
        self.assertIsNone(onboard.tools_problem(list(config.DEFAULT_SECOND_REVIEWER)))

    def test_non_omp_reviewer_is_not_checked(self) -> None:
        self.assertIsNone(onboard.tools_problem(["candidate-reviewer", "--model", "other/model", "{prompt}"]))


class HostReviewOverrideTest(unittest.TestCase):
    def test_host_second_command_overrides_default(self) -> None:
        command = ["omp", "-p", "--model", "other/model", "{prompt}"]
        with tempfile.TemporaryDirectory() as directory:
            repo = _git_repo(Path(directory))
            host = {"defaults": {"review": {"second_command": command}}}
            with mock.patch.object(config, "host_config", return_value=host):
                cfg = config.load(repo)
        self.assertEqual(cfg.second_reviewer, command)


class DoctorReviewerToolsTest(unittest.TestCase):
    def doctor_rows(self, host_review: dict) -> dict[str, dict]:
        with tempfile.TemporaryDirectory() as directory:
            repo = _git_repo(Path(directory))
            host = {"defaults": {"review": host_review}} if host_review else {}
            with mock.patch.object(config, "host_config", return_value=host):
                cfg = config.load(repo)

            def command(argv: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
                if argv[:3] == ["gh", "label", "list"]:
                    return subprocess.CompletedProcess(argv, 0, json.dumps(list(config.LABELS)), "")
                if argv[:3] == ["gh", "repo", "view"]:
                    return subprocess.CompletedProcess(argv, 0, "WRITE\n", "")
                return subprocess.CompletedProcess(argv, 0, "", "")

            output = io.StringIO()
            with mock.patch.object(onboard.config, "load", return_value=cfg), \
                    mock.patch.object(onboard.config, "host_config", return_value=host), \
                    mock.patch.object(onboard, "sh", side_effect=command), \
                    mock.patch.object(onboard.shutil, "which", return_value="/bin/tool"), \
                    mock.patch.object(onboard, "_dashboard_port_check", return_value=(True, "available")), \
                    mock.patch.object(triage, "probe_endpoint", return_value=(True, "loading model")), \
                    redirect_stdout(output):
                onboard.doctor(["--json"])
        return {row["label"]: row for row in json.loads(output.getvalue())["rows"]}

    def test_host_second_command_without_no_tools_warns(self) -> None:
        rows = self.doctor_rows({"second_command": ["omp", "-p", "--model", "other/model", "{prompt}"]})
        self.assertEqual(rows["second reviewer tools"]["status"], "WARN")
        self.assertIn("--no-tools", rows["second reviewer tools"]["detail"])
        self.assertEqual(rows["reviewer tools"]["status"], "PASS")

    def test_default_second_reviewer_passes_tools_check(self) -> None:
        rows = self.doctor_rows({})
        self.assertEqual(rows["second reviewer tools"]["status"], "PASS")
        self.assertEqual(rows["reviewer tools"]["status"], "PASS")

    def test_host_review_command_without_no_tools_warns(self) -> None:
        rows = self.doctor_rows({"command": ["omp", "-p", "--model", "other/model", "{prompt}"]})
        self.assertEqual(rows["reviewer tools"]["status"], "WARN")


def _git_repo(directory: Path) -> Path:
    repo = directory / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    (repo / config.CONFIG_NAME).write_text('[repo]\nslug = "acme/widgets"\n')
    return repo


if __name__ == "__main__":
    unittest.main()
