from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).parents[1]
SKILL_PATH = REPO_ROOT / "skills" / "create-public-pr" / "SKILL.md"
VERIFY_FIELDS = (
    "number,url,isDraft,baseRefName,headRefName,state,statusCheckRollup"
)
FORBIDDEN_OPTIONS = ("--reviewer", "--label", "--project", "--milestone")


FAKE_GH = "#!" + "/" + "usr/bin/env python3\n" + """
import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["GH_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(args) + "\\n")

if args[:2] in (["pr", "create"], ["pr", "edit"]):
    raise SystemExit(0)

if args[:2] == ["pr", "view"] and "--json" in args:
    fields = args[args.index("--json") + 1]
    if fields == "number":
        print("17")
    elif fields == "headRefName":
        print(os.environ["GH_BRANCH"])
    elif fields == "isDraft":
        print("true" if os.environ["GH_SCENARIO"] == "create" else "false")
    elif fields == os.environ["GH_VERIFY_FIELDS"]:
        print("{}")
    else:
        raise SystemExit(64)
    raise SystemExit(0)

raise SystemExit(64)
"""


class DocumentedGhWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.skill = SKILL_PATH.read_text(encoding="utf-8")

    def extract_shell_block(self, marker: str) -> str:
        self.assertEqual(self.skill.count(marker), 1)
        remainder = self.skill.split(marker, 1)[1].lstrip()
        self.assertTrue(remainder.startswith("```sh\n"))
        block, separator, _ = remainder.removeprefix("```sh\n").partition("\n```")
        self.assertEqual(separator, "\n```")
        return block

    def test_fake_executable_source_avoids_literal_absolute_shebang(self) -> None:
        absolute_shebang = "#!" + "/" + "usr/bin/env python3"

        self.assertFalse(
            absolute_shebang in Path(__file__).read_text(encoding="utf-8")
        )

    def run_documented_path(self, scenario: str) -> list[list[str]]:
        marker = {
            "create": "When the query returns no result, create one draft:",
            "refresh": (
                "After the open-PR query returns exactly one result, "
                "set its number and refresh it:"
            ),
        }[scenario]
        action_block = self.extract_shell_block(marker)
        verify_block = self.extract_shell_block("Verify either path:")
        shell = shutil.which("sh")
        self.assertIsNotNone(shell)

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            fake_gh = temporary_path / "gh"
            fake_gh.write_text(FAKE_GH, encoding="utf-8")
            fake_gh.chmod(0o755)
            log_path = temporary_path / "gh.jsonl"
            body_path = temporary_path / "body.md"
            body_path.write_text("Public beta summary\n", encoding="utf-8")
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": str(temporary_path)
                    + os.pathsep
                    + environment.get("PATH", ""),
                    "GH_LOG": str(log_path),
                    "GH_SCENARIO": scenario,
                    "GH_BRANCH": "codex/release-readiness",
                    "GH_VERIFY_FIELDS": VERIFY_FIELDS,
                    "base": "main",
                    "branch": "codex/release-readiness",
                    "title": "Public beta",
                    "body_file": str(body_path),
                    "pr_number": "17",
                    "existing_is_draft": "false",
                }
            )

            result = subprocess.run(
                [shell, "-eu", "-c", action_block + "\n" + verify_block],
                text=True,
                capture_output=True,
                env=environment,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stderr, "")
            return [
                json.loads(line)
                for line in log_path.read_text(encoding="utf-8").splitlines()
            ]

    def assert_no_implicit_metadata(self, calls: list[list[str]]) -> None:
        for option in FORBIDDEN_OPTIONS:
            self.assertFalse(
                any(option in call for call in calls),
                f"documented gh call passed {option}",
            )

    def test_visibility_gate_before_workflow(self) -> None:
        prefix = self.skill.split("```bash\n", 1)[1].split("pr_count=", 1)[0]
        stubs = '''
git() {
  case "$*" in
    'rev-parse --show-toplevel') printf '%s\\n' "$PWD" ;;
    'branch --show-current') printf '%s\\n' 'topic' ;;
    *) exit 99 ;;
  esac
}
gh() {
  case "$1 $2" in
    'auth status') return 0 ;;
    'repo view') printf '%s\\n' "$TEST_VISIBILITY"; return "$TEST_LOOKUP_STATUS" ;;
    *) exit 99 ;;
  esac
}
'''
        cases = [
            ("PUBLIC", 0, None, 0),
            ("PRIVATE", 0, None, 3),
            ("INTERNAL", 0, None, 3),
            ("UNKNOWN", 0, None, 3),
            ("", 0, None, 3),
            ("PUBLIC", 1, None, 3),
            ("PRIVATE", 0, "true", 0),
            ("PUBLIC", 0, "true", 0),
            ("UNKNOWN", 0, "true", 0),
            ("PUBLIC", 1, "true", 2),
            ("PRIVATE", 0, "yes", 2),
        ]
        for visibility, lookup_status, opt_in, expected in cases:
            with self.subTest(visibility=visibility, lookup_status=lookup_status, opt_in=opt_in):
                environment = os.environ.copy()
                environment.pop("CREATE_PUBLIC_PR_EXPLICIT_OPT_IN", None)
                environment.update(TEST_VISIBILITY=visibility, TEST_LOOKUP_STATUS=str(lookup_status))
                if opt_in is not None:
                    environment["CREATE_PUBLIC_PR_EXPLICIT_OPT_IN"] = opt_in
                result = subprocess.run(
                    ["bash", "-eu", "-c", stubs + prefix + "printf 'WORKFLOW_ENTERED\\n'"],
                    text=True, capture_output=True, env=environment,
                )
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertEqual("WORKFLOW_ENTERED" in result.stdout, expected == 0)
                if expected == 3:
                    self.assertIn("Use the normal PR workflow.", result.stdout)

    def test_create_block_creates_draft_with_explicit_fields_and_verifies(self) -> None:
        calls = self.run_documented_path("create")
        body_file = calls[0][-1]

        self.assertEqual(
            calls[0],
            [
                "pr",
                "create",
                "--draft",
                "--base",
                "main",
                "--head",
                "codex/release-readiness",
                "--title",
                "Public beta",
                "--body-file",
                body_file,
            ],
        )
        self.assertFalse(any(call[:2] == ["pr", "edit"] for call in calls))
        self.assertEqual(
            calls[-1], ["pr", "view", "17", "--json", VERIFY_FIELDS]
        )
        self.assert_no_implicit_metadata(calls)

    def test_refresh_block_edits_existing_pr_without_create_and_verifies(self) -> None:
        calls = self.run_documented_path("refresh")
        body_file = calls[0][-1]

        self.assertEqual(
            calls[0],
            [
                "pr",
                "edit",
                "17",
                "--base",
                "main",
                "--title",
                "Public beta",
                "--body-file",
                body_file,
            ],
        )
        self.assertFalse(any(call[:2] == ["pr", "create"] for call in calls))
        self.assertEqual(
            calls[-1], ["pr", "view", "17", "--json", VERIFY_FIELDS]
        )
        self.assert_no_implicit_metadata(calls)


if __name__ == "__main__":
    unittest.main()
