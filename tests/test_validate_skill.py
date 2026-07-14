from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


REPO_ROOT = Path(__file__).parents[1]
VALIDATOR = REPO_ROOT / "scripts" / "validate_skill.py"


class SkillRepositoryValidationTests(unittest.TestCase):
    def run_validator(self, repo: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), "--repo", str(repo)],
            text=True,
            capture_output=True,
        )

    @contextmanager
    def copied_repository(self) -> Iterator[Path]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "repo"
            shutil.copytree(
                REPO_ROOT,
                destination,
                ignore=shutil.ignore_patterns(
                    ".git", ".pytest_cache", ".superpowers", "__pycache__"
                ),
            )
            yield destination

    def replace(self, repo: Path, relative_path: str, old: str, new: str) -> None:
        path = repo / relative_path
        content = path.read_text(encoding="utf-8")
        self.assertIn(old, content)
        path.write_text(content.replace(old, new, 1), encoding="utf-8")

    def assert_invalid(self, repo: Path, expected_message: str) -> None:
        result = self.run_validator(repo)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(expected_message, result.stdout)
        self.assertEqual(result.stderr, "")

    def test_complete_repository_surface_validates(self) -> None:
        result = self.run_validator(REPO_ROOT)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "skill validation: clean\n")
        self.assertEqual(result.stderr, "")

    def test_missing_required_public_file_is_rejected(self) -> None:
        with self.copied_repository() as repo:
            (repo / "SECURITY.md").unlink()

            self.assert_invalid(repo, "missing required file: SECURITY.md")

    def test_routing_evals_require_positive_and_negative_cases(self) -> None:
        with self.copied_repository() as repo:
            evals_path = repo / "skills/create-public-pr/evals/evals.json"
            payload = json.loads(evals_path.read_text(encoding="utf-8"))
            payload["evals"] = [
                case for case in payload["evals"] if case["kind"] != "routing-negative"
            ]
            evals_path.write_text(json.dumps(payload), encoding="utf-8")

            self.assert_invalid(repo, "evals require routing-negative cases")

    def test_pr_creation_must_be_draft(self) -> None:
        with self.copied_repository() as repo:
            self.replace(
                repo,
                "skills/create-public-pr/SKILL.md",
                "gh pr create --draft --base",
                "gh pr create --base",
            )

            self.assert_invalid(repo, "draft PR creation contract is missing")

    def test_pr_creation_must_use_a_body_file(self) -> None:
        with self.copied_repository() as repo:
            self.replace(
                repo,
                "skills/create-public-pr/SKILL.md",
                'gh pr create --draft --base "$base" --head "$branch" --title "$title" --body-file "$body_file"',
                'gh pr create --draft --base "$base" --head "$branch" --title "$title" --body "inline"',
            )

            self.assert_invalid(repo, "PR creation must use --body-file")

    def test_existing_pr_must_be_refreshed(self) -> None:
        with self.copied_repository() as repo:
            self.replace(
                repo,
                "skills/create-public-pr/SKILL.md",
                'gh pr edit "$pr_number" --base "$base" --title "$title" --body-file "$body_file"',
                'printf "%s\\n" "skip refresh"',
            )

            self.assert_invalid(repo, "existing PR refresh contract is missing")

    def test_pr_commands_must_not_add_metadata_implicitly(self) -> None:
        for option in ("--reviewer", "--label", "--project", "--milestone"):
            with self.subTest(option=option), self.copied_repository() as repo:
                self.replace(
                    repo,
                    "skills/create-public-pr/SKILL.md",
                    "gh pr create --draft --base",
                    f"gh pr create {option} example-value --draft --base",
                )

                self.assert_invalid(repo, f"forbidden implicit PR option: {option}")

    def test_readme_uses_latest_for_user_installation(self) -> None:
        with self.copied_repository() as repo:
            self.replace(
                repo,
                "README.md",
                "npx skills@latest add",
                "npx skills@1.5.17 add",
            )

            self.assert_invalid(repo, "README installation must use skills@latest")

    def test_ci_pins_repository_discovery(self) -> None:
        with self.copied_repository() as repo:
            self.replace(
                repo,
                ".github/workflows/validate.yml",
                "npx --yes skills@1.5.17 add . --list",
                "npx --yes skills@latest add . --list",
            )

            self.assert_invalid(repo, "CI discovery must pin skills@1.5.17")

    def test_ci_rejects_third_party_python_test_dependencies(self) -> None:
        with self.copied_repository() as repo:
            self.replace(
                repo,
                ".github/workflows/validate.yml",
                "run: python -m unittest discover",
                "run: python -m pip install pytest && python -m unittest discover",
            )

            self.assert_invalid(repo, "CI Python checks must use only the standard library")

    def test_default_branch_and_commit_conventions_are_required(self) -> None:
        with self.copied_repository() as repo:
            skill_path = repo / "skills/create-public-pr/SKILL.md"
            content = skill_path.read_text(encoding="utf-8")
            content = content.replace("codex/<short-description>", "topic-branch")
            content = content.replace("Conventional Commits", "descriptive messages")
            skill_path.write_text(content, encoding="utf-8")

            result = self.run_validator(repo)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("default branch naming contract is missing", result.stdout)
            self.assertIn("default commit convention is missing", result.stdout)

    def test_git_checks_and_commit_do_not_print_raw_paths(self) -> None:
        with self.copied_repository() as repo:
            skill_path = repo / "skills/create-public-pr/SKILL.md"
            content = skill_path.read_text(encoding="utf-8")
            content = content.replace(
                'git diff --cached --check > "$diff_check_file"',
                "git diff --cached --check",
            )
            content = content.replace("git commit --quiet -F", "git commit -F")
            skill_path.write_text(content, encoding="utf-8")

            result = self.run_validator(repo)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("staged diff check must capture raw path output", result.stdout)
            self.assertIn("commit command must suppress the file summary", result.stdout)


if __name__ == "__main__":
    unittest.main()
