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

    def test_comparator_is_required_after_both_audits(self) -> None:
        with self.copied_repository() as repo:
            skill_path = repo / "skills/create-public-pr/SKILL.md"
            content = skill_path.read_text(encoding="utf-8")
            comparator_call = (
                'python3 "$comparator" --audit-file "$audit_file" '
                '--review-file "$review_file" || exit 2'
            )
            content = content.replace(comparator_call, "printf 'skip comparator'", 1)
            skill_path.write_text(content, encoding="utf-8")

            self.assert_invalid(repo, "audit/review comparator must run after both scans")

    def test_branch_safety_contract_is_required(self) -> None:
        with self.copied_repository() as repo:
            skill_path = repo / "skills/create-public-pr/SKILL.md"
            content = skill_path.read_text(encoding="utf-8")
            content = content.replace(
                'git switch -c "$branch_name" || exit 2',
                "printf 'skip focused branch'",
            )
            content = content.replace(
                'test "$branch" != "$base" || exit 2',
                "printf 'skip branch comparison'",
            )
            content = content.replace(
                'git merge-base --is-ancestor "origin/$base" HEAD || exit 2',
                "printf 'skip ancestry check'",
            )
            skill_path.write_text(content, encoding="utf-8")

            result = self.run_validator(repo)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("focused branch creation contract is missing", result.stdout)
            self.assertIn("branch must differ from base", result.stdout)
            self.assertIn("base ancestry contract is missing", result.stdout)

    def test_repository_local_name_and_noreply_email_are_required(self) -> None:
        with self.copied_repository() as repo:
            skill_path = repo / "skills/create-public-pr/SKILL.md"
            content = skill_path.read_text(encoding="utf-8")
            content = content.replace(
                "git config --local --get user.name | grep -Eq '[^[:space:]]' || exit 2",
                "printf 'skip local name'",
            )
            skill_path.write_text(content, encoding="utf-8")

            self.assert_invalid(repo, "repository-local user.name check is missing")

    def test_public_content_scan_covers_future_files(self) -> None:
        markers = (
            "/" + "Users/example/private",
            "service" + "." + "internal",
        )
        for marker in markers:
            with self.subTest(marker_kind=marker.rsplit(".", 1)[-1]), self.copied_repository() as repo:
                notes = repo / "notes"
                notes.mkdir()
                (notes / "new.md").write_text(marker + "\n", encoding="utf-8")

                self.assert_invalid(
                    repo,
                    "public content contains internal/local marker: notes/new.md",
                )

    def test_public_content_scan_covers_scanner_and_tests(self) -> None:
        targets = (
            "skills/create-public-pr/scripts/audit_public_pr.py",
            "tests/test_audit_public_pr.py",
        )
        for relative_path in targets:
            with self.subTest(relative_path=relative_path), self.copied_repository() as repo:
                path = repo / relative_path
                marker = "/" + "Users/example/private"
                path.write_text(
                    path.read_text(encoding="utf-8") + "\n# " + marker + "\n",
                    encoding="utf-8",
                )

                self.assert_invalid(
                    repo,
                    f"public content contains internal/local marker: {relative_path}",
                )

    def test_eval_semantics_require_exact_routing_and_pressure_coverage(self) -> None:
        with self.copied_repository() as repo:
            evals_path = repo / "skills/create-public-pr/evals/evals.json"
            payload = json.loads(evals_path.read_text(encoding="utf-8"))
            replacements = {
                "routing-positive": (("create", "make"), ("publish", "share")),
                "routing-negative": (
                    ("issue-only", "other"),
                    ("deployment", "release"),
                ),
                "workflow-pressure": (
                    ("one-to-one audit/review comparator", "manual review"),
                ),
            }
            def replace_all(text: str, pairs: tuple[tuple[str, str], ...]) -> str:
                for old, new in pairs:
                    text = text.replace(old, new).replace(old.title(), new.title())
                return text

            for case in payload["evals"]:
                pairs = replacements.get(case["kind"], ())
                for field in ("prompt", "expected_output"):
                    case[field] = replace_all(case[field], pairs)
                case["expectations"] = [
                    replace_all(expectation, pairs)
                    for expectation in case["expectations"]
                ]
            evals_path.write_text(json.dumps(payload), encoding="utf-8")

            result = self.run_validator(repo)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("routing-positive eval trigger coverage is incomplete", result.stdout)
            self.assertIn("routing-negative eval trigger coverage is incomplete", result.stdout)
            self.assertIn("workflow-pressure eval expectations are incomplete", result.stdout)

    def test_readme_uses_official_repository_and_badge(self) -> None:
        with self.copied_repository() as repo:
            readme_path = repo / "README.md"
            content = readme_path.read_text(encoding="utf-8")
            content = content.replace(
                "takeshijuan/create-public-pr --skill create-public-pr",
                "YOUR_GITHUB_OWNER/create-public-pr --skill create-public-pr",
            )
            content = content.replace(
                "[![skills.sh](https://skills.sh/b/takeshijuan/create-public-pr)](https://skills.sh/takeshijuan/create-public-pr)",
                "skills.sh",
            )
            readme_path.write_text(content, encoding="utf-8")

            result = self.run_validator(repo)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("README installation must use the public repository", result.stdout)
            self.assertIn("README official skills.sh badge is missing", result.stdout)


if __name__ == "__main__":
    unittest.main()
