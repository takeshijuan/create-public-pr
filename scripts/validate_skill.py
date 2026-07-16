"""Validate the portable create-public-pr skill repository."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any


REQUIRED_FILES = (
    ".gitignore",
    ".github/FUNDING.yml",
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/ISSUE_TEMPLATE/false-positive.yml",
    ".github/pull_request_template.md",
    ".github/workflows/validate.yml",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "scripts/validate_skill.py",
    "skills.sh.json",
    "skills/create-public-pr/SKILL.md",
    "skills/create-public-pr/evals/evals.json",
    "skills/create-public-pr/references/pr-writing.md",
    "skills/create-public-pr/references/privacy-policy.md",
    "skills/create-public-pr/scripts/audit_public_pr.py",
    "skills/create-public-pr/scripts/validate_audit_review.py",
    "tests/test_audit_public_pr.py",
    "tests/test_gh_workflow.py",
    "tests/test_validate_audit_review.py",
    "tests/test_validate_skill.py",
)

SKILL_PATH = "skills/create-public-pr/SKILL.md"
EVALS_PATH = "skills/create-public-pr/evals/evals.json"
REGISTRY_PATH = "skills.sh.json"
README_PATH = "README.md"
WORKFLOW_PATH = ".github/workflows/validate.yml"


def read_text(repo: Path, relative_path: str, errors: list[str]) -> str:
    try:
        return (repo / relative_path).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        errors.append(f"unreadable text file: {relative_path}")
        return ""


def read_json(repo: Path, relative_path: str, errors: list[str]) -> Any:
    text = read_text(repo, relative_path, errors)
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        errors.append(f"invalid JSON: {relative_path}")
        return None


def validate_required_files(repo: Path, errors: list[str]) -> None:
    for relative_path in REQUIRED_FILES:
        path = repo / relative_path
        if not path.is_file() or path.is_symlink():
            errors.append(f"missing required file: {relative_path}")


def parse_frontmatter(text: str, errors: list[str]) -> dict[str, str]:
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        errors.append("SKILL.md must start with YAML frontmatter")
        return {}
    try:
        closing_index = lines.index("---", 1)
    except ValueError:
        errors.append("SKILL.md frontmatter is not closed")
        return {}
    metadata: dict[str, str] = {}
    for line in lines[1:closing_index]:
        key, separator, value = line.partition(":")
        if not separator or not key.strip() or not value.strip():
            errors.append("SKILL.md frontmatter must contain simple key/value fields")
            continue
        metadata[key.strip()] = value.strip().strip('"\'')
    return metadata


def validate_frontmatter_and_references(skill: str, errors: list[str]) -> None:
    metadata = parse_frontmatter(skill, errors)
    if set(metadata) != {"name", "description"}:
        errors.append("SKILL.md frontmatter requires only name and description")
    name = metadata.get("name", "")
    if name != "create-public-pr" or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        errors.append("skill name must be create-public-pr and hyphenated")
    description = metadata.get("description", "")
    if not description.startswith("Use when "):
        errors.append("skill description must start with 'Use when...'")
    if len(description) > 500 or " I " in f" {description} " or " my " in description.lower():
        errors.append("skill description must be compact and third-person")
    for trigger in ("create", "open", "prepare", "publish", "refresh"):
        if trigger not in description.lower():
            errors.append(f"skill description lacks positive trigger: {trigger}")
    for negative in ("review-only", "commit-only", "issue", "merge", "deployment"):
        if negative not in description.lower():
            errors.append(f"skill description lacks negative trigger: {negative}")

    references = set(re.findall(r"\((references/[a-z0-9-]+\.md)\)", skill))
    expected = {"references/privacy-policy.md", "references/pr-writing.md"}
    if references != expected:
        errors.append("SKILL.md must reference exactly the two progressive resources")
    word_count = len(re.findall(r"\b[\w'-]+\b", skill))
    if not 700 <= word_count <= 1800:
        errors.append(f"SKILL.md word count outside 700-1800: {word_count}")


def validate_workflow_contract(skill: str, errors: list[str]) -> None:
    required_phrases = (
        "inspect-scope-branch-audit-validate-stage-commit-reaudit-push-draft-verify",
        "explicit user authorization",
        "mixed staged/untracked",
        "manual-review record",
        "no force option",
        "repository-local GitHub noreply identity",
    )
    normalized = skill.lower().replace(" and ", "-")
    if required_phrases[0] not in normalized:
        ordered_headings = re.findall(r"\d+\. \*\*([A-Za-z -]+)\.\*\*", skill)
        expected_order = [
            "Inspect",
            "Scope",
            "Branch",
            "Prepare",
            "Audit",
            "Validate",
            "Stage",
            "Commit and re-audit",
            "Push",
            "Create or refresh and verify",
        ]
        if ordered_headings != expected_order:
            errors.append("ordered public PR workflow contract is incomplete")
    for phrase in required_phrases[1:]:
        if phrase.lower() not in skill.lower():
            errors.append(f"workflow guidance missing: {phrase}")

    scanner_options = (
        "--repo",
        "--base",
        "--profile",
        "--paths-from",
        "--title-file",
        "--body-file",
        "--commit-message-file",
        "--public-artifacts-from",
        "--format json",
    )
    if 'scanner="$skill_root/scripts/audit_public_pr.py"' not in skill:
        errors.append("portable installed scanner path is missing")
    if 'comparator="$skill_root/scripts/validate_audit_review.py"' not in skill:
        errors.append("portable installed comparator path is missing")
    if 'python3 "$scanner"' not in skill:
        errors.append("exact scanner invocation is missing")
    comparator_call = (
        'python3 "$comparator" --audit-file "$audit_file" '
        '--review-file "$review_file" || exit 2'
    )
    if skill.count(comparator_call) != 2:
        errors.append("audit/review comparator must run after both scans")
    if re.search(r"\b1\)\s*:\s*;;", skill):
        errors.append("audit exit 1 must not bypass review validation")
    for option in scanner_options:
        if option not in skill:
            errors.append(f"scanner invocation missing option: {option}")
    if "exit 2" not in skill.lower() or "incomplete" not in skill.lower():
        errors.append("scanner incomplete hard-stop contract is missing")
    profile_routing_clauses = (
        "Use `community` for ordinary OSS publication, including repositories "
        "described only as future-public.",
        "Select `locked-down` only when repository instructions explicitly impose "
        "no-external-links, no-internal-links, or an equivalent prohibition.",
    )
    if not all(clause in skill for clause in profile_routing_clauses):
        errors.append("explicit community and locked-down profile routing is missing")
    profile_setup_instruction = (
        "Before running the sequence, set `CREATE_PUBLIC_PR_PROFILE` to the "
        "profile selected in step 4."
    )
    profile_selection_block = "\n".join(
        (
            "readonly profile=${CREATE_PUBLIC_PR_PROFILE:?select community or "
            "locked-down from repository instructions}",
            'case "$profile" in',
            "  community|locked-down) ;;",
            "  *) exit 2 ;;",
            "esac",
        )
    )
    if (
        profile_setup_instruction not in skill
        or profile_selection_block not in skill
    ):
        errors.append("executable profile selection contract is missing")
    elif skill.index(profile_selection_block) > skill.index('python3 "$scanner"'):
        errors.append("profile selection must precede scanner invocation")
    profile_assignment_lines = [
        line.strip()
        for line in skill.splitlines()
        if re.match(
            r"^[ \t]*(?:(?:declare|export|readonly|typeset)[ \t]+)?profile=",
            line,
        )
    ]
    if profile_assignment_lines != [profile_selection_block.splitlines()[0]]:
        errors.append("profile must be readonly and assigned exactly once")
    if skill.count('--profile "$profile"') != 2:
        errors.append("validated profile must be passed to both scanner invocations")
    if re.search(r"--profile\s+(?:community|locked-down)(?:\s|$)", skill):
        errors.append("scanner profile must not be hardcoded")

    if 'gh pr list --head "$branch" --state open' not in skill:
        errors.append("existing PR discovery contract is missing")
    create_line = next(
        (line.strip() for line in skill.splitlines() if line.strip().startswith("gh pr create ")),
        "",
    )
    if not create_line.startswith('gh pr create --draft --base "$base" --head "$branch"'):
        errors.append("draft PR creation contract is missing")
    if '--title "$title" --body-file "$body_file"' not in create_line:
        errors.append("PR creation must use --body-file")
    edit_line = (
        'gh pr edit "$pr_number" --base "$base" '
        '--title "$title" --body-file "$body_file"'
    )
    if edit_line not in skill:
        errors.append("existing PR refresh contract is missing")
    verify_fields = "number,url,isDraft,baseRefName,headRefName,state,statusCheckRollup"
    if verify_fields not in skill:
        errors.append("post-create PR verification fields are incomplete")
    if "gh auth status" not in skill:
        errors.append("GitHub authentication check is missing")
    if "codex/<short-description>" not in skill:
        errors.append("default branch naming contract is missing")
    if "Conventional Commits" not in skill:
        errors.append("default commit convention is missing")
    ancestry = 'git merge-base --is-ancestor "origin/$base" HEAD || exit 2'
    branch_create = 'git switch -c "$branch_name" || exit 2'
    branch_compare = 'test "$branch" != "$base" || exit 2'
    if branch_create not in skill:
        errors.append("focused branch creation contract is missing")
    if branch_compare not in skill:
        errors.append("branch must differ from base")
    if ancestry not in skill:
        errors.append("base ancestry contract is missing")
    elif branch_create in skill and skill.index(ancestry) > skill.index(branch_create):
        errors.append("base ancestry must be checked before fallback branch creation")
    if "git config --local --get user.name | grep -Eq '[^[:space:]]' || exit 2" not in skill:
        errors.append("repository-local user.name check is missing")
    if (
        "git config --local --get user.email "
        "| grep -Eq '@users\\.noreply\\.github\\.com$' || exit 2"
    ) not in skill:
        errors.append("repository-local noreply email check is missing")
    for contract in (
        'base=$(gh pr view "$pr_number" --json baseRefName',
        'pr_head=$(gh pr view "$pr_number" --json headRefName',
        'existing_is_draft=$(gh pr view "$pr_number" --json isDraft',
        'review_file="$repo_root/.git/public-pr-review.json"',
        'public_artifacts_file="$repo_root/.git/public-pr-public-artifacts.txt"',
        'public_artifact_args=(--public-artifacts-from "$public_artifacts_file")',
        "exact full key: `category`, `severity`, `source`, plus `commit`, `path_id`, and `artifact_id` whenever present",
        'git diff --cached --name-only > "$staged_file"',
    ):
        if contract not in skill:
            errors.append(f"workflow precision contract missing: {contract}")
    if "git diff --cached --name-status" in skill:
        errors.append("workflow must not print raw staged paths")
    if 'git diff --cached --check > "$diff_check_file" 2>&1' not in skill:
        errors.append("staged diff check must capture raw path output")
    if 'git commit --quiet -F "$commit_message_file"' not in skill:
        errors.append("commit command must suppress the file summary")

    for option in ("--reviewer", "--label", "--project", "--milestone"):
        if re.search(rf"(?<![\w-]){re.escape(option)}(?:\s|=)", skill):
            errors.append(f"forbidden implicit PR option: {option}")
    if re.search(r"git\s+push[^\n]*(?:--force|-f(?:\s|$))", skill):
        errors.append("force-push command is forbidden")
    if re.search(r"git\s+add\s+(?:-A|--all|\.)(?:\s|$)", skill):
        errors.append("broad staging command is forbidden")
    for command in (
        "git add -- <confirmed-paths>",
        "git add -p -- <confirmed-partial-paths>",
        "git diff --cached --check",
        "git push -u origin \"$branch\"",
    ):
        if command not in skill:
            errors.append(f"workflow command missing: {command}")


def validate_evals(repo: Path, errors: list[str]) -> None:
    payload = read_json(repo, EVALS_PATH, errors)
    if not isinstance(payload, dict):
        return
    if payload.get("skill_name") != "create-public-pr":
        errors.append("eval skill_name must be create-public-pr")
    evals = payload.get("evals")
    if not isinstance(evals, list) or not evals:
        errors.append("evals must contain a non-empty evals list")
        return
    ids: set[int] = set()
    kinds: set[str] = set()
    required = {"id", "kind", "prompt", "expected_output", "files", "expectations"}
    for index, case in enumerate(evals):
        if not isinstance(case, dict) or not required.issubset(case):
            errors.append(f"eval {index} is missing required fields")
            continue
        identifier = case["id"]
        if not isinstance(identifier, int) or identifier in ids:
            errors.append(f"eval {index} id must be a unique integer")
        else:
            ids.add(identifier)
        kind = case["kind"]
        if isinstance(kind, str):
            kinds.add(kind)
        if not isinstance(case["prompt"], str) or not case["prompt"].strip():
            errors.append(f"eval {identifier} prompt must be non-empty")
        if not isinstance(case["expected_output"], str) or not case["expected_output"].strip():
            errors.append(f"eval {identifier} expected_output must be non-empty")
        if not isinstance(case["files"], list):
            errors.append(f"eval {identifier} files must be a list")
        expectations = case["expectations"]
        if not isinstance(expectations, list) or not expectations or not all(
            isinstance(expectation, str) and expectation.strip()
            for expectation in expectations
        ):
            errors.append(f"eval {identifier} expectations must be non-empty strings")
    for kind in ("routing-positive", "routing-negative", "workflow-pressure"):
        if kind not in kinds:
            errors.append(f"evals require {kind} cases")
    if sum(1 for case in evals if isinstance(case, dict) and case.get("kind") == "workflow-pressure") < 3:
        errors.append("evals require at least three workflow-pressure cases")
    text_by_kind: dict[str, str] = {}
    for kind in kinds:
        parts: list[str] = []
        for case in evals:
            if not isinstance(case, dict) or case.get("kind") != kind:
                continue
            parts.extend(
                str(case.get(field, ""))
                for field in ("prompt", "expected_output")
            )
            expectations = case.get("expectations", [])
            if isinstance(expectations, list):
                parts.extend(str(expectation) for expectation in expectations)
        text_by_kind[kind] = " ".join(parts).lower()
    positive_markers = (
        "create",
        "open",
        "prepare",
        "publish",
        "refresh",
        "public-safe",
    )
    if not all(
        marker in text_by_kind.get("routing-positive", "")
        for marker in positive_markers
    ):
        errors.append("routing-positive eval trigger coverage is incomplete")
    negative_markers = (
        "review-only",
        "commit-only",
        "issue-only",
        "merge",
        "deployment",
    )
    if not all(
        marker in text_by_kind.get("routing-negative", "")
        for marker in negative_markers
    ):
        errors.append("routing-negative eval trigger coverage is incomplete")
    pressure_markers = (
        "locked-down profile",
        "does not amend, rebase, reset, or force-push",
        "authorizes the strategy change",
        "exact scope or clean worktree",
        "does not use broad staging, stash, reset, or restore",
        "one-to-one audit/review comparator",
        "external repository link as blocking",
    )
    if not all(
        marker in text_by_kind.get("workflow-pressure", "")
        for marker in pressure_markers
    ):
        errors.append("workflow-pressure eval expectations are incomplete")


def validate_registry(repo: Path, errors: list[str]) -> None:
    payload = read_json(repo, REGISTRY_PATH, errors)
    expected = {
        "$schema": "https://skills.sh/schemas/skills.sh.schema.json",
        "notGrouped": "bottom",
        "groupings": [
            {
                "title": "Git & Pull Requests",
                "description": "Portable workflows for preparing privacy-safe public pull requests.",
                "skills": ["create-public-pr"],
            }
        ],
    }
    if payload != expected:
        errors.append("skills.sh.json does not match the official grouped registry shape")


def validate_readme_and_ci(repo: Path, errors: list[str]) -> None:
    readme = read_text(repo, README_PATH, errors)
    user_install = (
        "npx skills@latest add takeshijuan/create-public-pr "
        "--skill create-public-pr"
    )
    if user_install not in readme:
        errors.append("README installation must use skills@latest")
        errors.append("README installation must use the public repository")
    badge = (
        "[![skills.sh](https://skills.sh/b/takeshijuan/create-public-pr)]"
        "(https://skills.sh/takeshijuan/create-public-pr)"
    )
    if badge not in readme:
        errors.append("README official skills.sh badge is missing")
    if "npx skills@latest add . --list" not in readme:
        errors.append("README local discovery must use skills@latest")
    pinned = "npx --yes skills@1.5.17 add . --list"
    if pinned not in readme:
        errors.append("README must document the skills@1.5.17 CI pin")
    beta_markers = (
        "## v0.1.0 beta limitations",
        "heuristic",
        "fake `gh`",
        "live github",
    )
    if not all(marker in readme.lower() for marker in beta_markers):
        errors.append("README v0.1.0 beta limitations are incomplete")

    workflow = read_text(repo, WORKFLOW_PATH, errors)
    if pinned not in workflow:
        errors.append("CI discovery must pin skills@1.5.17")
    for version in ("3.10", "3.11", "3.12", "3.13", "3.14"):
        if f'"{version}"' not in workflow:
            errors.append(f"CI Python matrix missing supported version: {version}")
    for command in (
        "python -m unittest discover -s tests -v",
        "python scripts/validate_skill.py --repo .",
    ):
        if command not in workflow:
            errors.append(f"CI validation command missing: {command}")
    if re.search(r"(?:pip\s+install|python\s+-m\s+pytest|\bpytest\b)", workflow):
        errors.append("CI Python checks must use only the standard library")


def validate_public_content(repo: Path, errors: list[str]) -> None:
    excluded_directories = {
        ".git",
        ".superpowers",
        ".pytest_cache",
        "__pycache__",
        "node_modules",
        "htmlcov",
    }
    excluded_files = {".coverage", ".DS_Store"}
    local_marker_pattern = re.compile(
        r"(?:^|[\s'\"(])/(?:"
        + r"Users|home"
        + r")/[^\s'\"`]+|"
        + "file:"
        + r"///[^\s'\"`]+|"
        + r"(?<![A-"
        + r"Z0"
        + r"-9])[A-Z]:[\\/](?:[^\s\\/]+[\\/])+[^\s\\/]+",
        re.I,
    )
    private_url_pattern = re.compile(
        r"https?://(?:[^\s/]+\.)?(?:"
        + r"local"
        + r"host|[^\s/]+\.in"
        + r"ternal|slack\."
        + r"com|notion\.so|clickup\.com"
        r")(?:/[^\s]*)?",
        re.I,
    )
    private_host_pattern = re.compile(
        r"\b(?:local" + r"host|[a-z0-9.-]+\.in" + r"ternal)\b",
        re.I,
    )
    email_pattern = re.compile(
        r"\b[A-"
        + r"Z0"
        + r"-9._%+-]+@([A-"
        + r"Z0"
        + r"-9.-]+\.[A-"
        + r"Z]{2,})\b",
        re.I,
    )
    public_files: list[Path] = []
    for root, directories, filenames in os.walk(repo):
        directories[:] = [
            directory
            for directory in directories
            if directory not in excluded_directories
        ]
        root_path = Path(root)
        for filename in filenames:
            if filename in excluded_files:
                continue
            public_files.append(root_path / filename)

    allowed_scanner_detector_lines = {
        '    r"\\bgithub_pat_[A-Za-z0-9_]{20,255}\\b|(?i:\\bBea'
        + 'rer\\s+[A-Za-z0-9._~+/-]{20,}))"',
        'LOCAL_HOST_RE = re.compile(r"(?i)\\b(?:local'
        + 'host|[a-z0-9.-]+\\.(?:local|internal))\\b")',
        '    r"(?:(?i:file):'
        + chr(47) * 3
        + '(?:[^\\s'
        + chr(47)
        + ']+'
        + chr(47)
        + ')+[^\\s'
        + chr(47)
        + ']+|"',
    }

    def intentional_detector_line(relative_path: str, line: str) -> bool:
        return (
            relative_path == "skills/create-public-pr/scripts/audit_public_pr.py"
            and line in allowed_scanner_detector_lines
        )

    for path in sorted(public_files):
        relative_path = path.relative_to(repo).as_posix()
        if path.is_symlink():
            errors.append(f"public content file must not be a symlink: {relative_path}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            errors.append("public content must be UTF" + f"-8 text: {relative_path}")
            continue
        for line in text.splitlines():
            if (
                local_marker_pattern.search(line)
                or private_url_pattern.search(line)
                or private_host_pattern.search(line)
            ) and not intentional_detector_line(relative_path, line):
                errors.append(
                    f"public content contains internal/local marker: {relative_path}"
                )
                break
        for match in email_pattern.finditer(text):
            address = match.group(0).lower()
            domain = match.group(1).lower()
            if address in {
                "git@" + "github.com",
                "git@" + "gitlab.com",
                "git@" + "bitbucket.org",
                "noreply@" + "github.com",
            }:
                continue
            if address.endswith("@users.noreply.github.com"):
                continue
            if domain in {"example.com", "example.net", "example.org"}:
                continue
            if domain.endswith((".example", ".invalid", ".test")):
                continue
            if "\\" in address:
                continue
            errors.append(f"public content contains non-example email: {relative_path}")
            break


def validate(repo: Path) -> list[str]:
    errors: list[str] = []
    validate_required_files(repo, errors)
    skill = read_text(repo, SKILL_PATH, errors)
    validate_frontmatter_and_references(skill, errors)
    validate_workflow_contract(skill, errors)
    validate_evals(repo, errors)
    validate_registry(repo, errors)
    validate_readme_and_ci(repo, errors)
    validate_public_content(repo, errors)
    return sorted(set(errors))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).resolve()
    errors = validate(repo)
    if errors:
        print("skill validation: failed")
        for error in errors:
            print(f"- {error}")
        return 1
    print("skill validation: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
