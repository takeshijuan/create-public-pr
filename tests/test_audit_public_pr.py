from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).parents[1]
    / "skills"
    / "create-public-pr"
    / "scripts"
    / "audit_public_pr.py"
)


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        text=True,
        capture_output=True,
    )


def initialize_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Public Contributor")
    git(repo, "config", "user.email", "12345+public@users.noreply.github.com")
    git(repo, "config", "commit.gpgsign", "false")
    git(repo, "remote", "add", "origin", "https://github.com/example/project.git")
    (repo / "README.md").write_text("# Example\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "initial")
    return repo


def audit(
    repo: Path, base: str = "HEAD~1", *args: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(repo),
            "--base",
            base,
            "--profile",
            "community",
            "--format",
            "json",
            *args,
        ],
        text=True,
        capture_output=True,
    )


def test_clean_committed_change_passes(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "public.txt").write_text(
        "ordinary public documentation\n", encoding="utf-8"
    )
    git(repo, "add", "public.txt")
    git(repo, "commit", "-m", "docs: add public documentation")

    result = audit(repo)

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "complete": True,
        "findings": [],
        "profile": "community",
    }


def test_non_repository_exits_incomplete(tmp_path: Path) -> None:
    not_repo = tmp_path / "not-repo"
    not_repo.mkdir()

    result = audit(not_repo, "main")

    assert result.returncode == 2
    assert json.loads(result.stdout) == {
        "complete": False,
        "error": "repository validation failed",
        "findings": [],
        "profile": "community",
    }


def test_invalid_base_ref_exits_incomplete(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)

    result = audit(repo, "missing-ref")

    assert result.returncode == 2
    assert json.loads(result.stdout)["complete"] is False


def test_detached_head_exits_incomplete(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    git(repo, "checkout", "--detach")

    result = audit(repo, "HEAD")

    assert result.returncode == 2
    assert json.loads(result.stdout)["complete"] is False


@pytest.mark.parametrize(
    ("category", "content"),
    [
        ("credential", "api_" + "key = sk-" + "live-" + "A" * 24),
        ("private-key", "-----BEGIN " + "PRIVATE KEY-----"),
        ("credential-url", "https://" + "alice:passphrase@service.example/path"),
        ("collaboration-url", "https://" + "workspace.slack.com/archives/C0123"),
        ("private-host", "http://" + "localhost:3000/internal"),
        ("private-host", "http://" + "10.0.0.8/internal"),
        ("private-host", "http://" + "[fd00::1]/internal"),
        ("local-path", "/Users/" + "private-user/work/project"),
        ("email", "person" + "@private-company.dev"),
        ("external-tracker", "PRIVATE" + "-123"),
        ("repository-link", "https://" + "gitlab.com/other/private-repo"),
    ],
)
def test_detects_sensitive_added_content(
    tmp_path: Path, category: str, content: str
) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "change.txt").write_text(content + "\n", encoding="utf-8")
    git(repo, "add", "change.txt")
    git(repo, "commit", "-m", "add change")

    result = audit(repo)

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert category in {finding["category"] for finding in payload["findings"]}
    assert content not in result.stdout
    assert content not in result.stderr


def test_scans_commit_messages(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "safe.txt").write_text("safe\n", encoding="utf-8")
    git(repo, "add", "safe.txt")
    marker = "PRIVATE" + "-456"
    git(repo, "commit", "-m", f"copy details from {marker}")

    result = audit(repo)

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert any(
        finding["category"] == "external-tracker"
        and finding["source"] == "commit-message"
        for finding in payload["findings"]
    )
    assert marker not in result.stdout


def test_non_noreply_author_and_committer_are_redacted_review_findings(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    author_email = "author" + "@private-company.dev"
    committer_email = "committer" + "@private-company.dev"
    git(repo, "config", "user.email", committer_email)
    (repo / "safe.txt").write_text("safe\n", encoding="utf-8")
    git(repo, "add", "safe.txt")
    git(
        repo,
        "commit",
        "--author",
        f"Private Author <{author_email}>",
        "-m",
        "safe change",
    )

    result = audit(repo)

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    identity_findings = [
        finding for finding in payload["findings"] if finding["category"] == "identity"
    ]
    assert {finding["source"] for finding in identity_findings} == {
        "author-identity",
        "committer-identity",
    }
    assert all(finding["severity"] == "review" for finding in identity_findings)
    assert not any(finding["category"] == "email" for finding in payload["findings"])
    assert author_email not in result.stdout
    assert committer_email not in result.stdout


def test_scans_current_branch_name(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    marker = "PRIVATE" + "-789"
    git(repo, "checkout", "-b", f"feature/{marker}")
    (repo / "safe.txt").write_text("safe\n", encoding="utf-8")
    git(repo, "add", "safe.txt")
    git(repo, "commit", "-m", "safe change")

    result = audit(repo)

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert any(
        finding["category"] == "external-tracker" and finding["source"] == "branch-name"
        for finding in payload["findings"]
    )
    assert marker not in result.stdout


def test_scans_changed_filenames_without_printing_them(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    marker = "PRIVATE" + "-901"
    filename = f"notes-{marker}.txt"
    (repo / filename).write_text("safe\n", encoding="utf-8")
    git(repo, "add", filename)
    git(repo, "commit", "-m", "safe change")

    result = audit(repo)

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert any(
        finding["category"] == "external-tracker"
        and finding["source"] == "committed-path"
        and finding["path_id"]
        for finding in payload["findings"]
    )
    assert marker not in result.stdout
    assert filename not in result.stdout


def test_scans_tracked_and_untracked_worktree_changes(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "tracked.txt").write_text("base\n", encoding="utf-8")
    git(repo, "add", "tracked.txt")
    git(repo, "commit", "-m", "add tracked file")
    (repo / "tracked.txt").write_text(
        "/Users/" + "private-user/project\n", encoding="utf-8"
    )
    (repo / "untracked.txt").write_text(
        "http://" + "192.168.50.9/service\n", encoding="utf-8"
    )

    result = audit(repo)

    assert result.returncode == 1
    worktree_categories = {
        finding["category"]
        for finding in json.loads(result.stdout)["findings"]
        if finding["source"] == "worktree-content"
    }
    assert {"local-path", "private-host"} <= worktree_categories


def test_paths_file_limits_only_worktree_scan(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    committed_marker = "PRIVATE" + "-222"
    (repo / "tracked.txt").write_text(committed_marker + "\n", encoding="utf-8")
    git(repo, "add", "tracked.txt")
    git(repo, "commit", "-m", "add tracked file")
    (repo / "tracked.txt").write_text(
        "/Users/" + "selected-user/project\n", encoding="utf-8"
    )
    (repo / "untracked.txt").write_text(
        "http://" + "10.20.30.40/service\n", encoding="utf-8"
    )
    paths_file = tmp_path / "paths.txt"
    paths_file.write_text("tracked.txt\n", encoding="utf-8")

    result = audit(repo, "HEAD~1", "--paths-from", str(paths_file))

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert any(
        finding["category"] == "external-tracker"
        and finding["source"] == "committed-content"
        for finding in findings
    )
    assert any(
        finding["category"] == "local-path" and finding["source"] == "worktree-content"
        for finding in findings
    )
    assert not any(
        finding["category"] == "private-host"
        and finding["source"].startswith("worktree")
        for finding in findings
    )


def test_detects_sensitive_content_added_then_removed_in_intermediate_commit(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    secret = "api_" + "key = sk-" + "intermediate-" + "Z" * 24
    (repo / "temporary.txt").write_text(secret + "\n", encoding="utf-8")
    git(repo, "add", "temporary.txt")
    git(repo, "commit", "-m", "add temporary configuration")
    git(repo, "rm", "temporary.txt")
    git(repo, "commit", "-m", "remove temporary configuration")

    result = audit(repo, "HEAD~2")

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert any(
        finding["category"] == "credential" and finding["source"] == "committed-content"
        for finding in findings
    )
    assert secret not in result.stdout


def test_scans_optional_proposed_text_files(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "safe.txt").write_text("safe\n", encoding="utf-8")
    git(repo, "add", "safe.txt")
    git(repo, "commit", "-m", "safe change")
    title = tmp_path / "title.txt"
    body = tmp_path / "body.txt"
    commit_message = tmp_path / "commit-message.txt"
    title.write_text("PRIVATE" + "-333\n", encoding="utf-8")
    body.write_text("https://" + "workspace.slack.com/archives/C99\n", encoding="utf-8")
    commit_message.write_text("/Users/" + "private-user/project\n", encoding="utf-8")

    result = audit(
        repo,
        "HEAD~1",
        "--title-file",
        str(title),
        "--body-file",
        str(body),
        "--commit-message-file",
        str(commit_message),
    )

    assert result.returncode == 1
    sources = {finding["source"] for finding in json.loads(result.stdout)["findings"]}
    assert {"proposed-title", "proposed-body", "proposed-commit-message"} <= sources


def test_flags_committed_binary_for_manual_review(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "asset.bin").write_bytes(b"\x00\x01\x02public-binary")
    git(repo, "add", "asset.bin")
    git(repo, "commit", "-m", "add asset")

    result = audit(repo)

    assert result.returncode == 1
    assert any(
        finding["category"] == "binary"
        and finding["severity"] == "review"
        and finding["source"] == "committed-binary"
        for finding in json.loads(result.stdout)["findings"]
    )


def test_flags_untracked_binary_for_manual_review(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "asset.bin").write_bytes(b"\x00\x01\x02worktree-binary")

    result = audit(repo, "HEAD")

    assert result.returncode == 1
    assert any(
        finding["category"] == "binary"
        and finding["severity"] == "review"
        and finding["source"] == "worktree-binary"
        for finding in json.loads(result.stdout)["findings"]
    )


@pytest.mark.parametrize("target", ["/tmp/outside", "../outside"])
def test_flags_unsafe_worktree_symlink_targets(tmp_path: Path, target: str) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "link").symlink_to(target)

    result = audit(repo, "HEAD")

    assert result.returncode == 1
    assert any(
        finding["category"] == "symlink" and finding["source"] == "worktree-symlink"
        for finding in json.loads(result.stdout)["findings"]
    )


def test_does_not_follow_safe_worktree_symlink(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    secret = "api_" + "key = sk-" + "target-" + "Y" * 24
    outside = repo / "target.txt"
    outside.write_text(secret + "\n", encoding="utf-8")
    (repo / "link").symlink_to("target.txt")
    paths_file = tmp_path / "paths.txt"
    paths_file.write_text("link\n", encoding="utf-8")

    result = audit(repo, "HEAD", "--paths-from", str(paths_file))

    assert result.returncode == 0
    assert json.loads(result.stdout)["findings"] == []
    assert secret not in result.stdout


def test_flags_unsafe_committed_symlink_target(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "link").symlink_to("../outside")
    git(repo, "add", "link")
    git(repo, "commit", "-m", "add link")

    result = audit(repo)

    assert result.returncode == 1
    assert any(
        finding["category"] == "symlink" and finding["source"] == "committed-symlink"
        for finding in json.loads(result.stdout)["findings"]
    )


@pytest.mark.parametrize(
    "same_repo_link",
    [
        "https://" + "github.com/example/project/issues/123",
        "git@" + "github.com:example/project.git",
    ],
)
def test_allows_same_repository_links(tmp_path: Path, same_repo_link: str) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "reference.txt").write_text(same_repo_link + "\n", encoding="utf-8")
    git(repo, "add", "reference.txt")
    git(repo, "commit", "-m", "add reference")

    result = audit(repo)

    assert result.returncode == 0
    assert json.loads(result.stdout)["findings"] == []


@pytest.mark.parametrize(
    ("profile", "severity"),
    [("community", "review"), ("locked-down", "blocking")],
)
def test_external_repository_link_severity_depends_on_profile(
    tmp_path: Path, profile: str, severity: str
) -> None:
    repo = initialize_repo(tmp_path)
    external_link = "https://" + "github.com/other/project"
    (repo / "reference.txt").write_text(external_link + "\n", encoding="utf-8")
    git(repo, "add", "reference.txt")
    git(repo, "commit", "-m", "add reference")

    extra = () if profile == "community" else ("--profile", profile)
    result = audit(repo, "HEAD~1", *extra)

    assert result.returncode == 1
    finding = next(
        finding
        for finding in json.loads(result.stdout)["findings"]
        if finding["category"] == "repository-link"
    )
    assert finding["severity"] == severity


def test_text_output_is_deduplicated_and_redacted(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    secret = "api_" + "key = sk-" + "redacted-" + "R" * 24
    (repo / "change.txt").write_text(secret + "\n" + secret + "\n", encoding="utf-8")
    git(repo, "add", "change.txt")
    git(repo, "commit", "-m", "add change")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(repo),
            "--base",
            "HEAD~1",
            "--profile",
            "community",
            "--format",
            "text",
        ],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 1
    assert result.stdout.count("credential") == 1
    assert "blocking" in result.stdout
    assert "committed-content" in result.stdout
    assert secret not in result.stdout
    assert secret not in result.stderr


@pytest.mark.parametrize(
    "credential",
    [
        "AKIA" + "A" * 16,
        "ghp_" + "b" * 36,
        "github_pat_" + "C" * 40,
        "Bearer " + "d" * 32,
    ],
)
def test_detects_common_unlabelled_credentials(tmp_path: Path, credential: str) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "change.txt").write_text(credential + "\n", encoding="utf-8")
    git(repo, "add", "change.txt")
    git(repo, "commit", "-m", "add change")

    result = audit(repo)

    assert result.returncode == 1
    assert any(
        finding["category"] == "credential"
        for finding in json.loads(result.stdout)["findings"]
    )
    assert credential not in result.stdout


def test_does_not_scan_content_only_removed_from_base(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    secret = "api_" + "key = sk-" + "removed-" + "Q" * 24
    (repo / "old.txt").write_text(secret + "\n", encoding="utf-8")
    git(repo, "add", "old.txt")
    git(repo, "commit", "-m", "base with old content")
    git(repo, "rm", "old.txt")
    git(repo, "commit", "-m", "remove old content")

    result = audit(repo, "HEAD~1")

    assert result.returncode == 0
    assert json.loads(result.stdout)["findings"] == []


def test_allows_example_and_github_noreply_emails(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    allowed = "docs" + "@example.com\n123+public" + "@users.noreply.github.com\n"
    (repo / "contacts.txt").write_text(allowed, encoding="utf-8")
    git(repo, "add", "contacts.txt")
    git(repo, "commit", "-m", "add example contacts")

    result = audit(repo)

    assert result.returncode == 0
    assert json.loads(result.stdout)["findings"] == []


def test_unreadable_optional_input_exits_incomplete(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    missing = tmp_path / "missing-body.txt"

    result = audit(repo, "HEAD", "--body-file", str(missing))

    assert result.returncode == 2
    assert json.loads(result.stdout)["complete"] is False


def test_repo_argument_must_be_worktree_root(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    nested = repo / "nested"
    nested.mkdir()

    result = audit(nested, "HEAD")

    assert result.returncode == 2
    assert json.loads(result.stdout)["complete"] is False


def test_paths_file_can_select_an_ignored_untracked_file(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    (repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    git(repo, "add", ".gitignore")
    git(repo, "commit", "-m", "add ignore rule")
    (repo / "ignored.txt").write_text(
        "/Users/" + "selected-user/private\n", encoding="utf-8"
    )
    paths_file = tmp_path / "paths.txt"
    paths_file.write_text("ignored.txt\n", encoding="utf-8")

    result = audit(repo, "HEAD~1", "--paths-from", str(paths_file))

    assert result.returncode == 1
    assert any(
        finding["category"] == "local-path" and finding["source"] == "worktree-content"
        for finding in json.loads(result.stdout)["findings"]
    )


@pytest.mark.parametrize(
    "link",
    [
        "git@" + "github.com:other/project.git",
        "ssh://" + "git@gitlab.com/other/project.git",
        "https://" + "bitbucket.org/other/project",
    ],
)
def test_detects_repository_links_across_hosts_and_protocols(
    tmp_path: Path, link: str
) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "reference.txt").write_text(link + "\n", encoding="utf-8")
    git(repo, "add", "reference.txt")
    git(repo, "commit", "-m", "add reference")

    result = audit(repo)

    assert result.returncode == 1
    assert any(
        finding["category"] == "repository-link"
        for finding in json.loads(result.stdout)["findings"]
    )
