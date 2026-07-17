from __future__ import annotations

import hashlib
import json
import inspect
import runpy
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Callable


class _Mark:
    @staticmethod
    def parametrize(
        argnames: str | tuple[str, ...], argvalues: list[Any]
    ) -> Callable[[Callable[..., None]], Callable[..., None]]:
        names = (
            tuple(name.strip() for name in argnames.split(","))
            if isinstance(argnames, str)
            else tuple(argnames)
        )

        def decorate(function: Callable[..., None]) -> Callable[..., None]:
            setattr(function, "_parameter_cases", (names, tuple(argvalues)))
            return function

        return decorate


class _PytestStyle:
    mark = _Mark()


pytest = _PytestStyle()


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


def write_public_artifact_manifest(repo: Path, *relative_paths: str) -> Path:
    manifest = repo / ".git" / "public-pr-public-artifacts.txt"
    rows = []
    for relative_path in relative_paths:
        digest = hashlib.sha256((repo / relative_path).read_bytes()).hexdigest()
        rows.append(f"{digest}  {relative_path}")
    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return manifest


def install_raw_commit(repo: Path, invalid_field: str) -> str:
    parent = git(repo, "rev-parse", "HEAD").stdout.strip()
    tree = git(repo, "rev-parse", "HEAD^{tree}").stdout.strip()
    private_path = b"/" + b"Users/" + b"invalid-owner/private-repo"
    invalid_value = b"Invalid \xff " + private_path
    identity = invalid_value if invalid_field == "identity" else b"Public Contributor"
    message = invalid_value if invalid_field == "message" else b"safe message"
    email = b"12345+public@users.noreply.github.com"
    raw_commit = b"\n".join(
        (
            b"tree " + tree.encode("ascii"),
            b"parent " + parent.encode("ascii"),
            b"author " + identity + b" <" + email + b"> 1700000000 +0000",
            b"committer " + identity + b" <" + email + b"> 1700000000 +0000",
            b"",
            message,
            b"",
        )
    )
    result = subprocess.run(
        ["git", "-C", str(repo), "hash-object", "-t", "commit", "-w", "--stdin"],
        input=raw_commit,
        capture_output=True,
        check=True,
    )
    commit = result.stdout.decode("ascii").strip()
    git(repo, "reset", "--hard", "--quiet", commit)
    return parent


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
        ("private-host", "http://" + "local" + "host:3000/internal"),
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


@pytest.mark.parametrize(
    "content",
    [
        'echo "::add-mask::sensitive value"',
        'echo "::add-matcher::matcher.json"',
        'echo "::add-path::tools/bin"',
        'echo "::debug::diagnostic message"',
        'echo "::error::required package path is missing"',
        'echo "::warning file=ci.yml,line=1,col=1::check failed"',
        'echo "::echo::on"',
        'echo "::endgroup::"',
        'echo "::group::build details"',
        'echo "::notice::build completed"',
        'echo "::remove-matcher owner=compiler::"',
        'echo "::set-env name=MODE::release"',
        'echo "::set-output name=result::ok"',
        'echo "::save-state name=phase::done"',
        'echo "::stop-commands::stopMarker"',
        'echo "::WARNING::uppercase command"',
        'echo "::resume-token::"',
        'echo "::$stopMarker::"',
        'echo "::${stopMarker}::"',
    ],
)
def test_github_workflow_command_is_not_private_host(
    tmp_path: Path, content: str
) -> None:
    repo = initialize_repo(tmp_path)
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(content + "\n", encoding="utf-8")
    git(repo, "add", ".github/workflows/ci.yml")
    git(repo, "commit", "-m", "ci: add workflow annotation")

    result = audit(repo)

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["findings"] == []


def test_github_workflow_command_message_still_scans_private_host(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    private_ipv6 = "[" + "fd00" + ":" + ":" + "8]"
    workflow.write_text(
        f'echo "::error::backend returned {private_ipv6}"\n',
        encoding="utf-8",
    )
    git(repo, "add", ".github/workflows/ci.yml")
    git(repo, "commit", "-m", "ci: add unsafe workflow annotation")

    result = audit(repo)

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert any(finding["category"] == "private-host" for finding in findings)


def test_github_workflow_command_unspaced_message_still_scans_private_host(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    private_ipv6 = "fd00" + ":" + ":" + "8"
    workflow.write_text(
        f'echo "::error::{private_ipv6}"\n',
        encoding="utf-8",
    )
    git(repo, "add", ".github/workflows/ci.yml")
    git(repo, "commit", "-m", "ci: add unsafe workflow annotation")

    result = audit(repo)

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert any(finding["category"] == "private-host" for finding in findings)


def test_github_workflow_command_property_delimiter_still_scans_private_host(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    private_ipv6 = "fd00" + ":" + ":" + "1"
    workflow.write_text(
        f'echo "::error title={private_ipv6}::message"\n',
        encoding="utf-8",
    )
    git(repo, "add", ".github/workflows/ci.yml")
    git(repo, "commit", "-m", "ci: add unsafe workflow annotation property")

    result = audit(repo)

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert any(finding["category"] == "private-host" for finding in findings)


@pytest.mark.parametrize(
    ("address_kind", "property_prefix", "message"),
    [
        ("loopback", True, "failed"),
        ("loopback", False, "1failed"),
        ("ula", True, "error"),
        ("ula", False, "bad"),
    ],
)
def test_expanded_private_ipv6_at_workflow_delimiter_is_detected(
    tmp_path: Path,
    address_kind: str,
    property_prefix: bool,
    message: str,
) -> None:
    repo = initialize_repo(tmp_path)
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    if address_kind == "loopback":
        private_ipv6 = ":".join(["0"] * 7 + ["1"])
    else:
        private_ipv6 = "fd00:" + ":".join(["0"] * 6 + ["1"])
    command_prefix = (
        ":" + ":" + "error title="
        if property_prefix
        else ":" + ":" + "error" + ":" + ":"
    )
    delimiter = ":" + ":"
    workflow.write_text(
        f'echo "{command_prefix}{private_ipv6}{delimiter}{message}"\n',
        encoding="utf-8",
    )
    git(repo, "add", ".github/workflows/ci.yml")
    git(repo, "commit", "-m", "ci: add unsafe expanded workflow address")

    result = audit(repo)

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert any(finding["category"] == "private-host" for finding in findings)


@pytest.mark.parametrize(
    ("token", "stop_first"),
    [
        ("1", True),
        ("1", False),
        ("fd00", True),
        ("fd00", False),
        ("fc00", True),
        ("fc00", False),
        ("fe80", True),
        ("fe80", False),
    ],
)
def test_private_ipv6_marker_is_not_masked_by_matching_stop_token(
    tmp_path: Path, token: str, stop_first: bool
) -> None:
    repo = initialize_repo(tmp_path)
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    stop_command = ":" + ":" + "stop-commands" + ":" + ":" + token
    private_marker = ":" + ":" + token + ":" + ":"
    stop_line = f'echo "{stop_command}"'
    marker_line = f'backend="{private_marker}"'
    lines = [stop_line, marker_line] if stop_first else [marker_line, stop_line]
    workflow.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )
    git(repo, "add", ".github/workflows/ci.yml")
    git(repo, "commit", "-m", "ci: add unsafe workflow marker")

    result = audit(repo)

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert any(finding["category"] == "private-host" for finding in findings)


@pytest.mark.parametrize(
    "address_kind",
    ["compressed-ula", "compressed-link-local", "expanded-ula", "expanded-loopback"],
)
def test_private_ipv6_inside_expression_token_is_not_masked(
    tmp_path: Path, address_kind: str
) -> None:
    repo = initialize_repo(tmp_path)
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    if address_kind == "compressed-ula":
        private_ipv6 = "fd00" + ":" + ":" + "1"
    elif address_kind == "compressed-link-local":
        private_ipv6 = "fe80" + ":" + ":" + "1"
    elif address_kind == "expanded-ula":
        private_ipv6 = "fd00:" + ":".join(["0"] * 6 + ["1"])
    else:
        private_ipv6 = ":".join(["0"] * 7 + ["1"])
    if address_kind.startswith("expanded"):
        private_ipv6 += ":" + ":" + "x"
    marker_value = "face-${{ '" + private_ipv6 + "' }}"
    stop_command = ":" + ":" + "stop-commands" + ":" + ":" + marker_value
    resume_marker = ":" + ":" + marker_value + ":" + ":"
    workflow.write_text(
        f'echo "{stop_command}"\necho "{resume_marker}"\n',
        encoding="utf-8",
    )
    git(repo, "add", ".github/workflows/ci.yml")
    git(repo, "commit", "-m", "ci: add unsafe workflow expression")

    result = audit(repo)

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert any(finding["category"] == "private-host" for finding in findings)


@pytest.mark.parametrize(
    "later_marker",
    [
        ":" + ":" + "error" + ":" + ":" + "message",
        ":" + ":" + "resume-token" + ":" + ":",
        ":" + ":" + "${stopMarker}" + ":" + ":",
    ],
)
def test_workflow_command_property_private_ipv6_before_marker_is_detected(
    tmp_path: Path, later_marker: str
) -> None:
    repo = initialize_repo(tmp_path)
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    private_ipv6 = "fd00" + ":" + ":" + "8"
    workflow.write_text(
        f'echo "::error title={private_ipv6} before {later_marker}"\n',
        encoding="utf-8",
    )
    git(repo, "add", ".github/workflows/ci.yml")
    git(repo, "commit", "-m", "ci: add unsafe workflow annotation property")

    result = audit(repo)

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert any(finding["category"] == "private-host" for finding in findings)


@pytest.mark.parametrize(
    "suffix",
    [
        " before " + ":" + ":" + "error" + ":" + ":" + "message",
        " before marker " + ":" + ":",
    ],
)
def test_private_compressed_ipv6_before_later_marker_is_detected(
    tmp_path: Path, suffix: str
) -> None:
    repo = initialize_repo(tmp_path)
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    private_ipv6 = ":" + ":" + "1"
    workflow.write_text(
        f'echo "{private_ipv6}{suffix}"\n',
        encoding="utf-8",
    )
    git(repo, "add", ".github/workflows/ci.yml")
    git(repo, "commit", "-m", "ci: add unsafe workflow annotation")

    result = audit(repo)

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert any(finding["category"] == "private-host" for finding in findings)


@pytest.mark.parametrize(
    "suffix",
    [
        "-label" + ":" + ":",
        "_label" + ":" + ":",
        "z" + ":" + ":",
        "-label key=value" + ":" + ":",
        "z key=value" + ":" + ":",
    ],
)
def test_private_compressed_ipv6_with_token_suffix_is_detected(
    tmp_path: Path, suffix: str
) -> None:
    repo = initialize_repo(tmp_path)
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    private_ipv6 = ":" + ":" + "1"
    workflow.write_text(
        f'echo "{private_ipv6}{suffix}"\n',
        encoding="utf-8",
    )
    git(repo, "add", ".github/workflows/ci.yml")
    git(repo, "commit", "-m", "ci: add unsafe workflow annotation")

    result = audit(repo)

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert any(finding["category"] == "private-host" for finding in findings)


@pytest.mark.parametrize(
    "token",
    [
        "face-token",
        "face-${GITHUB_RUN_ID}",
        "face-${{ github.run_id }}",
        "face-${{ format('}}-{0}', github.run_id) }}",
        "7-token",
    ],
)
def test_paired_workflow_resume_token_is_not_private_host(
    tmp_path: Path, token: str
) -> None:
    repo = initialize_repo(tmp_path)
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    stop_command = ":" + ":" + "stop-commands" + ":" + ":" + token
    resume_marker = ":" + ":" + token + ":" + ":"
    workflow.write_text(
        f'echo "{stop_command}"\necho "{resume_marker}"\n',
        encoding="utf-8",
    )
    git(repo, "add", ".github/workflows/ci.yml")
    git(repo, "commit", "-m", "ci: resume workflow commands")

    result = audit(repo)

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["findings"] == []


def test_workflow_span_scan_remains_linear() -> None:
    module = runpy.run_path(str(SCRIPT))
    marker = ":" + ":" + "error" + ":" + ":"
    private_ipv6 = "fd00" + ":" + ":" + "1"
    text = " ".join([marker] * 5_000 + [private_ipv6] * 5_000)

    started_at = time.perf_counter()
    findings = module["scan_text"](
        text,
        profile="community",
        source="performance-regression",
        repo_identity=None,
    )
    elapsed = time.perf_counter() - started_at

    assert elapsed < 5.0
    assert any(finding["category"] == "private-host" for finding in findings)


def test_malformed_workflow_expression_scan_remains_linear() -> None:
    module = runpy.run_path(str(SCRIPT))
    stop_command = ":" + ":" + "stop-commands" + ":" + ":"
    malformed_expression = "${{" + "a"
    text = stop_command + malformed_expression * 10_000

    started_at = time.perf_counter()
    tokens = module["extract_workflow_stop_tokens"](text)
    elapsed = time.perf_counter() - started_at

    assert elapsed < 3.0
    assert tokens == frozenset()


def test_unterminated_workflow_marker_scan_remains_linear() -> None:
    module = runpy.run_path(str(SCRIPT))
    expression = "${{ x }}"
    text = ":" + ":" + expression * 10_000 + ":x"

    started_at = time.perf_counter()
    tokens = module["extract_workflow_stop_tokens"](text)
    elapsed = time.perf_counter() - started_at

    assert elapsed < 3.0
    assert tokens == frozenset()


def test_repeated_malformed_workflow_prefixes_remain_linear() -> None:
    module = runpy.run_path(str(SCRIPT))
    stop_command = ":" + ":" + "stop-commands" + ":" + ":"
    malformed_stop = stop_command + "${{a "
    malformed_marker = ":" + ":" + "${{a"
    text = malformed_stop * 10_000 + malformed_marker * 10_000

    started_at = time.perf_counter()
    tokens = module["extract_workflow_stop_tokens"](text)
    elapsed = time.perf_counter() - started_at

    assert elapsed < 3.0
    assert tokens == frozenset()


def test_repeated_valid_workflow_expressions_remain_linear() -> None:
    module = runpy.run_path(str(SCRIPT))
    marker_value = "face-${{ x }}"
    stop_command = ":" + ":" + "stop-commands" + ":" + ":" + marker_value
    resume_marker = ":" + ":" + marker_value + ":" + ":"
    text = (stop_command + " " + resume_marker + " ") * 10_000

    started_at = time.perf_counter()
    tokens = module["extract_workflow_stop_tokens"](text)
    elapsed = time.perf_counter() - started_at

    assert elapsed < 3.0
    assert tokens == frozenset({marker_value})


@pytest.mark.parametrize(
    ("state", "source"),
    [
        ("committed", "committed-content"),
        ("staged", "staged-content"),
        ("unstaged", "worktree-content"),
    ],
)
def test_diff_attribute_cannot_hide_sensitive_text(
    tmp_path: Path, state: str, source: str
) -> None:
    repo = initialize_repo(tmp_path)
    (repo / ".gitattributes").write_text("secret.txt -diff\n", encoding="utf-8")
    (repo / "secret.txt").write_text("safe\n", encoding="utf-8")
    git(repo, "add", ".gitattributes", "secret.txt")
    git(repo, "commit", "-m", "add text attributes")

    credential = "api_" + "key = sk-" + "attribute-" + "A" * 24
    (repo / "secret.txt").write_text(credential + "\n", encoding="utf-8")
    if state == "committed":
        git(repo, "add", "secret.txt")
        git(repo, "commit", "-m", "update attributed text")
        result = audit(repo)
    elif state == "staged":
        git(repo, "add", "secret.txt")
        result = audit(repo, "HEAD")
    else:
        result = audit(repo, "HEAD")

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert any(
        finding["category"] == "credential" and finding["source"] == source
        for finding in payload["findings"]
    )
    assert credential not in result.stdout
    assert credential not in result.stderr


def test_diff_attribute_cannot_hide_sensitive_text_in_root_commit(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Public Contributor")
    git(repo, "config", "user.email", "12345+public@users.noreply.github.com")
    git(repo, "config", "commit.gpgsign", "false")
    credential = "api_" + "key = sk-" + "root-attribute-" + "A" * 24
    (repo / ".gitattributes").write_text("secret.txt -diff\n", encoding="utf-8")
    (repo / "secret.txt").write_text(credential + "\n", encoding="utf-8")
    git(repo, "add", ".gitattributes", "secret.txt")
    git(repo, "commit", "-m", "root attributed text")

    git(repo, "checkout", "--orphan", "unrelated")
    git(repo, "rm", "-f", ".gitattributes", "secret.txt")
    (repo / "unrelated.txt").write_text("safe\n", encoding="utf-8")
    git(repo, "add", "unrelated.txt")
    git(repo, "commit", "-m", "unrelated base")
    git(repo, "checkout", "main")

    result = audit(repo, "unrelated")

    assert result.returncode == 1
    assert any(
        finding["category"] == "credential" and finding["source"] == "committed-content"
        for finding in json.loads(result.stdout)["findings"]
    )
    assert credential not in result.stdout


def test_diff_attribute_cannot_hide_sensitive_merge_resolution(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    (repo / ".gitattributes").write_text("secret.txt -diff\n", encoding="utf-8")
    (repo / "secret.txt").write_text("base\n", encoding="utf-8")
    git(repo, "add", ".gitattributes", "secret.txt")
    git(repo, "commit", "-m", "add attributed merge file")
    base = git(repo, "rev-parse", "HEAD").stdout.strip()

    git(repo, "checkout", "-b", "side")
    (repo / "secret.txt").write_text("side\n", encoding="utf-8")
    git(repo, "add", "secret.txt")
    git(repo, "commit", "-m", "change side")

    git(repo, "checkout", "main")
    (repo / "secret.txt").write_text("main\n", encoding="utf-8")
    git(repo, "add", "secret.txt")
    git(repo, "commit", "-m", "change main")
    merge = subprocess.run(
        ["git", "-C", str(repo), "merge", "--no-ff", "side"],
        text=True,
        capture_output=True,
    )
    assert merge.returncode == 1
    credential = "api_" + "key = sk-" + "merge-attribute-" + "A" * 24
    (repo / "secret.txt").write_text(credential + "\n", encoding="utf-8")
    git(repo, "add", "secret.txt")
    git(repo, "commit", "-m", "resolve attributed merge")

    result = audit(repo, base)

    assert result.returncode == 1
    assert any(
        finding["category"] == "credential" and finding["source"] == "committed-content"
        for finding in json.loads(result.stdout)["findings"]
    )
    assert credential not in result.stdout


@pytest.mark.parametrize("driver_option", ["command", "textconv"])
def test_custom_diff_driver_cannot_hide_content_or_execute(
    tmp_path: Path, driver_option: str
) -> None:
    repo = initialize_repo(tmp_path)
    marker = tmp_path / f"{driver_option}-executed"
    driver = tmp_path / f"{driver_option}-driver.py"
    driver.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
        "print('masked diff')\n",
        encoding="utf-8",
    )
    git(
        repo,
        "config",
        f"diff.malicious.{driver_option}",
        f"{sys.executable} {driver}",
    )
    (repo / ".gitattributes").write_text(
        "secret.txt diff=malicious\n", encoding="utf-8"
    )
    (repo / "secret.txt").write_text("safe\n", encoding="utf-8")
    git(repo, "add", ".gitattributes", "secret.txt")
    git(repo, "commit", "-m", "add custom diff driver")

    credential = "api_" + "key = sk-" + "driver-" + "A" * 24
    (repo / "secret.txt").write_text(credential + "\n", encoding="utf-8")
    git(repo, "add", "secret.txt")
    git(repo, "commit", "-m", "update custom diff text")

    result = audit(repo)

    assert result.returncode == 1
    assert any(
        finding["category"] == "credential" and finding["source"] == "committed-content"
        for finding in json.loads(result.stdout)["findings"]
    )
    assert not marker.exists()
    assert credential not in result.stdout
    assert credential not in result.stderr


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


def test_deleted_existing_sensitive_path_is_not_new_public_content(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    marker = "PRIVATE" + "-902"
    filename = f"notes-{marker}.txt"
    (repo / filename).write_text("legacy content\n", encoding="utf-8")
    git(repo, "add", filename)
    git(repo, "commit", "-m", "add legacy path")
    git(repo, "rm", filename)

    result = audit(repo, "HEAD")

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["findings"] == []
    assert marker not in result.stdout + result.stderr


def test_rename_to_sensitive_path_is_still_blocked(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "safe.txt").write_text("safe\n", encoding="utf-8")
    git(repo, "add", "safe.txt")
    git(repo, "commit", "-m", "add safe path")
    marker = "PRIVATE" + "-903"
    filename = f"notes-{marker}.txt"
    git(repo, "mv", "safe.txt", filename)

    result = audit(repo, "HEAD")

    assert result.returncode == 1
    assert any(
        finding["category"] == "external-tracker"
        and finding["source"] == "worktree-path"
        for finding in json.loads(result.stdout)["findings"]
    )
    assert marker not in result.stdout + result.stderr


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


def test_paths_file_scans_selected_staged_content_even_if_worktree_reverts_it(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    for name in ("selected.txt", "excluded.txt"):
        (repo / name).write_text("safe\n", encoding="utf-8")
    git(repo, "add", "selected.txt", "excluded.txt")
    git(repo, "commit", "-m", "add tracked files")

    selected_secret = "api_" + "key = sk-" + "selected-" + "S" * 24
    excluded_secret = "api_" + "key = sk-" + "excluded-" + "E" * 24
    (repo / "selected.txt").write_text(selected_secret + "\n", encoding="utf-8")
    (repo / "excluded.txt").write_text(excluded_secret + "\n", encoding="utf-8")
    git(repo, "add", "selected.txt", "excluded.txt")
    (repo / "selected.txt").write_text("safe\n", encoding="utf-8")
    (repo / "excluded.txt").write_text("safe\n", encoding="utf-8")
    paths_file = tmp_path / "paths.txt"
    paths_file.write_text("selected.txt\n", encoding="utf-8")

    result = audit(repo, "HEAD", "--paths-from", str(paths_file))

    assert result.returncode == 1
    staged_findings = [
        finding
        for finding in json.loads(result.stdout)["findings"]
        if finding["source"] == "staged-content"
    ]
    assert len(staged_findings) == 1
    assert staged_findings[0]["category"] == "credential"
    assert selected_secret not in result.stdout
    assert excluded_secret not in result.stdout


def test_flags_staged_binary_even_if_worktree_reverts_it(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "asset.bin").write_text("safe\n", encoding="utf-8")
    git(repo, "add", "asset.bin")
    git(repo, "commit", "-m", "add tracked asset")
    (repo / "asset.bin").write_bytes(b"\x00\x01\x02staged-binary")
    git(repo, "add", "asset.bin")
    (repo / "asset.bin").write_text("safe\n", encoding="utf-8")

    result = audit(repo, "HEAD")

    assert result.returncode == 1
    assert any(
        finding["category"] == "binary" and finding["source"] == "staged-binary"
        for finding in json.loads(result.stdout)["findings"]
    )


def test_paths_file_does_not_rescan_clean_tracked_binary(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "asset.bin").write_bytes(b"\x00\x01\x02base-binary")
    git(repo, "add", "asset.bin")
    git(repo, "commit", "-m", "add base asset")
    paths_file = tmp_path / "paths.txt"
    paths_file.write_text("asset.bin\n", encoding="utf-8")

    result = audit(repo, "HEAD", "--paths-from", str(paths_file))

    assert result.returncode == 0
    assert json.loads(result.stdout)["findings"] == []


@pytest.mark.parametrize("prefix", ["++", "+++"])
def test_scans_added_content_that_begins_with_diff_header_markers(
    tmp_path: Path, prefix: str
) -> None:
    repo = initialize_repo(tmp_path)
    secret = prefix + " api_" + "key = sk-" + "plus-line-" + "P" * 24
    (repo / "change.txt").write_text(secret + "\n", encoding="utf-8")
    git(repo, "add", "change.txt")
    git(repo, "commit", "-m", "add plus-prefixed content")

    result = audit(repo)

    assert result.returncode == 1
    assert any(
        finding["category"] == "credential" and finding["source"] == "committed-content"
        for finding in json.loads(result.stdout)["findings"]
    )
    assert secret not in result.stdout


def test_paths_file_reports_symlink_ancestor_without_following_it(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = "api_" + "key = sk-" + "outside-" + "O" * 24
    (outside / "private.txt").write_text(secret + "\n", encoding="utf-8")
    (repo / "redirect").symlink_to(outside, target_is_directory=True)
    paths_file = tmp_path / "paths.txt"
    paths_file.write_text("redirect/private.txt\n", encoding="utf-8")

    result = audit(repo, "HEAD", "--paths-from", str(paths_file))

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert any(
        finding["category"] == "symlink"
        and finding["source"] == "worktree-symlink-ancestor"
        for finding in findings
    )
    assert not any(finding["category"] == "credential" for finding in findings)
    assert secret not in result.stdout


def test_tracked_file_replaced_by_directory_is_incomplete(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    path = repo / "tracked.txt"
    path.write_text("safe\n", encoding="utf-8")
    git(repo, "add", "tracked.txt")
    git(repo, "commit", "-m", "add tracked file")
    path.unlink()
    path.mkdir()

    result = audit(repo, "HEAD")

    assert result.returncode == 2
    assert json.loads(result.stdout) == {
        "complete": False,
        "error": "repository validation failed",
        "findings": [],
        "profile": "community",
    }
    assert result.stderr == ""


@pytest.mark.parametrize(
    ("category", "content"),
    [
        (
            "credential-url",
            "postgresql://" + "dbuser:dbpass@database.example/app",
        ),
        ("private-host", "fd00::1"),
        ("local-path", "/tmp/" + "workspace/private-data"),
    ],
)
def test_detects_expanded_private_url_host_and_path_forms(
    tmp_path: Path, category: str, content: str
) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "change.txt").write_text(content + "\n", encoding="utf-8")
    git(repo, "add", "change.txt")
    git(repo, "commit", "-m", "add private reference")

    result = audit(repo)

    assert result.returncode == 1
    assert category in {
        finding["category"] for finding in json.loads(result.stdout)["findings"]
    }
    assert content not in result.stdout


@pytest.mark.parametrize("output_format", ["json", "text"])
def test_malformed_remote_returns_redacted_incomplete_output(
    tmp_path: Path, output_format: str
) -> None:
    repo = initialize_repo(tmp_path)
    malformed_remote = "https://" + "[broken/repository.git"
    git(repo, "remote", "set-url", "origin", malformed_remote)

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(repo),
            "--base",
            "HEAD",
            "--profile",
            "community",
            "--format",
            output_format,
        ],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 2
    if output_format == "json":
        payload = json.loads(result.stdout)
        assert payload["complete"] is False
        assert payload["findings"] == []
    else:
        assert "audit: incomplete" in result.stdout
    assert malformed_remote not in result.stdout
    assert malformed_remote not in result.stderr
    assert result.stderr == ""


@pytest.mark.parametrize(
    ("invalid_field", "output_format"),
    [
        ("message", "json"),
        ("message", "text"),
        ("identity", "json"),
        ("identity", "text"),
    ],
)
def test_invalid_utf8_commit_metadata_fails_closed_and_redacted(
    tmp_path: Path, invalid_field: str, output_format: str
) -> None:
    repo = initialize_repo(tmp_path)
    base = install_raw_commit(repo, invalid_field)

    result = subprocess.run(
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
            output_format,
        ],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 2
    if output_format == "json":
        assert json.loads(result.stdout) == {
            "complete": False,
            "error": "repository validation failed",
            "findings": [],
            "profile": "community",
        }
    else:
        assert "audit: incomplete" in result.stdout
        assert "repository validation failed" in result.stdout
    private_path = "/" + "Users/" + "invalid-owner/private-repo"
    output = result.stdout + result.stderr
    assert private_path not in output
    assert "/" + "Users/" not in output
    assert "\\xff" not in output
    assert "\ufffd" not in output
    assert result.stderr == ""


@pytest.mark.parametrize("target", ["/tmp/index-target", "../index-target"])
def test_flags_staged_symlink_target_after_worktree_becomes_regular_file(
    tmp_path: Path, target: str
) -> None:
    repo = initialize_repo(tmp_path)
    path = repo / "link"
    path.write_text("safe\n", encoding="utf-8")
    git(repo, "add", "link")
    git(repo, "commit", "-m", "add regular file")
    path.unlink()
    path.symlink_to(target)
    git(repo, "add", "link")
    path.unlink()
    path.write_text("safe\n", encoding="utf-8")

    result = audit(repo, "HEAD")

    assert result.returncode == 1
    assert any(
        finding["category"] == "symlink" and finding["source"] == "staged-symlink"
        for finding in json.loads(result.stdout)["findings"]
    )
    assert target not in result.stdout
    assert target not in result.stderr


def test_paths_file_dot_selects_changed_paths_from_repo_root(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "tracked.txt").write_text("safe\n", encoding="utf-8")
    git(repo, "add", "tracked.txt")
    git(repo, "commit", "-m", "add tracked file")
    secret = "api_" + "key = sk-" + "root-selection-" + "D" * 24
    (repo / "tracked.txt").write_text(secret + "\n", encoding="utf-8")
    paths_file = tmp_path / "paths.txt"
    paths_file.write_text(".\n", encoding="utf-8")

    result = audit(repo, "HEAD", "--paths-from", str(paths_file))

    assert result.returncode == 1
    assert any(
        finding["category"] == "credential" and finding["source"] == "worktree-content"
        for finding in json.loads(result.stdout)["findings"]
    )
    assert secret not in result.stdout


@pytest.mark.parametrize(
    "local_path",
    [
        "/" + "etc/ssh/config",
        "/" + "home/private-user/project",
        "/" + "tmp/private-work/project",
        "/" + "opt/private-work/project",
        "/" + "var/private-work/project",
        "/" + "private/var/private-work/project",
        "/" + "workspace/private-work/project",
        "/" + "usr/local/private-work/project",
        "/" + "Applications/PrivateTool.app/Contents",
        "/" + "data/private-work/project",
        "~/" + "Library/private-data",
        "D:\\workspace\\" + "private-data",
        "\\\\fileserver\\share\\" + "private-data",
    ],
)
def test_detects_general_unix_and_windows_absolute_paths(
    tmp_path: Path, local_path: str
) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "change.txt").write_text(local_path + "\n", encoding="utf-8")
    git(repo, "add", "change.txt")
    git(repo, "commit", "-m", "add local reference")

    result = audit(repo)

    assert result.returncode == 1
    assert any(
        finding["category"] == "local-path"
        for finding in json.loads(result.stdout)["findings"]
    )
    assert local_path not in result.stdout


@pytest.mark.parametrize(
    "ordinary_text",
    [
        "docs/guides/setup.md",
        "https://" + "example.com/etc/ssh/config",
        "ordinary slash/containing prose",
        "#!" + "/" + "usr/bin/env bash",
        "#!" + "/" + "usr/bin/env -S python -O",
        "#!" + "/" + "usr/bin/env -i -S python -O",
        "#!" + "/" + "usr/bin/env -iS python -O",
        "#!" + "/" + "usr/bin/env -ivS python -O",
        "#!" + "/" + "usr/bin/env --ignore-environment -- python -I",
        "#!" + "/" + "bin/sh",
        "#!" + "/" + "usr/bin/python3",
        "#!" + "/" + "usr/bin/python3 -I",
        "redirect output to /dev/null",
        "/api/v1/public/resource",
        "/public/v1/resource",
        "/" + "users/123/profile",
    ],
)
def test_does_not_treat_relative_prose_or_urls_as_local_paths(
    tmp_path: Path, ordinary_text: str
) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "change.txt").write_text(ordinary_text + "\n", encoding="utf-8")
    git(repo, "add", "change.txt")
    git(repo, "commit", "-m", "add public reference")

    result = audit(repo)

    assert result.returncode == 0
    assert json.loads(result.stdout)["findings"] == []


@pytest.mark.parametrize(
    "shebang",
    [
        "#!" + "/" + "usr/bin/env -S python /" + "home/private-user/script.py",
        "#!" + "/" + "usr/bin/env -iS python /" + "home/private-user/script.py",
        "#!" + "/" + "usr/bin/env python --config=/" + "Users/private-user/config",
        "#!" + "/" + "usr/bin/python3 /" + "tmp/private-script.py",
        (
            "#!"
            + "/"
            + "usr/bin/env -S python --config='/"
            + "Users/private user/config'"
        ),
        "#!" + "/" + "usr/bin/python3 '/" + "tmp/private script.py'",
    ],
)
def test_shebang_arguments_cannot_hide_local_paths(
    tmp_path: Path, shebang: str
) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "change.txt").write_text(shebang + "\n", encoding="utf-8")
    git(repo, "add", "change.txt")
    git(repo, "commit", "-m", "add unsafe shebang")

    result = audit(repo)

    assert result.returncode == 1
    assert any(
        finding["category"] == "local-path"
        for finding in json.loads(result.stdout)["findings"]
    )
    assert shebang not in result.stdout + result.stderr


def test_does_not_treat_unity_tilde_directory_as_local_path(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    source = repo / "Packages" / "com.example.project" / "Tests~" / "Runtime"
    source.mkdir(parents=True)
    (source / "PublicTests.cs").write_text("public test fixture\n", encoding="utf-8")
    git(
        repo,
        "add",
        "-f",
        "Packages/com.example.project/Tests~/Runtime/PublicTests.cs",
    )
    git(repo, "commit", "-m", "test: add Unity package fixture")

    result = audit(repo)

    assert result.returncode == 0
    assert json.loads(result.stdout)["findings"] == []


@pytest.mark.parametrize(
    "ordinary_relative_path",
    [
        "tests/generated_/nested/file.txt",
        "docs/generated./nested/file.txt",
        "docs/generated-/nested/file.txt",
        "../../tests/fixtures/public.json",
    ],
)
def test_does_not_treat_punctuated_relative_paths_as_absolute(
    tmp_path: Path, ordinary_relative_path: str
) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "change.txt").write_text(ordinary_relative_path + "\n", encoding="utf-8")
    git(repo, "add", "change.txt")
    git(repo, "commit", "-m", "add relative path")

    result = audit(repo)

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["findings"] == []


@pytest.mark.parametrize(
    "public_identifier",
    [
        "RFC-9180",
        "AES-256",
        "CAIP-2",
        "EIP-1559",
        "SHA-256",
        "LICENSE-2",
        "PKCS-8",
        "FIPS-186",
        "NIST-800",
        "SEC-1",
        "SLSA-1",
        "UTF-8",
        "X9-62",
        "ADR-12",
    ],
)
def test_does_not_treat_public_technical_identifiers_as_trackers(
    tmp_path: Path, public_identifier: str
) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "change.txt").write_text(public_identifier + "\n", encoding="utf-8")
    git(repo, "add", "change.txt")
    git(repo, "commit", "-m", "add public standard")

    result = audit(repo)

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["findings"] == []


@pytest.mark.parametrize(
    "tracker_identifier",
    [
        "SEC" + "-8472",
        "AES" + "-999",
        "FIPS" + "-999",
        "EIP" + "-999",
        "SHA" + "-999",
        "SLSA" + "-9",
    ],
)
def test_unknown_numbers_with_public_prefixes_remain_blocking(
    tmp_path: Path, tracker_identifier: str
) -> None:
    repo = initialize_repo(tmp_path)
    (repo / "change.txt").write_text(tracker_identifier + "\n", encoding="utf-8")
    git(repo, "add", "change.txt")
    git(repo, "commit", "-m", "add unknown identifier")

    result = audit(repo)

    assert result.returncode == 1
    assert any(
        finding["category"] == "external-tracker"
        for finding in json.loads(result.stdout)["findings"]
    )
    assert tracker_identifier not in result.stdout + result.stderr


def test_hash_pinned_public_artifact_is_reviewable(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    fixture = repo / "tests" / "fixtures" / "public-fixture.txt"
    fixture.parent.mkdir(parents=True)
    fixture.write_text(
        "api_" + "key = public-fixture-" + "A" * 24 + "\n"
        "http://" + "local" + "host:3000/public-test\n",
        encoding="utf-8",
    )
    manifest = write_public_artifact_manifest(
        repo, "tests/fixtures/public-fixture.txt"
    )

    result = audit(
        repo,
        "HEAD",
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert len(findings) == 1
    assert findings[0]["category"] == "public-artifact"
    assert findings[0]["severity"] == "review"
    assert findings[0]["source"] == "worktree-content"
    assert findings[0].get("path_id")
    assert findings[0]["artifact_id"] == hashlib.sha256(
        fixture.read_bytes()
    ).hexdigest()


def test_hash_pinned_committed_public_artifact_is_reviewable(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    base = git(repo, "rev-parse", "HEAD").stdout.strip()
    fixture = repo / "tests" / "fixtures" / "public-fixture.txt"
    fixture.parent.mkdir(parents=True)
    fixture.write_text(
        "api_" + "key = public-fixture-" + "D" * 24 + "\n",
        encoding="utf-8",
    )
    git(repo, "add", "tests/fixtures/public-fixture.txt")
    git(repo, "commit", "-m", "add public fixture")
    manifest = write_public_artifact_manifest(
        repo, "tests/fixtures/public-fixture.txt"
    )

    result = audit(
        repo,
        base,
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert len(findings) == 1
    assert findings[0]["category"] == "public-artifact"
    assert findings[0]["source"] == "committed-content"
    assert findings[0].get("commit")
    assert findings[0].get("path_id")
    assert findings[0]["artifact_id"] == hashlib.sha256(
        fixture.read_bytes()
    ).hexdigest()


def test_public_artifact_manifest_cannot_approve_private_key(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    fixture = repo / "tests" / "fixtures" / "public-fixture.txt"
    fixture.parent.mkdir(parents=True)
    marker = "-----BEGIN " + "PRIVATE KEY-----"
    fixture.write_text(marker + "\npublic fixture\n", encoding="utf-8")
    manifest = write_public_artifact_manifest(
        repo, "tests/fixtures/public-fixture.txt"
    )

    result = audit(
        repo,
        "HEAD",
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 1
    assert any(
        finding["category"] == "private-key"
        and finding["severity"] == "blocking"
        for finding in json.loads(result.stdout)["findings"]
    )
    assert marker not in result.stdout + result.stderr


def test_public_artifact_manifest_does_not_approve_repository_link(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    fixture = repo / "tests" / "fixtures" / "public-source.txt"
    fixture.parent.mkdir(parents=True)
    fixture.write_text(
        "https://" + "github.com/example/upstream\n",
        encoding="utf-8",
    )
    manifest = write_public_artifact_manifest(repo, "tests/fixtures/public-source.txt")

    result = audit(
        repo,
        "HEAD",
        "--profile",
        "locked-down",
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert any(
        finding["category"] == "repository-link"
        and finding["severity"] == "blocking"
        for finding in findings
    )
    assert not any(
        finding["category"] == "public-artifact" for finding in findings
    )


def test_public_artifact_manifest_hash_mismatch_is_incomplete(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    fixture = repo / "tests" / "fixtures" / "public-fixture.txt"
    fixture.parent.mkdir(parents=True)
    fixture.write_text("public fixture\n", encoding="utf-8")
    manifest = write_public_artifact_manifest(
        repo, "tests/fixtures/public-fixture.txt"
    )
    fixture.write_text(
        "api_" + "key = changed-after-review-" + "B" * 24 + "\n",
        encoding="utf-8",
    )

    result = audit(
        repo,
        "HEAD",
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["complete"] is False
    assert payload["findings"] == []
    assert "changed-after-review" not in result.stdout + result.stderr


def test_manifest_does_not_approve_different_intermediate_commit_bytes(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    base = git(repo, "rev-parse", "HEAD").stdout.strip()
    fixture = repo / "tests" / "fixtures" / "public-fixture.txt"
    fixture.parent.mkdir(parents=True)
    secret = "api_" + "key = intermediate-" + "C" * 24
    fixture.write_text(secret + "\n", encoding="utf-8")
    git(repo, "add", "tests/fixtures/public-fixture.txt")
    git(repo, "commit", "-m", "add temporary fixture")
    fixture.write_text("reviewed public fixture\n", encoding="utf-8")
    git(repo, "add", "tests/fixtures/public-fixture.txt")
    git(repo, "commit", "-m", "replace fixture")
    manifest = write_public_artifact_manifest(
        repo, "tests/fixtures/public-fixture.txt"
    )

    result = audit(
        repo,
        base,
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["complete"] is False
    assert payload["findings"] == []
    assert secret not in result.stdout + result.stderr


def test_manifest_rejects_intermediate_safe_symlink_blob_drift(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    base = git(repo, "rev-parse", "HEAD").stdout.strip()
    fixture = repo / "tests" / "fixtures" / "public-fixture.txt"
    fixture.parent.mkdir(parents=True)
    fixture.symlink_to("target.txt")
    git(repo, "add", "tests/fixtures/public-fixture.txt")
    git(repo, "commit", "-m", "add temporary fixture symlink")
    fixture.unlink()
    fixture.write_text("reviewed public fixture\n", encoding="utf-8")
    git(repo, "add", "tests/fixtures/public-fixture.txt")
    git(repo, "commit", "-m", "replace fixture symlink")
    manifest = write_public_artifact_manifest(
        repo, "tests/fixtures/public-fixture.txt"
    )

    result = audit(
        repo,
        base,
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["complete"] is False
    assert payload["findings"] == []


def test_manifest_rejects_intermediate_safe_symlink_mode_change(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    base = git(repo, "rev-parse", "HEAD").stdout.strip()
    fixture = repo / "tests" / "fixtures" / "public-fixture.txt"
    fixture.parent.mkdir(parents=True)
    fixture.symlink_to("target.txt")
    git(repo, "add", "tests/fixtures/public-fixture.txt")
    git(repo, "commit", "-m", "add temporary fixture symlink")
    symlink_commit = git(repo, "rev-parse", "HEAD").stdout.strip()
    fixture.unlink()
    fixture.write_text("target.txt", encoding="utf-8")
    git(repo, "add", "tests/fixtures/public-fixture.txt")
    git(repo, "commit", "-m", "replace fixture symlink")
    manifest = write_public_artifact_manifest(
        repo, "tests/fixtures/public-fixture.txt"
    )
    symlink_blob = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "show",
            f"{symlink_commit}:tests/fixtures/public-fixture.txt",
        ],
        check=True,
        capture_output=True,
    ).stdout
    manifest_digest = manifest.read_text(encoding="utf-8").split()[0]
    assert hashlib.sha256(symlink_blob).hexdigest() == manifest_digest

    result = audit(
        repo,
        base,
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["complete"] is False
    assert payload["findings"] == []


def test_manifest_rejects_intermediate_binary_blob_drift(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    base = git(repo, "rev-parse", "HEAD").stdout.strip()
    fixture = repo / "tests" / "fixtures" / "public-fixture.txt"
    fixture.parent.mkdir(parents=True)
    fixture.write_bytes(b"\x00intermediate binary fixture")
    git(repo, "add", "tests/fixtures/public-fixture.txt")
    git(repo, "commit", "-m", "add temporary binary fixture")
    fixture.write_text("reviewed public fixture\n", encoding="utf-8")
    git(repo, "add", "tests/fixtures/public-fixture.txt")
    git(repo, "commit", "-m", "replace binary fixture")
    manifest = write_public_artifact_manifest(
        repo, "tests/fixtures/public-fixture.txt"
    )

    result = audit(
        repo,
        base,
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["complete"] is False
    assert payload["findings"] == []


def test_manifest_digest_drift_in_staged_blob_is_incomplete(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    fixture = repo / "tests" / "fixtures" / "public-fixture.txt"
    fixture.parent.mkdir(parents=True)
    fixture.write_text("reviewed public fixture\n", encoding="utf-8")
    git(repo, "add", "tests/fixtures/public-fixture.txt")
    git(repo, "commit", "-m", "add public fixture")
    manifest = write_public_artifact_manifest(
        repo, "tests/fixtures/public-fixture.txt"
    )
    fixture.write_text("staged drift\n", encoding="utf-8")
    git(repo, "add", "tests/fixtures/public-fixture.txt")
    fixture.write_text("reviewed public fixture\n", encoding="utf-8")
    manifest_digest = manifest.read_text(encoding="utf-8").split()[0]
    staged_blob = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "show",
            ":tests/fixtures/public-fixture.txt",
        ],
        check=True,
        capture_output=True,
    ).stdout
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == manifest_digest
    assert hashlib.sha256(staged_blob).hexdigest() != manifest_digest

    result = audit(
        repo,
        "HEAD",
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["complete"] is False
    assert payload["findings"] == []


def test_manifest_digest_drift_in_staged_safe_symlink_is_incomplete(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    fixture = repo / "tests" / "fixtures" / "public-fixture.txt"
    fixture.parent.mkdir(parents=True)
    fixture.write_text("reviewed public fixture\n", encoding="utf-8")
    git(repo, "add", "tests/fixtures/public-fixture.txt")
    git(repo, "commit", "-m", "add public fixture")
    manifest = write_public_artifact_manifest(
        repo, "tests/fixtures/public-fixture.txt"
    )
    fixture.unlink()
    fixture.symlink_to("target.txt")
    git(repo, "add", "tests/fixtures/public-fixture.txt")
    fixture.unlink()
    fixture.write_text("reviewed public fixture\n", encoding="utf-8")
    manifest_digest = manifest.read_text(encoding="utf-8").split()[0]
    staged_blob = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "show",
            ":tests/fixtures/public-fixture.txt",
        ],
        check=True,
        capture_output=True,
    ).stdout
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == manifest_digest
    assert hashlib.sha256(staged_blob).hexdigest() != manifest_digest

    result = audit(
        repo,
        "HEAD",
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["complete"] is False
    assert payload["findings"] == []


def test_manifest_rejects_staged_safe_symlink_mode_change(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    fixture = repo / "tests" / "fixtures" / "public-fixture.txt"
    fixture.parent.mkdir(parents=True)
    fixture.write_text("target.txt", encoding="utf-8")
    git(repo, "add", "tests/fixtures/public-fixture.txt")
    git(repo, "commit", "-m", "add public fixture")
    manifest = write_public_artifact_manifest(
        repo, "tests/fixtures/public-fixture.txt"
    )
    fixture.unlink()
    fixture.symlink_to("target.txt")
    git(repo, "add", "tests/fixtures/public-fixture.txt")
    fixture.unlink()
    fixture.write_text("target.txt", encoding="utf-8")
    manifest_digest = manifest.read_text(encoding="utf-8").split()[0]
    staged_blob = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "show",
            ":tests/fixtures/public-fixture.txt",
        ],
        check=True,
        capture_output=True,
    ).stdout
    assert hashlib.sha256(staged_blob).hexdigest() == manifest_digest

    result = audit(
        repo,
        "HEAD",
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["complete"] is False
    assert payload["findings"] == []


@pytest.mark.parametrize(
    "credential_text",
    [
        "AK" + "IA" + "A" * 16,
        "gh" + "p_" + "A" * 36,
        "Bearer " + "A" * 24,
    ],
)
def test_public_artifact_manifest_cannot_approve_token_shapes(
    tmp_path: Path, credential_text: str
) -> None:
    repo = initialize_repo(tmp_path)
    fixture = repo / "tests" / "fixtures" / "public-fixture.txt"
    fixture.parent.mkdir(parents=True)
    fixture.write_text(credential_text + "\n", encoding="utf-8")
    manifest = write_public_artifact_manifest(
        repo, "tests/fixtures/public-fixture.txt"
    )

    result = audit(
        repo,
        "HEAD",
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 1
    findings = json.loads(result.stdout)["findings"]
    assert any(
        finding["category"] == "credential"
        and finding["severity"] == "blocking"
        for finding in findings
    )
    assert credential_text not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "manifest_row",
    [
        "not-a-digest  tests/fixtures/public-fixture.txt",
        "0" * 64 + " tests/fixtures/public-fixture.txt",
        "0" * 64 + "  /tests/fixtures/public-fixture.txt",
        "0" * 64 + "  ../public-fixture.txt",
        "0" * 64 + "  tests/../public-fixture.txt",
        "0" * 64 + "  tests/fixtures/public\0fixture.txt",
    ],
)
def test_public_artifact_manifest_rejects_malformed_or_unsafe_rows(
    tmp_path: Path, manifest_row: str
) -> None:
    repo = initialize_repo(tmp_path)
    manifest = repo / ".git" / "public-pr-public-artifacts.txt"
    manifest.write_text(manifest_row + "\n", encoding="utf-8")

    result = audit(
        repo,
        "HEAD",
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 2
    assert json.loads(result.stdout)["complete"] is False


def test_public_artifact_manifest_rejects_duplicate_paths(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    fixture = repo / "tests" / "fixtures" / "public-fixture.txt"
    fixture.parent.mkdir(parents=True)
    fixture.write_text("public fixture\n", encoding="utf-8")
    digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
    manifest = repo / ".git" / "public-pr-public-artifacts.txt"
    row = f"{digest}  tests/fixtures/public-fixture.txt\n"
    manifest.write_text(row + row, encoding="utf-8")

    result = audit(
        repo,
        "HEAD",
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 2
    assert json.loads(result.stdout)["complete"] is False


def test_public_artifact_manifest_rejects_symlink_paths(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    fixtures = repo / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    target = fixtures / "target.txt"
    target.write_text("public fixture\n", encoding="utf-8")
    link = fixtures / "public-fixture.txt"
    link.symlink_to("target.txt")
    digest = hashlib.sha256(link.read_bytes()).hexdigest()
    manifest = repo / ".git" / "public-pr-public-artifacts.txt"
    manifest.write_text(
        f"{digest}  tests/fixtures/public-fixture.txt\n", encoding="utf-8"
    )

    result = audit(
        repo,
        "HEAD",
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 2
    assert json.loads(result.stdout)["complete"] is False


def test_public_artifact_manifest_rejects_runtime_source_paths(tmp_path: Path) -> None:
    repo = initialize_repo(tmp_path)
    source = repo / "src" / "runtime-config.txt"
    source.parent.mkdir()
    source.write_text(
        "api_" + "key = runtime-value-" + "A" * 24 + "\n",
        encoding="utf-8",
    )
    manifest = write_public_artifact_manifest(repo, "src/runtime-config.txt")

    result = audit(
        repo,
        "HEAD",
        "--public-artifacts-from",
        str(manifest),
    )

    assert result.returncode == 2
    assert json.loads(result.stdout)["complete"] is False


def test_flags_binary_introduced_only_by_merge_conflict_resolution(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    asset = repo / "asset.bin"
    asset.write_text("base\n", encoding="utf-8")
    git(repo, "add", "asset.bin")
    git(repo, "commit", "-m", "add merge base")
    base = git(repo, "rev-parse", "HEAD").stdout.strip()

    git(repo, "checkout", "-b", "feature")
    asset.write_text("feature\n", encoding="utf-8")
    git(repo, "add", "asset.bin")
    git(repo, "commit", "-m", "change asset on feature")

    git(repo, "checkout", "main")
    asset.write_text("main\n", encoding="utf-8")
    git(repo, "add", "asset.bin")
    git(repo, "commit", "-m", "change asset on main")
    merge = subprocess.run(
        ["git", "-C", str(repo), "merge", "--no-ff", "feature"],
        text=True,
        capture_output=True,
    )
    assert merge.returncode == 1
    asset.write_bytes(b"\x00\x01\x02merge-result")
    git(repo, "add", "asset.bin")
    git(repo, "commit", "-m", "resolve merge with binary asset")

    result = audit(repo, base)

    assert result.returncode == 1
    binary_findings = [
        finding
        for finding in json.loads(result.stdout)["findings"]
        if finding["category"] == "binary" and finding["source"] == "committed-binary"
    ]
    assert len(binary_findings) == 1


def test_flags_binary_from_root_commit_when_base_is_unrelated(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Public Contributor")
    git(repo, "config", "user.email", "12345+public@users.noreply.github.com")
    git(repo, "config", "commit.gpgsign", "false")
    (repo / "asset.bin").write_bytes(b"\x00\x01\x02root-binary")
    git(repo, "add", "asset.bin")
    git(repo, "commit", "-m", "root binary")

    git(repo, "checkout", "--orphan", "unrelated")
    git(repo, "rm", "-f", "asset.bin")
    (repo / "unrelated.txt").write_text("safe\n", encoding="utf-8")
    git(repo, "add", "unrelated.txt")
    git(repo, "commit", "-m", "unrelated base")
    git(repo, "checkout", "main")

    result = audit(repo, "unrelated")

    assert result.returncode == 1
    assert any(
        finding["category"] == "binary" and finding["source"] == "committed-binary"
        for finding in json.loads(result.stdout)["findings"]
    )


def test_merge_does_not_reclassify_base_content_retained_from_one_parent(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    secret = "api_" + "key = sk-" + "base-only-" + "B" * 24
    private_file = repo / "private.txt"
    private_file.write_text(secret + "\n", encoding="utf-8")
    git(repo, "add", "private.txt")
    git(repo, "commit", "-m", "add base content")
    base = git(repo, "rev-parse", "HEAD").stdout.strip()

    git(repo, "checkout", "-b", "delete-side")
    git(repo, "rm", "private.txt")
    git(repo, "commit", "-m", "delete private file")

    git(repo, "checkout", "main")
    private_file.write_text(secret + "\nsafe retained note\n", encoding="utf-8")
    git(repo, "add", "private.txt")
    git(repo, "commit", "-m", "add safe retained note")
    merge = subprocess.run(
        ["git", "-C", str(repo), "merge", "--no-ff", "delete-side"],
        text=True,
        capture_output=True,
    )
    assert merge.returncode == 1
    private_file.write_text(secret + "\nsafe retained note\n", encoding="utf-8")
    git(repo, "add", "private.txt")
    git(repo, "commit", "-m", "retain main version")

    result = audit(repo, base)

    assert result.returncode == 0
    assert json.loads(result.stdout)["findings"] == []
    assert secret not in result.stdout


def test_merge_does_not_cross_match_retained_lines_between_paths(
    tmp_path: Path,
) -> None:
    repo = initialize_repo(tmp_path)
    secret = "api_" + "key = sk-" + "retained-cross-path-" + "B" * 24
    first = repo / "first.txt"
    second = repo / "second.txt"
    first.write_text(secret + "\n", encoding="utf-8")
    second.write_text(secret + "\n", encoding="utf-8")
    git(repo, "add", "first.txt", "second.txt")
    git(repo, "commit", "-m", "add base content in two paths")
    base = git(repo, "rev-parse", "HEAD").stdout.strip()

    git(repo, "checkout", "-b", "delete-first")
    first.write_text("safe first\n", encoding="utf-8")
    git(repo, "add", "first.txt")
    git(repo, "commit", "-m", "delete first base content")

    git(repo, "checkout", "main")
    second.write_text("safe second\n", encoding="utf-8")
    git(repo, "add", "second.txt")
    git(repo, "commit", "-m", "delete second base content")
    merge = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "merge",
            "--no-ff",
            "--no-commit",
            "delete-first",
        ],
        text=True,
        capture_output=True,
    )
    assert merge.returncode == 0
    first.write_text(secret + "\n", encoding="utf-8")
    second.write_text(secret + "\n", encoding="utf-8")
    git(repo, "add", "first.txt", "second.txt")
    git(repo, "commit", "-m", "retain both parent versions")

    result = audit(repo, base)

    assert result.returncode == 0
    assert json.loads(result.stdout)["findings"] == []
    assert secret not in result.stdout


def _test_case(
    name: str,
    function: Callable[..., None],
    parameter_names: tuple[str, ...],
    values: Any,
    case_index: int | None,
) -> unittest.FunctionTestCase:
    if parameter_names:
        parameter_values = (values,) if len(parameter_names) == 1 else tuple(values)
        parameters = dict(zip(parameter_names, parameter_values))
    else:
        parameters = {}

    def run() -> None:
        arguments = dict(parameters)
        if "tmp_path" in inspect.signature(function).parameters:
            with tempfile.TemporaryDirectory() as temporary_directory:
                arguments["tmp_path"] = Path(temporary_directory)
                function(**arguments)
        else:
            function(**arguments)

    suffix = "" if case_index is None else f"[{case_index}]"
    run.__name__ = f"{name}{suffix}"
    return unittest.FunctionTestCase(run, description=run.__name__)


def load_tests(
    loader: unittest.TestLoader,
    standard_tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    del loader, standard_tests, pattern
    suite = unittest.TestSuite()
    for name, function in list(globals().items()):
        if not name.startswith("test_") or not callable(function):
            continue
        parameter_cases = getattr(function, "_parameter_cases", None)
        if parameter_cases is None:
            suite.addTest(_test_case(name, function, (), (), None))
            continue
        parameter_names, cases = parameter_cases
        for case_index, values in enumerate(cases):
            suite.addTest(
                _test_case(name, function, parameter_names, values, case_index)
            )
    return suite
