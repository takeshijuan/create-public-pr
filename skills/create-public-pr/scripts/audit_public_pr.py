#!/usr/bin/env python3
"""Audit a proposed public pull request for privacy-sensitive material."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shlex
import subprocess
from collections.abc import Callable, Iterable
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


class AuditError(Exception):
    """Raised when the scanner cannot prove that its audit is complete."""


Finding = dict[str, str]


PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")
CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?key|client[_-]?secret|password|passwd|secret|token|authorization)\b"
    r"\s*[:=]\s*['\"]?[^\s'\"<>]{8,}"
)
CREDENTIAL_TOKEN_RE = re.compile(
    r"(?:\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36,255}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b|(?i:\bBearer\s+[A-Za-z0-9._~+/-]{20,}))"
)
CREDENTIAL_URL_RE = re.compile(r"(?i)[A-Z][A-Z0-9+.-]*://[^\s/:@]+:[^\s/@]+@[^\s/]+")
COLLABORATION_URL_RE = re.compile(
    r"(?i)https?://[^\s/]*(?:slack\.com|notion\.so|docs\.google\.com|"
    r"drive\.google\.com|linear\.app|discord\.com|teams\.microsoft\.com|"
    r"clickup\.com|atlassian\.net)(?:/[^\s]*)?"
)
LOCAL_HOST_RE = re.compile(r"(?i)\b(?:localhost|[a-z0-9.-]+\.(?:local|internal))\b")
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(\[?(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"[0-9A-Fa-f]{0,4}\]?)(?![0-9A-Fa-f:])"
)
HEX_COLON_RUN_RE = re.compile(
    r"(?<![0-9A-Fa-f:])([0-9A-Fa-f:]+)"
)
WORKFLOW_COMMAND_PREFIX_RE = re.compile(
    r":"
    r":"
    r"(?:add-mask|add-matcher|add-path|debug|echo|endgroup|error|group|notice|"
    r"remove-matcher|save-state|set-env|set-output|stop-commands|warning)"
    r"(?: [^:\r\n]*)?"
    r":"
    r":",
    re.IGNORECASE,
)
WORKFLOW_STOP_COMMAND_PREFIX_RE = re.compile(
    r":" r":" r"stop-commands" r":" r":",
    re.IGNORECASE,
)
WORKFLOW_UNPAIRED_RESUME_TOKEN_RE = re.compile(
    r":" r":" r"[G-Zg-z_$-][A-Za-z0-9_${}-]*" r":" r":",
)
LOCAL_PATH_RE = re.compile(
    r"(?:(?i:file):///(?:[^\s/]+/)+[^\s/]+|"
    r"(?<![A-Za-z0-9_.~:/\\-])/(?:Users|(?i:home|root|tmp|private|var|etc|"
    r"opt|usr|bin|sbin|applications|data|workspace|workspaces|library|"
    r"volumes|mnt|srv))"
    r"/(?:[^\s/]+/)*[^\s/]+|"
    r"(?<![A-Za-z0-9])[A-Za-z]:[\\/](?:[^\s\\/]+[\\/])*[^\s\\/]+|"
    r"(?<!\\)\\\\[^\s\\]+\\[^\s\\]+(?:\\[^\s\\]+)+|"
    r"(?<![A-Za-z0-9_.-])~/[^\s]+)"
)
SAFE_SHEBANG_RE = re.compile(
    r"/(?:usr/)?bin/(?:bash|dash|ksh|node|perl|python[0-9.]*|ruby|sh|zsh)"
)
SAFE_ENV_INTERPRETER_RE = re.compile(
    r"(?:bash|dash|ksh|node|perl|python[0-9.]*|ruby|sh|zsh)"
)
SAFE_ENV_PREFIX_OPTIONS = frozenset(
    {"-0", "--debug", "-i", "--ignore-environment", "--null", "-v"}
)
SAFE_ENV_SHORT_PREFIX_RE = re.compile(r"-[0iv]+")
SAFE_ENV_SPLIT_PREFIX_RE = re.compile(r"-[0iv]*S")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b")
TRACKER_RE = re.compile(
    r"\b([A-Z][A-Z0" + r"-9]{1,9})" + r"-[1-9]\d*\b"
)
PUBLIC_IDENTIFIER_NUMBERS = {
    "AES": frozenset({128, 192, 256}),
    "CAIP": frozenset({2}),
    "EIP": frozenset({1559}),
    "FIPS": frozenset({140, 180, 186, 197, 198, 202, 203, 204, 205, 206}),
    "LICENSE": frozenset({2}),
    "NIST": frozenset({800}),
    "PKCS": frozenset(range(1, 16)),
    "SEC": frozenset({1, 2}),
    "SHA": frozenset({1, 224, 256, 384, 512}),
    "SLSA": frozenset({1, 2, 3, 4}),
    "UTF": frozenset({8, 16, 32}),
    "X9": frozenset({62}),
}


def private_ipv6_candidate(candidate: str) -> bool:
    candidates = [candidate]
    delimiter = ":" + ":"
    if candidate.endswith(delimiter):
        candidates.append(candidate[:-2])
    if candidate.startswith(delimiter):
        candidates.append(candidate[2:])
    for value in candidates:
        try:
            address = ipaddress.ip_address(value.strip("[]"))
        except ValueError:
            continue
        if address.is_private or address.is_loopback or address.is_link_local:
            return True
    return False


def hex_colon_run_contains_private_ipv6(run: str) -> bool:
    delimiter = ":" + ":"
    split = run.find(delimiter)
    while split != -1 and split <= 45:
        if private_ipv6_candidate(run[:split]):
            return True
        split = run.find(delimiter, split + 1)
    return False


def workflow_token_contains_private_ipv6(token: str) -> bool:
    if any(
        private_ipv6_candidate(match.group(1)) for match in IPV6_RE.finditer(token)
    ):
        return True
    return any(
        hex_colon_run_contains_private_ipv6(match.group(1))
        for match in HEX_COLON_RUN_RE.finditer(token)
    )


def parse_workflow_expression(text: str, start: int) -> tuple[int | None, int]:
    cursor = start + 3
    in_single_quote = False
    while cursor < len(text):
        character = text[cursor]
        if character in {"\r", "\n"}:
            return None, cursor
        if character == "'":
            if (
                in_single_quote
                and cursor + 1 < len(text)
                and text[cursor + 1] == "'"
            ):
                cursor += 2
                continue
            in_single_quote = not in_single_quote
            cursor += 1
            continue
        if not in_single_quote and text.startswith("}}", cursor):
            return cursor + 2, cursor + 2
        cursor += 1
    return None, cursor


def parse_workflow_token(text: str, start: int) -> tuple[str | None, int]:
    cursor = start
    while cursor < len(text):
        if text.startswith("${{", cursor):
            expression_end, failure_end = parse_workflow_expression(text, cursor)
            if expression_end is None:
                return None, failure_end
            cursor = expression_end
            continue
        character = text[cursor]
        if character == ":" or character.isspace() or character in {'"', "'"}:
            break
        cursor += 1
    if cursor == start:
        return None, cursor
    return text[start:cursor], cursor


def workflow_stop_commands(
    text: str,
) -> tuple[tuple[str, tuple[int, int]], ...]:
    commands: list[tuple[str, tuple[int, int]]] = []
    cursor = 0
    while True:
        match = WORKFLOW_STOP_COMMAND_PREFIX_RE.search(text, cursor)
        if match is None:
            break
        token, end = parse_workflow_token(text, match.end())
        if token is None:
            cursor = max(match.end(), end)
            continue
        commands.append((token, (match.start(), end)))
        cursor = max(match.end(), end)
    return tuple(commands)


def workflow_markers(text: str) -> tuple[tuple[str, tuple[int, int]], ...]:
    delimiter = ":" + ":"
    markers: list[tuple[str, tuple[int, int]]] = []
    cursor = 0
    while True:
        start = text.find(delimiter, cursor)
        if start == -1:
            break
        token, token_end = parse_workflow_token(
            text, start + len(delimiter)
        )
        if token is not None and text.startswith(delimiter, token_end):
            end = token_end + len(delimiter)
            markers.append((token, (start, end)))
            cursor = end
            continue
        cursor = max(start + len(delimiter), token_end)
    return tuple(markers)


def extract_workflow_stop_tokens(text: str) -> frozenset[str]:
    first_stop_by_token: dict[str, int] = {}
    for token, (start, _) in workflow_stop_commands(text):
        first_stop_by_token.setdefault(token, start)
    first_marker_by_token: dict[str, int] = {}
    for token, (start, _) in workflow_markers(text):
        first_marker_by_token.setdefault(token, start)
    return frozenset(
        token
        for token, stop_position in first_stop_by_token.items()
        if stop_position < first_marker_by_token.get(token, -1)
        and not private_ipv6_candidate(":" + ":" + token + ":" + ":")
        and not workflow_token_contains_private_ipv6(token)
    )


PUBLIC_ARTIFACT_CATEGORIES = frozenset({"credential", "private-host"})
PUBLIC_ARTIFACT_REGULAR_MODES = frozenset({b"100644", b"100755"})
PUBLIC_ARTIFACT_PATH_COMPONENTS = frozenset(
    {
        "__fixtures__",
        "__tests__",
        "fixture",
        "fixtures",
        "spec",
        "specs",
        "test",
        "test-data",
        "test_data",
        "testdata",
        "tests",
    }
)
REPOSITORY_URL_RE = re.compile(
    r"(?i)(?:https?|ssh|git)://(?:[^\s/@]+@)?(?:www\.)?"
    r"(github\.com|gitlab\.com|bitbucket\.org)/"
    r"([A-Z0-9_.-]+)/([A-Z0-9_.-]+)"
)
REPOSITORY_SCP_RE = re.compile(
    r"(?i)\bgit@(github\.com|gitlab\.com|bitbucket\.org):"
    r"([A-Z0-9_.-]+)/([A-Z0-9_.-]+)"
)


def path_id(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8", "surrogateescape")).hexdigest()[:12]


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            capture_output=True,
        )
    except UnicodeError as exc:
        raise AuditError from exc


def git_bytes(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
    )


def validate_repository(repo_arg: str) -> Path:
    repo = Path(repo_arg)
    if not repo.is_dir():
        raise AuditError
    try:
        inside = git(repo, "rev-parse", "--is-inside-work-tree").stdout.strip()
        top_level = Path(
            git(repo, "rev-parse", "--show-toplevel").stdout.strip()
        ).resolve(strict=True)
        repo = repo.resolve(strict=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AuditError from exc
    if inside != "true" or repo != top_level:
        raise AuditError
    return repo


def validate_base(repo: Path, base: str) -> str:
    try:
        git(repo, "rev-parse", "--verify", f"{base}^{{commit}}")
        git(repo, "rev-parse", "--verify", "HEAD^{commit}")
        branch = git(repo, "symbolic-ref", "--quiet", "--short", "HEAD").stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AuditError from exc
    if not branch:
        raise AuditError
    return branch


def repository_identity(url: str) -> tuple[str, str, str] | None:
    url = url.strip()
    if not url:
        return None
    if "://" in url:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        parts = parsed.path.strip("/").split("/")
    else:
        match = re.match(r"(?:[^@]+@)?([^:]+):(.+)", url)
        if not match:
            return None
        host = match.group(1).lower()
        parts = match.group(2).strip("/").split("/")
    if len(parts) < 2:
        return None
    owner, name = parts[0].lower(), parts[1].lower()
    if name.endswith(".git"):
        name = name[:-4]
    return host, owner, name


def current_repository_identity(repo: Path) -> tuple[str, str, str] | None:
    try:
        remotes = git(repo, "remote").stdout.splitlines()
        if not remotes:
            return None
        remote = "origin" if "origin" in remotes else remotes[0]
        return repository_identity(git(repo, "remote", "get-url", remote).stdout)
    except (OSError, ValueError, UnicodeError, subprocess.CalledProcessError) as exc:
        raise AuditError from exc


def severity_for(category: str, profile: str) -> str:
    if category in {"identity", "binary", "public-artifact"}:
        return "review"
    if category == "repository-link" and profile == "community":
        return "review"
    return "blocking"


def safe_shebang(text: str) -> bool:
    stripped = text.strip()
    if not stripped.startswith("#!"):
        return False
    try:
        command = shlex.split(stripped[2:], posix=True)
    except ValueError:
        return False
    if not command:
        return False
    executable, *arguments = command
    if executable == "/usr/bin/env":
        while arguments:
            option = arguments[0]
            if (
                option in SAFE_ENV_PREFIX_OPTIONS
                or SAFE_ENV_SHORT_PREFIX_RE.fullmatch(option) is not None
            ):
                arguments = arguments[1:]
                continue
            if SAFE_ENV_SPLIT_PREFIX_RE.fullmatch(option) is not None:
                arguments = arguments[1:]
            break
        if arguments and arguments[0] == "--":
            arguments = arguments[1:]
        if not arguments:
            return False
        interpreter, *arguments = arguments
        if SAFE_ENV_INTERPRETER_RE.fullmatch(interpreter) is None:
            return False
    elif SAFE_SHEBANG_RE.fullmatch(executable) is None:
        return False
    return LOCAL_PATH_RE.search(" ".join(arguments)) is None


def make_finding(
    category: str,
    profile: str,
    source: str,
    *,
    commit: str | None = None,
    path: str | None = None,
    artifact_id: str | None = None,
) -> Finding:
    finding = {
        "category": category,
        "severity": severity_for(category, profile),
        "source": source,
    }
    if commit:
        finding["commit"] = commit[:12]
    if path:
        finding["path_id"] = path_id(path)
    if artifact_id:
        finding["artifact_id"] = artifact_id
    return finding


def scan_text(
    text: str,
    *,
    profile: str,
    source: str,
    repo_identity: tuple[str, str, str] | None,
    commit: str | None = None,
    path: str | None = None,
    known_workflow_stop_tokens: frozenset[str] = frozenset(),
) -> list[Finding]:
    categories: set[str] = set()
    if PRIVATE_KEY_RE.search(text):
        categories.add("private-key")
    if CREDENTIAL_RE.search(text) or CREDENTIAL_TOKEN_RE.search(text):
        categories.add("credential")
    if CREDENTIAL_URL_RE.search(text):
        categories.add("credential-url")
    if COLLABORATION_URL_RE.search(text):
        categories.add("collaboration-url")
    if LOCAL_HOST_RE.search(text):
        categories.add("private-host")
    for match in IP_RE.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if address.is_private or address.is_loopback or address.is_link_local:
            categories.add("private-host")
    workflow_command_spans = tuple(
        match.span() for match in WORKFLOW_COMMAND_PREFIX_RE.finditer(text)
    )
    workflow_stop_matches = workflow_stop_commands(text)
    workflow_stop_spans = tuple(
        span
        for token, span in workflow_stop_matches
        if not workflow_token_contains_private_ipv6(token)
    )
    stop_tokens = set(known_workflow_stop_tokens)
    stop_tokens.update(extract_workflow_stop_tokens(text))
    workflow_resume_spans = tuple(
        span for token, span in workflow_markers(text) if token in stop_tokens
    )
    workflow_unpaired_resume_spans = tuple(
        match.span()
        for match in WORKFLOW_UNPAIRED_RESUME_TOKEN_RE.finditer(text)
    )
    workflow_spans: list[tuple[int, int]] = []
    for start, end in sorted(
        workflow_command_spans
        + workflow_stop_spans
        + workflow_resume_spans
        + workflow_unpaired_resume_spans
    ):
        if workflow_spans and start <= workflow_spans[-1][1]:
            previous_start, previous_end = workflow_spans[-1]
            workflow_spans[-1] = (previous_start, max(previous_end, end))
        else:
            workflow_spans.append((start, end))

    def evaluate_ipv6_matches(
        matches: Iterable[re.Match[str]],
        is_private: Callable[[str], bool] = private_ipv6_candidate,
    ) -> None:
        workflow_span_index = 0
        for match in matches:
            start, end = match.span(1)
            while (
                workflow_span_index < len(workflow_spans)
                and workflow_spans[workflow_span_index][1] <= start
            ):
                workflow_span_index += 1
            if (
                workflow_span_index < len(workflow_spans)
                and workflow_spans[workflow_span_index][0] <= start
                and end <= workflow_spans[workflow_span_index][1]
            ):
                continue
            if is_private(match.group(1)):
                categories.add("private-host")

    evaluate_ipv6_matches(IPV6_RE.finditer(text))
    evaluate_ipv6_matches(
        HEX_COLON_RUN_RE.finditer(text),
        hex_colon_run_contains_private_ipv6,
    )
    ipv6_text_parts: list[str] = []
    cursor = 0
    for start, end in workflow_spans:
        ipv6_text_parts.append(text[cursor:start])
        ipv6_text_parts.append(" " * (end - start))
        cursor = end
    ipv6_text_parts.append(text[cursor:])
    ipv6_text = "".join(ipv6_text_parts)
    evaluate_ipv6_matches(IPV6_RE.finditer(ipv6_text))
    evaluate_ipv6_matches(
        HEX_COLON_RUN_RE.finditer(ipv6_text),
        hex_colon_run_contains_private_ipv6,
    )
    if not safe_shebang(text) and LOCAL_PATH_RE.search(text):
        categories.add("local-path")
    for match in EMAIL_RE.finditer(text):
        address = match.group(0).lower()
        domain = match.group(1).lower()
        if address in {
            "git@github.com",
            "git@gitlab.com",
            "git@bitbucket.org",
        }:
            continue
        if address.endswith("@users.noreply.github.com"):
            continue
        if domain in {"example.com", "example.net", "example.org"}:
            continue
        if domain.endswith((".example", ".invalid", ".test")):
            continue
        categories.add("email")
    if any(not public_identifier(match) for match in TRACKER_RE.finditer(text)):
        categories.add("external-tracker")
    for match in [
        *REPOSITORY_URL_RE.finditer(text),
        *REPOSITORY_SCP_RE.finditer(text),
    ]:
        linked = (
            match.group(1).lower(),
            match.group(2).lower(),
            match.group(3).lower().removesuffix(".git"),
        )
        if linked != repo_identity:
            categories.add("repository-link")
    return [
        make_finding(
            category,
            profile,
            source,
            commit=commit,
            path=path,
        )
        for category in sorted(categories)
    ]


def public_identifier(match: re.Match[str]) -> bool:
    prefix = match.group(1)
    number = int(match.group(0).rsplit("-", 1)[1])
    if prefix in {"ADR", "RFC"}:
        return True
    return number in PUBLIC_IDENTIFIER_NUMBERS.get(prefix, ())


def scan_content_text(
    text: str,
    *,
    profile: str,
    source: str,
    repo_identity: tuple[str, str, str] | None,
    commit: str | None = None,
    path: str,
    artifact_id: str | None = None,
    known_workflow_stop_tokens: frozenset[str] = frozenset(),
) -> list[Finding]:
    findings = scan_text(
        text,
        profile=profile,
        source=source,
        repo_identity=repo_identity,
        commit=commit,
        path=path,
        known_workflow_stop_tokens=known_workflow_stop_tokens,
    )
    if artifact_id is None or CREDENTIAL_TOKEN_RE.search(text):
        return findings
    retained = [
        finding
        for finding in findings
        if finding["category"] not in PUBLIC_ARTIFACT_CATEGORIES
    ]
    if len(retained) == len(findings):
        return findings
    retained.append(
        make_finding(
            "public-artifact",
            profile,
            source,
            commit=commit,
            path=path,
            artifact_id=artifact_id,
        )
    )
    return retained


def added_lines(diff: bytes, prefix_width: int = 1) -> list[str]:
    lines: list[str] = []
    in_hunk = False
    addition_prefix = b"+" * prefix_width
    for raw_line in diff.splitlines():
        if raw_line.startswith(b"diff --"):
            in_hunk = False
        elif raw_line.startswith(b"@@"):
            in_hunk = True
        elif in_hunk and raw_line.startswith(addition_prefix):
            lines.append(raw_line[prefix_width:].decode("utf-8", "replace"))
    return lines


def merge_added_lines(
    repo: Path, parents: list[str], commit: str, path: str
) -> list[str]:
    additions: set[str] | None = None
    for parent in parents:
        diff = git_bytes(
            repo,
            "diff",
            "--text",
            "--no-textconv",
            "--no-ext-diff",
            "--unified=0",
            parent,
            commit,
            "--",
            path,
        ).stdout
        parent_additions = set(added_lines(diff))
        additions = (
            parent_additions
            if additions is None
            else additions.intersection(parent_additions)
        )
    return sorted(additions or ())


def is_github_noreply(address: str) -> bool:
    address = address.strip().lower()
    return address == "noreply@github.com" or address.endswith(
        "@users.noreply.github.com"
    )


def unsafe_symlink_target(path: str, target: str) -> bool:
    if PurePosixPath(target).is_absolute() or re.match(r"^[A-Za-z]:[\\/]", target):
        return True
    depth = 0
    combined = PurePosixPath(path).parent / PurePosixPath(target)
    for part in combined.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if depth == 0:
                return True
            depth -= 1
        else:
            depth += 1
    return False


def symlink_path_component(repo: Path, path: str) -> tuple[str, str, bool] | None:
    relative = PurePosixPath(path)
    if relative.is_absolute() or ".." in relative.parts:
        raise AuditError
    current = repo
    components: list[str] = []
    for index, component in enumerate(relative.parts):
        if component in {"", "."}:
            continue
        components.append(component)
        current = current / component
        try:
            metadata = os.lstat(current)
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError as exc:
            raise AuditError from exc
        if metadata.st_mode & 0o170000 == 0o120000:
            try:
                target = os.readlink(current)
            except OSError as exc:
                raise AuditError from exc
            return "/".join(components), target, index == len(relative.parts) - 1
    return None


def load_public_artifacts(repo: Path, filename: str | None) -> dict[str, str]:
    if filename is None:
        return {}
    try:
        rows = Path(filename).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise AuditError from exc
    artifacts: dict[str, str] = {}
    for raw_row in rows:
        if not raw_row.strip() or raw_row.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", raw_row)
        if match is None:
            raise AuditError
        digest, path = match.groups()
        relative = PurePosixPath(path)
        if (
            any(ord(character) < 32 or ord(character) == 127 for character in path)
            or path != relative.as_posix()
            or relative.is_absolute()
            or relative.as_posix() in {"", "."}
            or ".." in relative.parts
            or ".git" in relative.parts
            or "\\" in path
            or path in artifacts
        ):
            raise AuditError
        if not any(
            component.lower() in PUBLIC_ARTIFACT_PATH_COMPONENTS
            for component in relative.parts
        ):
            raise AuditError
        try:
            if symlink_path_component(repo, path) is not None:
                raise AuditError
            file_path = repo / path
            if not file_path.is_file():
                raise AuditError
            if hashlib.sha256(file_path.read_bytes()).hexdigest() != digest:
                raise AuditError
        except (OSError, ValueError) as exc:
            raise AuditError from exc
        artifacts[path] = digest
    return artifacts


def artifact_id_for_blob(
    path: str,
    blob: bytes,
    public_artifacts: dict[str, str],
    *,
    mode: bytes | None = None,
) -> str | None:
    expected = public_artifacts.get(path)
    if expected is None:
        return None
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected or (
        mode is not None and mode not in PUBLIC_ARTIFACT_REGULAR_MODES
    ):
        raise AuditError
    return digest


def scan_commits(
    repo: Path,
    base: str,
    profile: str,
    repo_identity: tuple[str, str, str] | None,
    public_artifacts: dict[str, str],
) -> list[Finding]:
    try:
        commits = git(
            repo, "rev-list", "--reverse", f"{base}..HEAD"
        ).stdout.splitlines()
        findings: list[Finding] = []
        for commit in commits:
            parents = git(repo, "show", "-s", "--format=%P", commit).stdout.split()
            if len(parents) > 1:
                changed_paths = git_bytes(
                    repo,
                    "diff-tree",
                    "--cc",
                    "--no-commit-id",
                    "--name-only",
                    "--diff-filter=ACMRTUXB",
                    "-r",
                    "-z",
                    commit,
                ).stdout.split(b"\0")
            elif parents:
                parent = parents[0]
                changed_paths = git_bytes(
                    repo,
                    "diff",
                    "--name-only",
                    "--diff-filter=ACMRTUXB",
                    "-r",
                    "-z",
                    parent,
                    commit,
                    "--",
                ).stdout.split(b"\0")
            else:
                changed_paths = git_bytes(
                    repo,
                    "diff-tree",
                    "--root",
                    "--no-commit-id",
                    "--name-only",
                    "--diff-filter=ACMRTUXB",
                    "-r",
                    "-z",
                    commit,
                ).stdout.split(b"\0")
            for raw_path in changed_paths:
                if not raw_path:
                    continue
                changed_path = raw_path.decode("utf-8", "surrogateescape")
                findings.extend(
                    scan_text(
                        changed_path,
                        profile=profile,
                        source="committed-path",
                        repo_identity=repo_identity,
                        commit=commit,
                        path=changed_path,
                    )
                )
                blob = git_bytes(repo, "show", f"{commit}:{changed_path}").stdout
                tree_entry = git_bytes(
                    repo, "ls-tree", "-z", commit, "--", changed_path
                ).stdout
                mode = tree_entry.split(b" ", 1)[0]
                artifact_id = artifact_id_for_blob(
                    changed_path, blob, public_artifacts, mode=mode
                )
                if mode == b"120000":
                    target = blob.decode("utf-8", "replace")
                    findings.extend(
                        scan_text(
                            target,
                            profile=profile,
                            source="committed-symlink-target",
                            repo_identity=repo_identity,
                            commit=commit,
                            path=changed_path,
                        )
                    )
                    if unsafe_symlink_target(changed_path, target):
                        findings.append(
                            make_finding(
                                "symlink",
                                profile,
                                "committed-symlink",
                                commit=commit,
                                path=changed_path,
                            )
                        )
                elif b"\0" in blob[:8192]:
                    findings.append(
                        make_finding(
                            "binary",
                            profile,
                            "committed-binary",
                            commit=commit,
                            path=changed_path,
                        )
                    )
                else:
                    content_workflow_stop_tokens = extract_workflow_stop_tokens(
                        blob.decode("utf-8", "replace")
                    )
                    if len(parents) > 1:
                        content_lines = merge_added_lines(
                            repo, parents, commit, changed_path
                        )
                    elif parents:
                        diff = git_bytes(
                            repo,
                            "diff",
                            "--text",
                            "--no-textconv",
                            "--no-ext-diff",
                            "--unified=0",
                            parents[0],
                            commit,
                            "--",
                            changed_path,
                        ).stdout
                        content_lines = added_lines(diff)
                    else:
                        diff = git_bytes(
                            repo,
                            "show",
                            "--root",
                            "--format=",
                            "--text",
                            "--no-textconv",
                            "--no-ext-diff",
                            "--unified=0",
                            commit,
                            "--",
                            changed_path,
                        ).stdout
                        content_lines = added_lines(diff)
                    for line in content_lines:
                        findings.extend(
                            scan_content_text(
                                line,
                                profile=profile,
                                source="committed-content",
                                repo_identity=repo_identity,
                                commit=commit,
                                path=changed_path,
                                artifact_id=artifact_id,
                                known_workflow_stop_tokens=content_workflow_stop_tokens,
                            )
                        )
            message = git(repo, "show", "-s", "--format=%B", commit).stdout
            findings.extend(
                scan_text(
                    message,
                    profile=profile,
                    source="commit-message",
                    repo_identity=repo_identity,
                    commit=commit,
                )
            )
            identities = (
                git(
                    repo,
                    "show",
                    "-s",
                    "--format=%an%x00%ae%x00%cn%x00%ce",
                    commit,
                )
                .stdout.rstrip("\n")
                .split("\0")
            )
            if len(identities) != 4:
                raise AuditError
            author_name, author_email, committer_name, committer_email = identities
            for kind, name, email in (
                ("author", author_name, author_email),
                ("committer", committer_name, committer_email),
            ):
                source = f"{kind}-identity"
                findings.extend(
                    scan_text(
                        name,
                        profile=profile,
                        source=source,
                        repo_identity=repo_identity,
                        commit=commit,
                    )
                )
                if not is_github_noreply(email):
                    findings.append(
                        make_finding(
                            "identity",
                            profile,
                            source,
                            commit=commit,
                        )
                    )
        return findings
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AuditError from exc


def deduplicate(findings: list[Finding]) -> list[Finding]:
    unique = {tuple(sorted(finding.items())): finding for finding in findings}
    return [unique[key] for key in sorted(unique)]


def selected_worktree_paths(
    repo: Path, paths_from: str | None
) -> list[tuple[str, bool]]:
    try:
        staged = {
            path.decode("utf-8", "surrogateescape")
            for path in git_bytes(
                repo, "diff", "--cached", "--name-only", "-z", "HEAD", "--"
            ).stdout.split(b"\0")
            if path
        }
        unstaged = {
            path.decode("utf-8", "surrogateescape")
            for path in git_bytes(repo, "diff", "--name-only", "-z", "--").stdout.split(
                b"\0"
            )
            if path
        }
        untracked = {
            path.decode("utf-8", "surrogateescape")
            for path in git_bytes(
                repo, "ls-files", "--others", "--exclude-standard", "-z"
            ).stdout.split(b"\0")
            if path
        }
        candidates = staged | unstaged | untracked
        if paths_from is not None:
            requested = {
                (
                    ""
                    if PurePosixPath(line.strip()).as_posix() == "."
                    else PurePosixPath(line.strip()).as_posix()
                )
                for line in Path(paths_from).read_text(encoding="utf-8").splitlines()
                if line.strip()
            }
            for path in requested:
                candidate = Path(path)
                if candidate.is_absolute() or ".." in candidate.parts:
                    raise AuditError
            candidates = {
                path
                for path in candidates
                if any(
                    item == ""
                    or path == item
                    or path.startswith(item.rstrip("/") + "/")
                    for item in requested
                )
            }
            for path in requested:
                if path == "":
                    continue
                if path in candidates:
                    continue
                tracked_result = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "ls-files",
                        "--error-unmatch",
                        "--",
                        path,
                    ],
                    capture_output=True,
                )
                if tracked_result.returncode == 0:
                    continue
                link_component = symlink_path_component(repo, path)
                file_path = repo / path
                if link_component is None and not file_path.exists():
                    continue
                candidates.add(path)
                untracked.add(path)
        return [(path, path in untracked) for path in sorted(candidates)]
    except (OSError, UnicodeError, subprocess.CalledProcessError) as exc:
        raise AuditError from exc


def scan_worktree(
    repo: Path,
    profile: str,
    repo_identity: tuple[str, str, str] | None,
    paths_from: str | None,
    public_artifacts: dict[str, str],
) -> list[Finding]:
    findings: list[Finding] = []
    try:
        for path, untracked in selected_worktree_paths(repo, paths_from):
            file_path = repo / path
            link_component = symlink_path_component(repo, path)
            if not untracked and link_component is None and not file_path.exists():
                continue
            findings.extend(
                scan_text(
                    path,
                    profile=profile,
                    source="worktree-path",
                    repo_identity=repo_identity,
                    path=path,
                )
            )
            current_content = (
                file_path.read_bytes()
                if link_component is None and file_path.is_file()
                else None
            )
            if not untracked:
                for source, diff_args in (
                    (
                        "staged-content",
                        (
                            "diff",
                            "--cached",
                            "--text",
                            "--no-textconv",
                            "--no-ext-diff",
                            "--unified=0",
                            "HEAD",
                        ),
                    ),
                    (
                        "worktree-content",
                        (
                            "diff",
                            "--text",
                            "--no-textconv",
                            "--no-ext-diff",
                            "--unified=0",
                        ),
                    ),
                ):
                    diff = git_bytes(repo, *diff_args, "--", path).stdout
                    artifact_id = None
                    content_workflow_stop_tokens: frozenset[str] = frozenset()
                    if source == "staged-content" and diff:
                        index_entry = git_bytes(
                            repo, "ls-files", "--stage", "-z", "--", path
                        ).stdout
                        if index_entry:
                            index_blob = git_bytes(repo, "show", f":{path}").stdout
                            index_mode = index_entry.split(b" ", 1)[0]
                            artifact_id = artifact_id_for_blob(
                                path,
                                index_blob,
                                public_artifacts,
                                mode=index_mode,
                            )
                            if index_mode == b"120000":
                                index_target = index_blob.decode(
                                    "utf-8", "replace"
                                )
                                findings.extend(
                                    scan_text(
                                        index_target,
                                        profile=profile,
                                        source="staged-symlink-target",
                                        repo_identity=repo_identity,
                                        path=path,
                                    )
                                )
                                if unsafe_symlink_target(path, index_target):
                                    findings.append(
                                        make_finding(
                                            "symlink",
                                            profile,
                                            "staged-symlink",
                                            path=path,
                                        )
                                    )
                            elif b"\0" in index_blob[:8192]:
                                findings.append(
                                    make_finding(
                                        "binary",
                                        profile,
                                        "staged-binary",
                                        path=path,
                                    )
                                )
                            else:
                                content_workflow_stop_tokens = (
                                    extract_workflow_stop_tokens(
                                        index_blob.decode("utf-8", "replace")
                                    )
                                )
                    elif source == "worktree-content" and current_content is not None:
                        artifact_id = artifact_id_for_blob(
                            path, current_content, public_artifacts
                        )
                        if b"\0" not in current_content[:8192]:
                            content_workflow_stop_tokens = extract_workflow_stop_tokens(
                                current_content.decode("utf-8", "replace")
                            )
                    for line in added_lines(diff):
                        findings.extend(
                            scan_content_text(
                                line,
                                profile=profile,
                                source=source,
                                repo_identity=repo_identity,
                                path=path,
                                artifact_id=artifact_id,
                                known_workflow_stop_tokens=content_workflow_stop_tokens,
                            )
                        )
            if link_component is not None:
                component_path, target, is_final = link_component
                findings.extend(
                    scan_text(
                        target,
                        profile=profile,
                        source="worktree-symlink-target",
                        repo_identity=repo_identity,
                        path=path,
                    )
                )
                if not is_final or unsafe_symlink_target(component_path, target):
                    findings.append(
                        make_finding(
                            "symlink",
                            profile,
                            (
                                "worktree-symlink"
                                if is_final
                                else "worktree-symlink-ancestor"
                            ),
                            path=path,
                        )
                    )
                continue
            if not file_path.exists():
                continue
            if current_content is None:
                raise AuditError
            if b"\0" in current_content[:8192]:
                findings.append(
                    make_finding(
                        "binary",
                        profile,
                        "worktree-binary",
                        path=path,
                    )
                )
                continue
            if untracked:
                content = current_content.decode("utf-8", "replace")
                lines = content.splitlines()
                content_workflow_stop_tokens = extract_workflow_stop_tokens(content)
            else:
                lines = []
                content_workflow_stop_tokens = frozenset()
            artifact_id = artifact_id_for_blob(path, current_content, public_artifacts)
            for line in lines:
                findings.extend(
                    scan_content_text(
                        line,
                        profile=profile,
                        source="worktree-content",
                        repo_identity=repo_identity,
                        path=path,
                        artifact_id=artifact_id,
                        known_workflow_stop_tokens=content_workflow_stop_tokens,
                    )
                )
        return findings
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AuditError from exc


def scan_proposals(
    profile: str,
    repo_identity: tuple[str, str, str] | None,
    files: tuple[tuple[str, str | None], ...],
) -> list[Finding]:
    findings: list[Finding] = []
    try:
        for source, filename in files:
            if filename is None:
                continue
            text = Path(filename).read_text(encoding="utf-8")
            findings.extend(
                scan_text(
                    text,
                    profile=profile,
                    source=source,
                    repo_identity=repo_identity,
                )
            )
        return findings
    except (OSError, UnicodeError) as exc:
        raise AuditError from exc


def print_result(result: dict[str, object], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(result, sort_keys=True))
        return
    if not result["complete"]:
        print("audit: incomplete")
        print(f"profile: {result['profile']}")
        print(f"error: {result['error']}")
        return
    findings = result["findings"]
    assert isinstance(findings, list)
    print("audit: findings" if findings else "audit: clean")
    print(f"profile: {result['profile']}")
    for finding in findings:
        assert isinstance(finding, dict)
        details = [
            str(finding["severity"]),
            str(finding["category"]),
            f"source={finding['source']}",
        ]
        if "commit" in finding:
            details.append(f"commit={finding['commit']}")
        if "path_id" in finding:
            details.append(f"path_id={finding['path_id']}")
        if "artifact_id" in finding:
            details.append(f"artifact_id={finding['artifact_id']}")
        print("- " + " ".join(details))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument(
        "--profile", choices=("community", "locked-down"), required=True
    )
    parser.add_argument("--paths-from")
    parser.add_argument("--title-file")
    parser.add_argument("--body-file")
    parser.add_argument("--commit-message-file")
    parser.add_argument("--public-artifacts-from")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        repo = validate_repository(args.repo)
        branch = validate_base(repo, args.base)
        repo_identity = current_repository_identity(repo)
        public_artifacts = load_public_artifacts(repo, args.public_artifacts_from)
        findings = scan_text(
            branch,
            profile=args.profile,
            source="branch-name",
            repo_identity=repo_identity,
        )
        findings.extend(
            scan_commits(
                repo,
                args.base,
                args.profile,
                repo_identity,
                public_artifacts,
            )
        )
        findings.extend(
            scan_worktree(
                repo,
                args.profile,
                repo_identity,
                args.paths_from,
                public_artifacts,
            )
        )
        findings.extend(
            scan_proposals(
                args.profile,
                repo_identity,
                (
                    ("proposed-title", args.title_file),
                    ("proposed-body", args.body_file),
                    ("proposed-commit-message", args.commit_message_file),
                ),
            )
        )
        if args.public_artifacts_from is not None:
            if load_public_artifacts(repo, args.public_artifacts_from) != public_artifacts:
                raise AuditError
        findings = deduplicate(findings)
    except AuditError:
        result = {
            "complete": False,
            "error": "repository validation failed",
            "findings": [],
            "profile": args.profile,
        }
        print_result(result, args.format)
        return 2
    result = {"complete": True, "findings": findings, "profile": args.profile}
    print_result(result, args.format)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
