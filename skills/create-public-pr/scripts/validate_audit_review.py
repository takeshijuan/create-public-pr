"""Compare a redacted audit result with explicit manual-review records."""

from __future__ import annotations

import argparse
import json
import re
import unicodedata
from pathlib import Path
from typing import Any

from audit_public_pr import scan_text


KEY_FIELDS = ("category", "severity", "source", "commit", "path_id")
AUDIT_FIELDS = {"complete", "profile", "findings"}
BASE_FINDING_FIELDS = {"category", "severity", "source"}
BASE_RECORD_FIELDS = {
    "category",
    "severity",
    "source",
    "checks",
    "decision",
    "reviewer",
    "rationale",
}
CHECK_FIELDS = {
    "public_without_credentials",
    "relevant_to_change",
    "no_internal_context",
    "provenance_and_license",
}
PROFILES = {"community", "locked-down"}
EXPECTED_CHECKS = {
    "repository-link": {
        "public_without_credentials": "pass",
        "relevant_to_change": "pass",
        "no_internal_context": "pass",
        "provenance_and_license": "not-applicable",
    },
    "binary": {
        "public_without_credentials": "not-applicable",
        "relevant_to_change": "not-applicable",
        "no_internal_context": "pass",
        "provenance_and_license": "pass",
    },
    "identity": {
        "public_without_credentials": "not-applicable",
        "relevant_to_change": "not-applicable",
        "no_internal_context": "pass",
        "provenance_and_license": "not-applicable",
    },
}
HARD_BLOCK_CATEGORIES = {
    "private-key",
    "credential",
    "credential-url",
    "collaboration-url",
    "private-host",
    "local-path",
    "email",
    "external-tracker",
    "symlink",
}
KNOWN_CATEGORIES = HARD_BLOCK_CATEGORIES | set(EXPECTED_CHECKS)
UNSAFE_EVIDENCE_CATEGORIES = {
    "private-key",
    "credential",
    "credential-url",
    "collaboration-url",
    "private-host",
    "local-path",
    "email",
    "repository-link",
    "external-tracker",
}
SOURCE_RE = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*" + r"://\S+", re.I)
AT_HANDLE_RE = re.compile("@" + r"[A-Za-z0-9_]")
REPOSITORY_REFERENCE_RE = re.compile(
    r"\b(?:github\.com|gitlab\.com|bitbucket\.org)/"
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
    re.I,
)
COLLABORATION_HOST_RE = re.compile(
    r"\b(?:[a-z0-9-]+\.)*(?:slack\.com|notion\.so|docs\.google\.com|"
    r"drive\.google\.com|linear\.app|discord\.com|teams\.microsoft\.com|"
    r"clickup\.com|atlassian\.net)\b",
    re.I,
)
MAX_JSON_INTEGER_DIGITS = 4096


class InputError(Exception):
    """Raised when comparator input cannot be parsed safely."""


def parse_bounded_int(value: str) -> int:
    if len(value.removeprefix("-")) > MAX_JSON_INTEGER_DIGITS:
        raise ValueError
    return int(value)


def read_json(path_arg: str) -> Any:
    try:
        return json.loads(
            Path(path_arg).read_text(encoding="utf-8"),
            parse_int=parse_bounded_int,
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise InputError from exc


def finding_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(item.get(field) for field in KEY_FIELDS)


def nonempty_string(value: Any, maximum: int = 500) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= maximum


def valid_safe_identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{12}", value))


def valid_safe_source(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= 80
        and bool(SOURCE_RE.fullmatch(value))
    )


def expected_severity(category: Any, profile: Any) -> str | None:
    if not isinstance(category, str) or not isinstance(profile, str):
        return None
    if category not in KNOWN_CATEGORIES:
        return None
    if category in {"binary", "identity"}:
        return "review"
    if category == "repository-link" and profile == "community":
        return "review"
    return "blocking"


def validate_finding(finding: Any, profile: str) -> bool:
    if not isinstance(finding, dict):
        return False
    expected_fields = set(BASE_FINDING_FIELDS)
    for optional in ("commit", "path_id"):
        if optional in finding:
            expected_fields.add(optional)
    if set(finding) != expected_fields:
        return False
    category = finding.get("category")
    if not isinstance(category, str):
        return False
    severity = finding.get("severity")
    if not isinstance(severity, str):
        return False
    required_severity = expected_severity(category, profile)
    if required_severity is None or severity != required_severity:
        return False
    if not valid_safe_source(finding.get("source")):
        return False
    if "commit" in finding and not valid_safe_identifier(finding["commit"]):
        return False
    if "path_id" in finding and not valid_safe_identifier(finding["path_id"]):
        return False
    return True


def contains_absolute_path(value: str) -> bool:
    for token in value.split():
        candidate = token.lstrip("'\"([{")
        if candidate.startswith("/") or candidate.startswith("~" + "/"):
            return True
        if candidate.startswith("\\" + "\\"):
            return True
        if (
            len(candidate) >= 3
            and candidate[0].isalpha()
            and candidate[1] == ":"
            and candidate[2] in {"/", "\\"}
        ):
            return True
    return False


def safe_evidence_text(value: Any, maximum: int) -> bool:
    if not nonempty_string(value, maximum=maximum):
        return False
    assert isinstance(value, str)
    if any(unicodedata.category(character) == "Cc" for character in value):
        return False
    if (
        URL_RE.search(value)
        or AT_HANDLE_RE.search(value)
        or REPOSITORY_REFERENCE_RE.search(value)
        or COLLABORATION_HOST_RE.search(value)
        or contains_absolute_path(value)
    ):
        return False
    findings = scan_text(
        value,
        profile="community",
        source="review-evidence",
        repo_identity=None,
    )
    for finding in findings:
        category = finding.get("category")
        if isinstance(category, str) and category in UNSAFE_EVIDENCE_CATEGORIES:
            return False
    return True


def validate_record(record: Any) -> bool:
    if not isinstance(record, dict):
        return False
    expected_fields = set(BASE_RECORD_FIELDS)
    for optional in ("commit", "path_id"):
        if optional in record:
            expected_fields.add(optional)
    if set(record) != expected_fields:
        return False
    category = record.get("category")
    if not isinstance(category, str) or category not in EXPECTED_CHECKS:
        return False
    severity = record.get("severity")
    if not isinstance(severity, str) or severity != "review":
        return False
    if not valid_safe_source(record.get("source")):
        return False
    if "commit" in record and not valid_safe_identifier(record["commit"]):
        return False
    if "path_id" in record and not valid_safe_identifier(record["path_id"]):
        return False
    checks = record.get("checks")
    if not isinstance(checks, dict) or set(checks) != CHECK_FIELDS:
        return False
    if not all(isinstance(value, str) for value in checks.values()):
        return False
    if checks != EXPECTED_CHECKS[category]:
        return False
    decision = record.get("decision")
    if not isinstance(decision, str) or decision != "approved":
        return False
    if not safe_evidence_text(record.get("reviewer"), maximum=120):
        return False
    if not safe_evidence_text(record.get("rationale"), maximum=500):
        return False
    return True


def validate(audit: Any, reviews: Any) -> list[str]:
    if not isinstance(audit, dict):
        return ["audit is incomplete"]
    if set(audit) != AUDIT_FIELDS:
        return ["audit schema is invalid"]
    complete = audit.get("complete")
    if not isinstance(complete, bool) or complete is not True:
        return ["audit is incomplete"]
    profile = audit.get("profile")
    if not isinstance(profile, str) or profile not in PROFILES:
        return ["audit profile is invalid"]
    findings = audit.get("findings")
    if not isinstance(findings, list):
        return ["audit findings are invalid"]
    if not isinstance(reviews, list):
        return ["review record schema is invalid"]

    errors: list[str] = []
    valid_findings = [validate_finding(finding, profile) for finding in findings]
    if not all(valid_findings):
        errors.append("audit finding schema is invalid")
    audit_keys = [
        finding_key(finding)
        for valid, finding in zip(valid_findings, findings)
        if valid and isinstance(finding, dict)
    ]
    if len(audit_keys) != len(set(audit_keys)):
        errors.append("duplicate audit findings are forbidden")

    if any(
        valid and finding.get("severity") == "blocking"
        for valid, finding in zip(valid_findings, findings)
        if isinstance(finding, dict)
    ):
        errors.append("blocking findings are unresolved")

    eligible: list[dict[str, Any]] = []
    for valid, finding in zip(valid_findings, findings):
        if not isinstance(finding, dict):
            continue
        severity = finding.get("severity")
        category = finding.get("category")
        if (
            severity == "review"
            and category == "repository-link"
            and profile != "community"
        ):
            errors.append("audit contains an ineligible review finding")
        if not valid:
            continue
        if severity != "review":
            continue
        eligible.append(finding)

    eligible_keys = [finding_key(finding) for finding in eligible]
    if len(eligible_keys) != len(set(eligible_keys)):
        errors.append("duplicate eligible findings are forbidden")

    valid_records = [validate_record(record) for record in reviews]
    if not all(valid_records):
        errors.append("review record schema is invalid")
    review_keys = [
        finding_key(record)
        for valid, record in zip(valid_records, reviews)
        if valid and isinstance(record, dict)
    ]
    if len(review_keys) != len(set(review_keys)):
        errors.append("duplicate review records are forbidden")
    if set(review_keys) != set(eligible_keys) or len(review_keys) != len(eligible_keys):
        errors.append("review records do not exactly match findings")
    return sorted(set(errors))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-file", required=True)
    parser.add_argument("--review-file", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        audit = read_json(args.audit_file)
        reviews = read_json(args.review_file)
    except InputError:
        print("audit review validation: invalid input")
        return 2
    errors = validate(audit, reviews)
    if errors:
        print("audit review validation: failed")
        for error in errors:
            print(f"- {error}")
        return 1
    print("audit review validation: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
