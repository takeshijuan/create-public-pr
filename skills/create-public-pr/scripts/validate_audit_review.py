"""Compare a redacted audit result with explicit manual-review records."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


KEY_FIELDS = ("category", "severity", "source", "commit", "path_id")
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


class InputError(Exception):
    """Raised when comparator input cannot be parsed safely."""


def read_json(path_arg: str) -> Any:
    try:
        return json.loads(Path(path_arg).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InputError from exc


def finding_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(item.get(field) for field in KEY_FIELDS)


def nonempty_string(value: Any, maximum: int = 500) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= maximum


def valid_safe_identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{12}", value))


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
    if category not in EXPECTED_CHECKS:
        return False
    if record.get("severity") != "review":
        return False
    if not nonempty_string(record.get("source")):
        return False
    if "commit" in record and not valid_safe_identifier(record["commit"]):
        return False
    if "path_id" in record and not valid_safe_identifier(record["path_id"]):
        return False
    checks = record.get("checks")
    if not isinstance(checks, dict) or set(checks) != CHECK_FIELDS:
        return False
    if checks != EXPECTED_CHECKS[category]:
        return False
    if record.get("decision") != "approved":
        return False
    if not nonempty_string(record.get("reviewer"), maximum=120):
        return False
    if not nonempty_string(record.get("rationale")):
        return False
    return True


def validate(audit: Any, reviews: Any) -> list[str]:
    if not isinstance(audit, dict) or audit.get("complete") is not True:
        return ["audit is incomplete"]
    if audit.get("profile") not in {"community", "locked-down"}:
        return ["audit profile is invalid"]
    findings = audit.get("findings")
    if not isinstance(findings, list) or not all(
        isinstance(finding, dict) for finding in findings
    ):
        return ["audit findings are invalid"]
    if not isinstance(reviews, list):
        return ["review record schema is invalid"]

    errors: list[str] = []
    if any(finding.get("severity") == "blocking" for finding in findings):
        errors.append("blocking findings are unresolved")

    eligible: list[dict[str, Any]] = []
    for finding in findings:
        severity = finding.get("severity")
        category = finding.get("category")
        if severity != "review":
            continue
        if category not in EXPECTED_CHECKS:
            errors.append("audit contains an ineligible review finding")
            continue
        if category == "repository-link" and audit.get("profile") != "community":
            errors.append("audit contains an ineligible review finding")
            continue
        if not all(nonempty_string(finding.get(field)) for field in KEY_FIELDS[:3]):
            errors.append("audit review key is invalid")
            continue
        if "commit" in finding and not valid_safe_identifier(finding["commit"]):
            errors.append("audit review key is invalid")
            continue
        if "path_id" in finding and not valid_safe_identifier(finding["path_id"]):
            errors.append("audit review key is invalid")
            continue
        eligible.append(finding)

    eligible_keys = [finding_key(finding) for finding in eligible]
    if len(eligible_keys) != len(set(eligible_keys)):
        errors.append("duplicate eligible findings are forbidden")

    if not all(validate_record(record) for record in reviews):
        errors.append("review record schema is invalid")
    review_keys = [
        finding_key(record) for record in reviews if isinstance(record, dict)
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
