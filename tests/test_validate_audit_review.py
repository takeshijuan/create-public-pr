from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).parents[1]
SCRIPT = (
    REPO_ROOT
    / "skills"
    / "create-public-pr"
    / "scripts"
    / "validate_audit_review.py"
)


class AuditReviewComparatorTests(unittest.TestCase):
    def run_comparator(
        self, audit: Any, reviews: Any
    ) -> subprocess.CompletedProcess[str]:
        return self.run_comparator_text(json.dumps(audit), json.dumps(reviews))

    def run_comparator_text(
        self, audit_text: str, review_text: str = "[]"
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            audit_file = root / "audit.json"
            review_file = root / "review.json"
            audit_file.write_text(audit_text, encoding="utf-8")
            review_file.write_text(review_text, encoding="utf-8")
            return subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--audit-file",
                    str(audit_file),
                    "--review-file",
                    str(review_file),
                ],
                text=True,
                capture_output=True,
            )

    def review_record(self, **overrides: Any) -> dict[str, Any]:
        record: dict[str, Any] = {
            "category": "repository-link",
            "severity": "review",
            "source": "committed-content",
            "commit": "0123456789ab",
            "checks": {
                "public_without_credentials": "pass",
                "relevant_to_change": "pass",
                "no_internal_context": "pass",
                "provenance_and_license": "not-applicable",
            },
            "decision": "approved",
            "reviewer": "maintainer",
            "rationale": "Public and directly relevant reference.",
        }
        record.update(overrides)
        return record

    def audit_payload(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        return {"complete": True, "findings": findings, "profile": "community"}

    def wrong_json_values(self) -> tuple[Any, ...]:
        marker = "payload-marker"
        return (None, [marker], {marker: "value"}, 17, True)

    def assert_generic_schema_failure(
        self,
        result: subprocess.CompletedProcess[str],
        expected_message: str,
    ) -> None:
        self.assertEqual(result.returncode, 1)
        self.assertIn(expected_message, result.stdout)
        self.assertNotIn("payload-marker", result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")

    def test_clean_audit_and_empty_reviews_pass(self) -> None:
        result = self.run_comparator(self.audit_payload([]), [])

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "audit review validation: clean\n")
        self.assertEqual(result.stderr, "")

    def test_deeply_nested_valid_json_is_generic_invalid_input(self) -> None:
        marker = "deep-payload-marker"
        nested_profile = "[" * 1200 + json.dumps(marker) + "]" * 1200
        audit_text = (
            '{"complete":true,"profile":'
            + nested_profile
            + ',"findings":[]}'
        )

        result = self.run_comparator_text(audit_text)

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "audit review validation: invalid input\n")
        self.assertEqual(result.stderr, "")
        self.assertNotIn(marker, result.stdout + result.stderr)

    def test_overlong_valid_json_integer_is_generic_invalid_input(self) -> None:
        digits = "9" * 5000
        audit_text = (
            '{"complete":true,"profile":' + digits + ',"findings":[]}'
        )

        result = self.run_comparator_text(audit_text)

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "audit review validation: invalid input\n")
        self.assertEqual(result.stderr, "")
        self.assertNotIn(digits[:100], result.stdout + result.stderr)

    def test_json_nesting_above_portable_limit_is_generic_invalid_input(self) -> None:
        marker = "nested-payload-marker"
        nested_profile = "[" * 256 + json.dumps(marker) + "]" * 256
        audit_text = (
            '{"complete":true,"profile":'
            + nested_profile
            + ',"findings":[]}'
        )

        result = self.run_comparator_text(audit_text)

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "audit review validation: invalid input\n")
        self.assertEqual(result.stderr, "")
        self.assertNotIn(marker, result.stdout + result.stderr)

    def test_brackets_and_escaped_quotes_inside_string_do_not_count_as_nesting(
        self,
    ) -> None:
        profile = (
            "[" * 300
            + "{" * 300
            + ' public text with "escaped quotes" and \\\\ separators '
            + "}" * 300
            + "]" * 300
        )
        audit_text = json.dumps(
            {"complete": True, "profile": profile, "findings": []}
        )

        result = self.run_comparator_text(audit_text)

        self.assertEqual(result.returncode, 1)
        self.assertIn("audit profile is invalid", result.stdout)
        self.assertNotIn("invalid input", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_exact_eligible_review_record_passes(self) -> None:
        finding = {
            "category": "repository-link",
            "severity": "review",
            "source": "committed-content",
            "commit": "0123456789ab",
        }

        result = self.run_comparator(
            self.audit_payload([finding]), [self.review_record()]
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_exact_public_artifact_review_passes_in_locked_down_profile(
        self,
    ) -> None:
        finding = {
            "category": "public-artifact",
            "severity": "review",
            "source": "committed-content",
            "commit": "0123456789ab",
            "path_id": "abcdef012345",
            "artifact_id": "1" * 64,
        }
        audit = self.audit_payload([finding])
        audit["profile"] = "locked-down"
        record = self.review_record(
            category="public-artifact",
            path_id="abcdef012345",
            artifact_id="1" * 64,
            checks={
                "public_without_credentials": "pass",
                "relevant_to_change": "pass",
                "no_internal_context": "pass",
                "provenance_and_license": "pass",
                "upstream_bytes_match": "pass",
            },
            rationale="Checksum pinned public fixture with verified license.",
        )

        result = self.run_comparator(audit, [record])

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_public_artifact_review_digest_must_match_exactly(self) -> None:
        finding = {
            "category": "public-artifact",
            "severity": "review",
            "source": "committed-content",
            "commit": "0123456789ab",
            "path_id": "abcdef012345",
            "artifact_id": "1" * 64,
        }
        record = self.review_record(
            category="public-artifact",
            path_id="abcdef012345",
            artifact_id="2" * 64,
            checks={
                "public_without_credentials": "pass",
                "relevant_to_change": "pass",
                "no_internal_context": "pass",
                "provenance_and_license": "pass",
                "upstream_bytes_match": "pass",
            },
            rationale="Checksum pinned public fixture with verified license.",
        )

        result = self.run_comparator(self.audit_payload([finding]), [record])

        self.assertEqual(result.returncode, 1)
        self.assertIn("review records do not exactly match findings", result.stdout)

    def test_public_artifact_finding_requires_path_and_digest(self) -> None:
        finding = {
            "category": "public-artifact",
            "severity": "review",
            "source": "committed-content",
            "commit": "0123456789ab",
        }

        result = self.run_comparator(self.audit_payload([finding]), [])

        self.assertEqual(result.returncode, 1)
        self.assertIn("audit finding schema is invalid", result.stdout)

    def test_blocking_finding_always_stops_without_echoing_payload(self) -> None:
        finding = {
            "category": "credential",
            "severity": "blocking",
            "source": "committed-content",
            "commit": "0123456789ab",
        }

        result = self.run_comparator(self.audit_payload([finding]), [])

        self.assertEqual(result.returncode, 1)
        self.assertIn("blocking findings are unresolved", result.stdout)
        self.assertNotIn("credential", result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")

    def test_key_collision_cannot_hide_a_missing_record(self) -> None:
        common = {
            "category": "repository-link",
            "severity": "review",
            "source": "committed-content",
        }
        findings = [
            {**common, "commit": "0123456789ab"},
            {**common, "commit": "abcdef012345"},
        ]

        result = self.run_comparator(
            self.audit_payload(findings), [self.review_record()]
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("review records do not exactly match findings", result.stdout)

    def test_path_id_is_part_of_the_exact_key(self) -> None:
        finding = {
            "category": "binary",
            "severity": "review",
            "source": "worktree-binary",
            "path_id": "aaaabbbbcccc",
        }
        record = self.review_record(
            category="binary",
            source="worktree-binary",
            path_id="dddd11112222",
            checks={
                "public_without_credentials": "not-applicable",
                "relevant_to_change": "not-applicable",
                "no_internal_context": "pass",
                "provenance_and_license": "pass",
            },
        )
        record.pop("commit")

        result = self.run_comparator(self.audit_payload([finding]), [record])

        self.assertEqual(result.returncode, 1)
        self.assertIn("review records do not exactly match findings", result.stdout)

    def test_commit_and_path_id_form_one_full_key(self) -> None:
        finding = {
            "category": "binary",
            "severity": "review",
            "source": "committed-binary",
            "commit": "0123456789ab",
            "path_id": "aaaabbbbcccc",
        }
        exact = self.review_record(
            category="binary",
            source="committed-binary",
            path_id="aaaabbbbcccc",
            checks={
                "public_without_credentials": "not-applicable",
                "relevant_to_change": "not-applicable",
                "no_internal_context": "pass",
                "provenance_and_license": "pass",
            },
        )
        wrong_one_field = dict(exact, path_id="dddd11112222")

        passing = self.run_comparator(self.audit_payload([finding]), [exact])
        collision = self.run_comparator(
            self.audit_payload([finding]), [wrong_one_field]
        )

        self.assertEqual(passing.returncode, 0, passing.stdout + passing.stderr)
        self.assertEqual(collision.returncode, 1)
        self.assertIn(
            "review records do not exactly match findings", collision.stdout
        )

    def test_duplicate_or_stale_records_are_rejected(self) -> None:
        finding = {
            "category": "repository-link",
            "severity": "review",
            "source": "committed-content",
            "commit": "0123456789ab",
        }
        record = self.review_record()

        duplicate = self.run_comparator(
            self.audit_payload([finding]), [record, dict(record)]
        )
        stale = self.run_comparator(self.audit_payload([]), [record])

        self.assertEqual(duplicate.returncode, 1)
        self.assertIn("duplicate review records are forbidden", duplicate.stdout)
        self.assertEqual(stale.returncode, 1)
        self.assertIn("review records do not exactly match findings", stale.stdout)

    def test_record_fields_checks_and_decision_are_strict(self) -> None:
        finding = {
            "category": "repository-link",
            "severity": "review",
            "source": "committed-content",
            "commit": "0123456789ab",
        }
        invalid = self.review_record(
            decision="remove",
            checks={
                "public_without_credentials": "pass",
                "relevant_to_change": "unknown",
                "no_internal_context": "pass",
                "provenance_and_license": "not-applicable",
            },
            unexpected="field",
        )

        result = self.run_comparator(self.audit_payload([finding]), [invalid])

        self.assertEqual(result.returncode, 1)
        self.assertIn("review record schema is invalid", result.stdout)

    def test_incomplete_audit_is_rejected(self) -> None:
        result = self.run_comparator(
            {"complete": False, "findings": [], "profile": "community"}, []
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("audit is incomplete", result.stdout)

    def test_locked_down_repository_link_cannot_be_manually_approved(self) -> None:
        finding = {
            "category": "repository-link",
            "severity": "review",
            "source": "committed-content",
            "commit": "0123456789ab",
        }
        audit = self.audit_payload([finding])
        audit["profile"] = "locked-down"

        result = self.run_comparator(audit, [self.review_record()])

        self.assertEqual(result.returncode, 1)
        self.assertIn("audit contains an ineligible review finding", result.stdout)

    def test_every_finding_must_match_the_exact_safe_schema(self) -> None:
        cases = (
            {
                "category": "credential",
                "severity": "blocking",
                "source": "committed-content",
                "commit": "0123456789ab",
                "unexpected": "sensitive-payload",
            },
            {
                "category": "credential",
                "severity": "blocking",
                "source": "committed content",
                "commit": "0123456789ab",
            },
            {
                "category": "credential",
                "severity": "blocking",
                "source": "committed-content",
                "path_id": "NOT-" + "HEX-" + "1234",
            },
            {
                "category": ["credential"],
                "severity": "blocking",
                "source": "committed-content",
            },
        )

        for finding in cases:
            with self.subTest(finding=finding):
                result = self.run_comparator(self.audit_payload([finding]), [])

                self.assertEqual(result.returncode, 1)
                self.assertIn("audit finding schema is invalid", result.stdout)
                self.assertNotIn("sensitive-payload", result.stdout + result.stderr)

    def test_category_profile_and_severity_must_be_possible(self) -> None:
        cases = (
            ("community", "repository-link", "blocking"),
            ("locked-down", "repository-link", "review"),
            ("community", "binary", "blocking"),
            ("community", "credential", "review"),
            ("community", "unknown-category", "blocking"),
            ("community", "unknown-category", None),
            ("community", "credential", "warning"),
        )

        for profile, category, severity in cases:
            with self.subTest(profile=profile, category=category, severity=severity):
                finding = {
                    "category": category,
                    "severity": severity,
                    "source": "committed-content",
                    "commit": "0123456789ab",
                }
                audit = self.audit_payload([finding])
                audit["profile"] = profile

                result = self.run_comparator(audit, [])

                self.assertEqual(result.returncode, 1)
                self.assertIn("audit finding schema is invalid", result.stdout)

    def test_valid_locked_down_repository_link_is_blocking(self) -> None:
        finding = {
            "category": "repository-link",
            "severity": "blocking",
            "source": "committed-content",
            "commit": "0123456789ab",
        }
        audit = self.audit_payload([finding])
        audit["profile"] = "locked-down"

        result = self.run_comparator(audit, [])

        self.assertEqual(result.returncode, 1)
        self.assertIn("blocking findings are unresolved", result.stdout)
        self.assertNotIn("audit finding schema is invalid", result.stdout)

    def test_duplicate_audit_findings_are_rejected(self) -> None:
        finding = {
            "category": "credential",
            "severity": "blocking",
            "source": "committed-content",
            "commit": "0123456789ab",
        }

        result = self.run_comparator(
            self.audit_payload([finding, dict(finding)]), []
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("duplicate audit findings are forbidden", result.stdout)

    def test_manual_review_evidence_rejects_sensitive_text_without_echo(self) -> None:
        unsafe_values = (
            ("rationale", "https://" + "github.com/acme/private-repository"),
            ("rationale", "git" + "@github.com:acme/private-repository.git"),
            ("rationale", "github.com/" + "acme/private-repository"),
            ("reviewer", "reviewer" + "@private-company.dev"),
            ("reviewer", "@" + "maintainer"),
            ("rationale", "/" + "Users/private-user/work/repository"),
            ("rationale", "/" + "tmp"),
            ("rationale", "api_" + "key=" + "live-secret-value"),
            ("rationale", "https://" + "workspace.slack.com/archives/C123"),
            ("rationale", "workspace." + "slack.com was checked"),
            ("rationale", "service" + ".internal was checked"),
        )
        finding = {
            "category": "repository-link",
            "severity": "review",
            "source": "committed-content",
            "commit": "0123456789ab",
        }

        for field, unsafe in unsafe_values:
            with self.subTest(field=field, unsafe=unsafe):
                record = self.review_record(**{field: unsafe})

                result = self.run_comparator(
                    self.audit_payload([finding]), [record]
                )

                self.assertEqual(result.returncode, 1)
                self.assertIn("review record schema is invalid", result.stdout)
                self.assertNotIn(unsafe, result.stdout + result.stderr)

    def test_manual_review_evidence_rejects_control_characters(self) -> None:
        finding = {
            "category": "repository-link",
            "severity": "review",
            "source": "committed-content",
            "commit": "0123456789ab",
        }
        record = self.review_record(rationale="Public reference.\nSecond line.")

        result = self.run_comparator(self.audit_payload([finding]), [record])

        self.assertEqual(result.returncode, 1)
        self.assertIn("review record schema is invalid", result.stdout)

    def test_manual_review_evidence_accepts_safe_prose(self) -> None:
        finding = {
            "category": "repository-link",
            "severity": "review",
            "source": "committed-content",
            "commit": "0123456789ab",
        }
        record = self.review_record(
            reviewer="Release maintainer",
            rationale="Public project reference verified as relevant to this change.",
        )

        result = self.run_comparator(self.audit_payload([finding]), [record])

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_audit_profile_wrong_json_types_fail_generically(self) -> None:
        for wrong_value in self.wrong_json_values():
            with self.subTest(value_type=type(wrong_value).__name__):
                audit = self.audit_payload([])
                audit["profile"] = wrong_value

                result = self.run_comparator(audit, [])

                self.assert_generic_schema_failure(result, "audit profile is invalid")

    def test_audit_complete_wrong_json_types_fail_generically(self) -> None:
        marker = "payload-marker"
        wrong_values = (None, [marker], {marker: "value"}, 17, False)
        for wrong_value in wrong_values:
            with self.subTest(value_type=type(wrong_value).__name__):
                audit = self.audit_payload([])
                audit["complete"] = wrong_value

                result = self.run_comparator(audit, [])

                self.assert_generic_schema_failure(result, "audit is incomplete")

    def test_top_level_audit_rejects_extra_payload_fields(self) -> None:
        audit = self.audit_payload([])
        audit["payload-marker"] = "must-not-be-echoed"

        result = self.run_comparator(audit, [])

        self.assert_generic_schema_failure(result, "audit schema is invalid")

    def test_finding_fields_reject_every_wrong_json_type_without_traceback(self) -> None:
        valid_finding = {
            "category": "credential",
            "severity": "blocking",
            "source": "committed-content",
            "commit": "0123456789ab",
            "path_id": "abcdef012345",
        }

        for field in ("category", "severity", "source", "commit", "path_id"):
            for wrong_value in self.wrong_json_values():
                with self.subTest(field=field, value_type=type(wrong_value).__name__):
                    finding = dict(valid_finding)
                    finding[field] = wrong_value

                    result = self.run_comparator(self.audit_payload([finding]), [])

                    self.assert_generic_schema_failure(
                        result, "audit finding schema is invalid"
                    )

    def test_record_fields_reject_every_wrong_json_type_without_traceback(self) -> None:
        finding = {
            "category": "repository-link",
            "severity": "review",
            "source": "committed-content",
            "commit": "0123456789ab",
            "path_id": "abcdef012345",
        }
        valid_record = self.review_record(path_id="abcdef012345")

        for field in (
            "category",
            "severity",
            "source",
            "commit",
            "path_id",
            "checks",
            "decision",
            "reviewer",
            "rationale",
        ):
            for wrong_value in self.wrong_json_values():
                with self.subTest(field=field, value_type=type(wrong_value).__name__):
                    record = dict(valid_record)
                    record[field] = wrong_value

                    result = self.run_comparator(
                        self.audit_payload([finding]), [record]
                    )

                    self.assert_generic_schema_failure(
                        result, "review record schema is invalid"
                    )

    def test_top_level_findings_and_reviews_reject_wrong_json_types(self) -> None:
        marker = "payload-marker"
        wrong_containers = (None, {marker: "value"}, 17, True)
        for wrong_value in wrong_containers:
            with self.subTest(field="findings", value_type=type(wrong_value).__name__):
                audit = self.audit_payload([])
                audit["findings"] = wrong_value
                result = self.run_comparator(audit, [])
                self.assert_generic_schema_failure(result, "audit findings are invalid")

            with self.subTest(field="reviews", value_type=type(wrong_value).__name__):
                result = self.run_comparator(self.audit_payload([]), wrong_value)
                self.assert_generic_schema_failure(
                    result, "review record schema is invalid"
                )

        findings_list = self.audit_payload([])
        findings_list["findings"] = [marker]
        self.assert_generic_schema_failure(
            self.run_comparator(findings_list, []),
            "audit finding schema is invalid",
        )
        self.assert_generic_schema_failure(
            self.run_comparator(self.audit_payload([]), [marker]),
            "review record schema is invalid",
        )

    def test_external_tracker_evidence_is_rejected_without_echo(self) -> None:
        tracker = "PUBLIC" + "-123"
        finding = {
            "category": "repository-link",
            "severity": "review",
            "source": "committed-content",
            "commit": "0123456789ab",
        }

        for field in ("reviewer", "rationale"):
            with self.subTest(field=field):
                record = self.review_record(**{field: tracker})
                result = self.run_comparator(
                    self.audit_payload([finding]), [record]
                )

                self.assertEqual(result.returncode, 1)
                self.assertIn("review record schema is invalid", result.stdout)
                self.assertNotIn(tracker, result.stdout + result.stderr)
                self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
