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
        self, audit: dict[str, Any], reviews: list[dict[str, Any]]
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            audit_file = root / "audit.json"
            review_file = root / "review.json"
            audit_file.write_text(json.dumps(audit), encoding="utf-8")
            review_file.write_text(json.dumps(reviews), encoding="utf-8")
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

    def test_clean_audit_and_empty_reviews_pass(self) -> None:
        result = self.run_comparator(self.audit_payload([]), [])

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "audit review validation: clean\n")
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


if __name__ == "__main__":
    unittest.main()
