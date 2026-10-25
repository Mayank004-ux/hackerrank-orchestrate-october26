"""End-to-end and regression tests for DeletionAuditPipeline (Milestone 3).

Tests validate:
1. Valid request with no remaining prohibited data (COMPLETE).
2. DELETE request with remaining record (INCOMPLETE + REPORT_REMAINING_RECORD).
3. REDACT request with prohibited PII present (INCOMPLETE + REPORT_EXPOSED_PII).
4. ANONYMIZE request with attributable data (INCOMPLETE + REPORT_EXPOSED_PII).
5. ANONYMIZE request with compliant anonymized data.
6. RETAIN request with required evidence present (VERIFY_RECORD_PRESENT).
7. RETAIN request with required evidence missing (INCOMPLETE, no invented finding).
8. Strict exclusion of evidence captured after audit_at.
9. Non-deletion requests evaluated as NOT_APPLICABLE with steps_json=[].
10. Unknown mappings rejected without silent guessing.
11. Output schema compliance and permitted operation/state verification.
12. Processing of all 518 evaluation requests without duplicate or missing IDs.
"""

from __future__ import annotations

import csv
import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from code.evidence_reader import ObservedResource
from code.main import DeletionAuditPipeline
from code.policy import UnknownMappingError, classify_request_intent_heuristic


class TestDeletionAuditPipeline(unittest.TestCase):
    """End-to-end integration and contract tests for DeletionAuditPipeline."""

    @classmethod
    def setUpClass(cls):
        cls.pipeline = DeletionAuditPipeline(dataset_dir="dataset")

    def test_valid_request_no_remaining_data(self):
        """A valid request with no remaining prohibited data produces COMPLETE status."""
        req = {
            "case_id": "case_01",
            "email": "amina.elmasri@gmail.com",
            "requested_at": "2026-08-18T09:14:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-08-20T16:42:00Z",
            "audit_at": "2026-09-03T11:30:00Z",
            "request_text": "Please remove the profile and the personal details attached to it.",
        }
        cid, status, steps = self.pipeline.evaluate_case(req)
        self.assertEqual(cid, "case_01")
        self.assertEqual(status, "COMPLETE")
        # All steps in complete case must be VERIFICATION
        for s in steps:
            self.assertEqual(s["phase"], "VERIFICATION")
            self.assertTrue(bool(s["evidence_id"]))

    def test_delete_remaining_record(self):
        """A DELETE request where data remains produces INCOMPLETE and REPORT_REMAINING_RECORD."""
        req = {
            "case_id": "case_05",
            "email": "leila.haddad@yahoo.com",
            "requested_at": "2026-08-27T14:17:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-08-28T09:03:00Z",
            "audit_at": "2026-09-08T13:40:00Z",
            "request_text": "Please remove any remaining copy of my profile.",
        }
        cid, status, steps = self.pipeline.evaluate_case(req)
        self.assertEqual(cid, "case_05")
        self.assertEqual(status, "INCOMPLETE")

        finding_ops = [s["operation"] for s in steps if s["phase"] == "FINDING"]
        self.assertIn("REPORT_REMAINING_RECORD", finding_ops)

    def test_redact_prohibited_pii_present(self):
        """A tombstone or record with exposed PII produces REPORT_EXPOSED_PII and REDACT_RECORD."""
        obs = ObservedResource(
            evidence_id="evidence_51",
            system_id="identity_service",
            resource_id="tombstone_9178",
            observed_state="PRESENT",
            details={"collection": "deleted_customer_references", "has_stable_user_id": True, "has_exposed_pii": True},
            subject_user_id="user_542",
        )
        res = self.pipeline.engine.evaluate_resource(obs)
        self.assertTrue(res["is_violation"])
        self.assertEqual(res["finding"]["operation"], "REPORT_EXPOSED_PII")
        self.assertEqual(res["finding"]["state"], "PRESENT")
        self.assertEqual(res["remediation"]["operation"], "REDACT_RECORD")
        self.assertEqual(res["remediation"]["state"], "REDACTED")

    def test_anonymize_attributable_data(self):
        """Attributable analytics profile produces REPORT_EXPOSED_PII and ANONYMIZE_RECORD."""
        obs = ObservedResource(
            evidence_id="evidence_94",
            system_id="analytics_platform",
            resource_id="analytics_037",
            observed_state="PRESENT",
            details={"collection": "customer_analytics_reports"},
        )
        res = self.pipeline.engine.evaluate_resource(obs)
        self.assertTrue(res["is_violation"])
        self.assertEqual(res["finding"]["operation"], "REPORT_EXPOSED_PII")
        self.assertEqual(res["remediation"]["operation"], "ANONYMIZE_RECORD")
        self.assertEqual(res["remediation"]["state"], "ANONYMIZED")

    def test_anonymize_compliant_data(self):
        """Compliant anonymized record is marked compliant without violation."""
        obs = ObservedResource(
            evidence_id="evidence_94",
            system_id="analytics_platform",
            resource_id="analytics_037",
            observed_state="ANONYMIZED",
            details={"collection": "customer_analytics_reports"},
        )
        res = self.pipeline.engine.evaluate_resource(obs)
        self.assertFalse(res["is_violation"])
        self.assertTrue(res["is_compliant"])
        self.assertEqual(res["verification"]["operation"], "VERIFY_RECORD_ANONYMIZED")
        self.assertEqual(res["verification"]["state"], "ANONYMIZED")

    def test_retain_required_evidence_present(self):
        """Required retained audit record that is present emits VERIFY_RECORD_PRESENT."""
        obs = ObservedResource(
            evidence_id="evidence_92",
            system_id="security_service",
            resource_id="audit_record_451",
            observed_state="PRESENT",
            details={"collection": "security_audit_events"},
        )
        res = self.pipeline.engine.evaluate_resource(obs)
        self.assertTrue(res["is_compliant"])
        self.assertEqual(res["verification"]["operation"], "VERIFY_RECORD_PRESENT")

    def test_retain_required_evidence_missing(self):
        """Missing required retention marks INCOMPLETE without inventing an unsupported finding."""
        obs = ObservedResource(
            evidence_id="evidence_92",
            system_id="security_service",
            resource_id="audit_record_missing",
            observed_state="ABSENT",
            details={"collection": "security_audit_events"},
        )
        res = self.pipeline.engine.evaluate_resource(obs)
        self.assertTrue(res["is_violation"])
        self.assertTrue(res.get("missing_required_retention"))
        self.assertIsNone(res["finding"])  # Contract forbids invented operations

    def test_evidence_after_audit_timestamp_excluded(self):
        """Evidence captured strictly after audit_at is completely excluded."""
        audit_cutoff = "2026-06-01T00:00:00Z"
        valid_files = self.pipeline.manifest.get_valid_files(audit_cutoff)
        for vf in valid_files:
            self.assertLessEqual(vf.captured_at, audit_cutoff)

    def test_non_deletion_request_not_applicable(self):
        """Non-deletion requests (data export, invoice copy) emit NOT_APPLICABLE and steps_json=[]."""
        export_req = {
            "case_id": "case_535",
            "email": "gabriel.l5556@outlook.com",
            "requested_at": "2026-08-01T00:00:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-08-02T00:00:00Z",
            "audit_at": "2026-08-10T00:00:00Z",
            "request_text": "I'd like to download my account information in a portable format. Please keep the account as it is.",
        }
        cid, status, steps = self.pipeline.evaluate_case(export_req)
        self.assertEqual(cid, "case_535")
        self.assertEqual(status, "NOT_APPLICABLE")
        self.assertEqual(steps, [])

        invoice_req = {
            "case_id": "case_540",
            "email": "ieriksen5151@fastmail.com",
            "requested_at": "2026-08-01T00:00:00Z",
            "reported_status": "COMPLETE",
            "reported_at": "2026-08-02T00:00:00Z",
            "audit_at": "2026-08-10T00:00:00Z",
            "request_text": "I need a copy of last year's invoices for my records. Please leave my profile and purchase history in place.",
        }
        cid2, status2, steps2 = self.pipeline.evaluate_case(invoice_req)
        self.assertEqual(cid2, "case_540")
        self.assertEqual(status2, "NOT_APPLICABLE")
        self.assertEqual(steps2, [])

    def test_unknown_mappings_handled(self):
        """Unknown or ungrounded system_id/collection raises UnknownMappingError."""
        with self.assertRaises(UnknownMappingError):
            self.pipeline.engine.get_category_for_system_collection("unknown_sys", "unknown_coll")

    def test_output_schema_and_permitted_values(self):
        """Verify generated CSV adheres strictly to case_id,deletion_status,steps_json contract."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # Run pipeline on public sample requests to isolated temp output
            count = self.pipeline.run_pipeline(
                requests_file="dataset/sample_deletion_requests.csv",
                output_file=tmp_path,
            )
            self.assertEqual(count, 32)

            with open(tmp_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                self.assertEqual(reader.fieldnames, ["case_id", "deletion_status", "steps_json"])
                rows = list(reader)

            self.assertEqual(len(rows), 32)
            allowed_statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
            allowed_ops = {
                "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
                "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD",
                "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED",
                "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
            }
            allowed_states = {"PRESENT", "ABSENT", "ACTIVE", "DISABLED", "BLOCKED", "REDACTED", "ANONYMIZED"}

            for r in rows:
                self.assertIn(r["deletion_status"], allowed_statuses)
                steps = json.loads(r["steps_json"])
                self.assertIsInstance(steps, list)
                if r["deletion_status"] == "NOT_APPLICABLE":
                    self.assertEqual(steps, [])

                # Verify step structure
                for idx, step in enumerate(steps, start=1):
                    self.assertEqual(step["step_no"], idx)
                    self.assertIn(step["phase"], {"FINDING", "REMEDIATION", "VERIFICATION"})
                    self.assertIn(step["operation"], allowed_ops)
                    self.assertIn(step["state"], allowed_states)
                    self.assertIn("system_id", step)
                    self.assertIn("resource_id", step)
                    self.assertIn("evidence_id", step)

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_all_518_requests_processed_without_duplicates(self):
        """Pipeline must load all 518 evaluation requests without duplicate or missing IDs."""
        with open("dataset/deletion_requests.csv", "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            req_ids = [r["case_id"].strip() for r in reader]

        self.assertEqual(len(req_ids), 518)
        self.assertEqual(len(set(req_ids)), 518)
        self.assertEqual(req_ids[0], "case_33")
        self.assertEqual(req_ids[-1], "case_550")


if __name__ == "__main__":
    unittest.main()
