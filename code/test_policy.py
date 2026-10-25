"""Comprehensive unit tests for PolicyEngine and Milestone 2 requirements.

Tests cover:
1. Dynamic deletion rules loading (no hardcoded actions).
2. Evidence-backed system/collection mappings and unknown mapping rejection.
3. DELETE action: PRESENT -> REPORT_REMAINING_RECORD; ABSENT -> compliant.
4. REDACT / Tombstones: compliant (stable user_id + direct PII removed) vs non-compliant (exposed PII).
5. ANONYMIZE action: PRESENT -> REPORT_EXPOSED_PII (per repository contract); ANONYMIZED -> compliant.
6. RETAIN action: PRESENT -> compliant; ABSENT -> marks incomplete without invented finding.
7. Phone number digit-only normalization and matching.
8. Configurable prohibited PII fields.
9. Strict temporal filtering excluding future-dated evidence.
10. Deterministic step sorting and consecutive renumbering.
"""

from __future__ import annotations

import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from code.evidence_reader import (
    DEFAULT_PROHIBITED_PII_FIELDS,
    EvidenceManifest,
    ObservedResource,
    extract_exposed_pii_fields,
)
from code.identity import UserIdentity, normalize_phone
from code.policy import (
    PolicyEngine,
    UnknownMappingError,
    classify_request_intent_heuristic,
)


class TestPolicyEngine(unittest.TestCase):
    """Test PolicyEngine rule evaluations and mappings."""

    @classmethod
    def setUpClass(cls):
        cls.engine = PolicyEngine(dataset_dir="dataset")

    def test_dynamic_rule_loading(self):
        """Rules are dynamically loaded from dataset/deletion_rules.csv."""
        self.assertGreater(len(self.engine.rules_by_category), 10)
        user_prof_rule = self.engine.get_rule_for_category("USER_PROFILE")
        self.assertEqual(user_prof_rule.required_action, "DELETE")
        tombstone_rule = self.engine.get_rule_for_category("ACCOUNT_TOMBSTONE")
        self.assertEqual(tombstone_rule.required_action, "REDACT")
        audit_rule = self.engine.get_rule_for_category("SECURITY_AUDIT_LOG")
        self.assertEqual(audit_rule.required_action, "RETAIN")
        analytics_rule = self.engine.get_rule_for_category("ANALYTICS_PROFILE")
        self.assertEqual(analytics_rule.required_action, "ANONYMIZE")

    def test_system_collection_mapping(self):
        """(system_id, collection) maps to correct data_category."""
        cat = self.engine.get_category_for_system_collection("account_service", "customer_profiles")
        self.assertEqual(cat, "USER_PROFILE")
        cat2 = self.engine.get_category_for_system_collection("identity_service", "deleted_customer_references")
        self.assertEqual(cat2, "ACCOUNT_TOMBSTONE")
        cat3 = self.engine.get_category_for_system_collection("security_service", "security_audit_events")
        self.assertEqual(cat3, "SECURITY_AUDIT_LOG")

    def test_unknown_mapping_raises_error(self):
        """Unknown or unmapped (system_id, collection) raises UnknownMappingError rather than guessing."""
        with self.assertRaises(UnknownMappingError):
            self.engine.get_category_for_system_collection("random_service", "unmapped_table")

    def test_delete_present_generates_finding_and_remediation(self):
        """DELETE + PRESENT -> REPORT_REMAINING_RECORD / PRESENT, DELETE_RECORD / ABSENT, VERIFY_RECORD_ABSENT."""
        obs = ObservedResource(
            evidence_id="evidence_54",
            system_id="account_service",
            resource_id="account_005",
            observed_state="PRESENT",
            details={"collection": "customer_profiles"},
        )
        res = self.engine.evaluate_resource(obs)
        self.assertTrue(res["is_violation"])
        self.assertFalse(res["is_compliant"])

        finding = res["finding"]
        self.assertEqual(finding["operation"], "REPORT_REMAINING_RECORD")
        self.assertEqual(finding["state"], "PRESENT")
        self.assertEqual(finding["evidence_id"], "evidence_54")

        remediation = res["remediation"]
        self.assertEqual(remediation["operation"], "DELETE_RECORD")
        self.assertEqual(remediation["state"], "ABSENT")
        self.assertEqual(remediation["evidence_id"], "")

        verification = res["verification"]
        self.assertEqual(verification["operation"], "VERIFY_RECORD_ABSENT")
        self.assertEqual(verification["state"], "ABSENT")

    def test_delete_absent_is_compliant(self):
        """DELETE + ABSENT -> compliant verification step only."""
        obs = ObservedResource(
            evidence_id="evidence_54",
            system_id="account_service",
            resource_id="account_001",
            observed_state="ABSENT",
            details={"collection": "customer_profiles"},
        )
        res = self.engine.evaluate_resource(obs)
        self.assertFalse(res["is_violation"])
        self.assertTrue(res["is_compliant"])
        self.assertIsNone(res["finding"])
        self.assertIsNone(res["remediation"])
        self.assertEqual(res["verification"]["operation"], "VERIFY_RECORD_ABSENT")

    def test_compliant_tombstone(self):
        """ACCOUNT_TOMBSTONE: stable user_id preserved and direct PII removed -> REDACTED (compliant)."""
        obs = ObservedResource(
            evidence_id="evidence_51",
            system_id="identity_service",
            resource_id="tombstone_440",
            observed_state="REDACTED",
            details={
                "collection": "deleted_customer_references",
                "has_stable_user_id": True,
                "has_exposed_pii": False,
            },
            subject_user_id="user_541",
        )
        res = self.engine.evaluate_resource(obs)
        self.assertFalse(res["is_violation"])
        self.assertTrue(res["is_compliant"])
        self.assertEqual(res["verification"]["operation"], "VERIFY_RECORD_REDACTED")
        self.assertEqual(res["verification"]["state"], "REDACTED")

    def test_non_compliant_tombstone_exposed_pii(self):
        """ACCOUNT_TOMBSTONE with exposed PII -> REPORT_EXPOSED_PII / PRESENT."""
        obs = ObservedResource(
            evidence_id="evidence_51",
            system_id="identity_service",
            resource_id="tombstone_9178",
            observed_state="PRESENT",
            details={
                "collection": "deleted_customer_references",
                "has_stable_user_id": True,
                "has_exposed_pii": True,
            },
            subject_user_id="user_542",
        )
        res = self.engine.evaluate_resource(obs)
        self.assertTrue(res["is_violation"])
        self.assertEqual(res["finding"]["operation"], "REPORT_EXPOSED_PII")
        self.assertEqual(res["finding"]["state"], "PRESENT")
        self.assertEqual(res["remediation"]["operation"], "REDACT_RECORD")
        self.assertEqual(res["remediation"]["state"], "REDACTED")

    def test_anonymize_present_generates_finding(self):
        """ANONYMIZE + PRESENT -> REPORT_EXPOSED_PII / PRESENT per repository contract."""
        obs = ObservedResource(
            evidence_id="evidence_94",
            system_id="analytics_platform",
            resource_id="analytics_037",
            observed_state="PRESENT",
            details={"collection": "customer_analytics_reports"},
        )
        res = self.engine.evaluate_resource(obs)
        self.assertTrue(res["is_violation"])
        self.assertEqual(res["finding"]["operation"], "REPORT_EXPOSED_PII")
        self.assertEqual(res["remediation"]["operation"], "ANONYMIZE_RECORD")
        self.assertEqual(res["remediation"]["state"], "ANONYMIZED")
        self.assertEqual(res["verification"]["operation"], "VERIFY_RECORD_ANONYMIZED")

    def test_anonymize_compliant_record_is_not_violation(self):
        """ANONYMIZE + ANONYMIZED -> compliant without finding or remediation."""
        obs = ObservedResource(
            evidence_id="evidence_94",
            system_id="analytics_platform",
            resource_id="analytics_037",
            observed_state="ANONYMIZED",
            details={"collection": "customer_analytics_reports"},
        )
        res = self.engine.evaluate_resource(obs)
        self.assertFalse(res["is_violation"])
        self.assertTrue(res["is_compliant"])
        self.assertIsNone(res["finding"])
        self.assertIsNone(res["remediation"])
        self.assertEqual(res["verification"]["operation"], "VERIFY_RECORD_ANONYMIZED")
        self.assertEqual(res["verification"]["state"], "ANONYMIZED")


    def test_retain_present_and_absent(self):
        """RETAIN + PRESENT is compliant; RETAIN + ABSENT marks incomplete without invented finding."""
        # Present audit record
        obs_pres = ObservedResource(
            evidence_id="evidence_92",
            system_id="security_service",
            resource_id="audit_record_451",
            observed_state="PRESENT",
            details={"collection": "security_audit_events"},
        )
        res_pres = self.engine.evaluate_resource(obs_pres)
        self.assertTrue(res_pres["is_compliant"])
        self.assertEqual(res_pres["verification"]["operation"], "VERIFY_RECORD_PRESENT")

        # Absent audit record (missing required retention)
        obs_abs = ObservedResource(
            evidence_id="evidence_92",
            system_id="security_service",
            resource_id="audit_record_missing",
            observed_state="ABSENT",
            details={"collection": "security_audit_events"},
        )
        res_abs = self.engine.evaluate_resource(obs_abs)
        self.assertTrue(res_abs["is_violation"])
        self.assertTrue(res_abs.get("missing_required_retention"))
        self.assertIsNone(res_abs["finding"])  # Do not invent an unsupported finding operation


class TestPhoneNormalizationAndPII(unittest.TestCase):
    """Test phone normalization and configurable PII detection."""

    def test_phone_digit_normalization(self):
        """normalize_phone extracts digit-only strings consistently."""
        self.assertEqual(normalize_phone("+971 50 482 7316"), "971504827316")
        self.assertEqual(normalize_phone("+34 612 847 593"), "34612847593")
        self.assertEqual(normalize_phone("+1 (202) 555-0103"), "12025550103")
        self.assertEqual(normalize_phone(""), "")

    def test_user_identity_matches_digit_only_phone(self):
        """UserIdentity matches phone regardless of formatting spaces, dashes, or parentheses."""
        ident = UserIdentity(
            user_id="user_test",
            primary_name="Test User",
            primary_email="test@example.com",
            primary_phone="+1 (202) 555-0103",
            primary_email_hash="hash123",
            updated_at="2026-01-01T00:00:00Z",
        )
        ident.all_phones.add("+1 (202) 555-0103")

        # Must match digit-only string
        self.assertTrue(ident.matches("12025550103"))
        # Must match raw string
        self.assertTrue(ident.matches("+1 (202) 555-0103"))
        # Must match dashed string
        self.assertTrue(ident.matches("1-202-555-0103"))

    def test_configurable_pii_fields(self):
        """extract_exposed_pii_fields detects direct PII fields configurably."""
        rec = {
            "name": "Alex Smith",
            "email": "alex@example.com",
            "address": "123 Main St",
            "dob": "1990-05-15",
            "safe_counter": 42,
        }
        # Default fields include address and dob
        exposed = extract_exposed_pii_fields(rec)
        self.assertIn("address", exposed)
        self.assertIn("dob", exposed)
        self.assertIn("email", exposed)
        self.assertIn("name", exposed)
        self.assertNotIn("safe_counter", exposed)

        # Custom restricted fields
        custom_exposed = extract_exposed_pii_fields(rec, prohibited_fields={"email", "phone"})
        self.assertEqual(custom_exposed, ["email"])


class TestStepSortingAndCutoff(unittest.TestCase):
    """Test deterministic step sorting and temporal cutoff."""

    @classmethod
    def setUpClass(cls):
        cls.engine = PolicyEngine(dataset_dir="dataset")
        cls.manifest = EvidenceManifest(dataset_dir="dataset")

    def test_future_dated_evidence_excluded(self):
        """Evidence captured strictly after audit_at must not be returned."""
        audit_cutoff = "2026-07-01T00:00:00Z"
        valid_files = self.manifest.get_valid_files(audit_cutoff)
        for f in valid_files:
            self.assertLessEqual(f.captured_at, audit_cutoff)

    def test_deterministic_step_sorting(self):
        """Steps are sorted strictly by phase, operation, system_id, and resource_id."""
        raw_steps = [
            {"phase": "VERIFICATION", "operation": "VERIFY_RECORD_ABSENT", "system_id": "account_service", "resource_id": "account_006", "state": "ABSENT", "evidence_id": ""},
            {"phase": "FINDING", "operation": "REPORT_REMAINING_RECORD", "system_id": "search_service", "resource_id": "search_001", "state": "PRESENT", "evidence_id": "evidence_57"},
            {"phase": "REMEDIATION", "operation": "DELETE_RECORD", "system_id": "search_service", "resource_id": "search_001", "state": "ABSENT", "evidence_id": ""},
            {"phase": "VERIFICATION", "operation": "VERIFY_RECORD_ABSENT", "system_id": "search_service", "resource_id": "search_001", "state": "ABSENT", "evidence_id": ""},
        ]
        sorted_steps = self.engine.sort_and_renumber_steps(raw_steps, is_case_complete=False)

        # Step 1 must be FINDING
        self.assertEqual(sorted_steps[0]["step_no"], 1)
        self.assertEqual(sorted_steps[0]["phase"], "FINDING")
        self.assertEqual(sorted_steps[0]["resource_id"], "search_001")
        self.assertEqual(sorted_steps[0]["evidence_id"], "evidence_57")

        # Step 2 must be REMEDIATION
        self.assertEqual(sorted_steps[1]["step_no"], 2)
        self.assertEqual(sorted_steps[1]["phase"], "REMEDIATION")
        self.assertEqual(sorted_steps[1]["operation"], "DELETE_RECORD")
        self.assertEqual(sorted_steps[1]["evidence_id"], "")

        # Steps 3 and 4 must be VERIFICATION ordered by system_id (account_service then search_service)
        self.assertEqual(sorted_steps[2]["step_no"], 3)
        self.assertEqual(sorted_steps[2]["system_id"], "account_service")
        self.assertEqual(sorted_steps[2]["evidence_id"], "")

        self.assertEqual(sorted_steps[3]["step_no"], 4)
        self.assertEqual(sorted_steps[3]["system_id"], "search_service")
        self.assertEqual(sorted_steps[3]["evidence_id"], "")

    def test_complete_case_retains_verification_evidence_id(self):
        """For COMPLETE cases, verification steps preserve non-empty evidence IDs."""
        raw_steps = [
            {"phase": "VERIFICATION", "operation": "VERIFY_RECORD_ABSENT", "system_id": "account_service", "resource_id": "account_001", "state": "ABSENT", "evidence_id": "evidence_54"}
        ]
        sorted_steps = self.engine.sort_and_renumber_steps(raw_steps, is_case_complete=True)
        self.assertEqual(sorted_steps[0]["evidence_id"], "evidence_54")

    def test_temporal_cutoff_exact_second(self):
        """Verify evidence captured even one second after audit_at is excluded."""
        from code.evidence_reader import EvidenceFileMeta, is_timestamp_le

        # 1. Exact ISO comparison logic at 1-second boundary
        t_capture = "2026-05-04T09:41:48Z"
        t_before = "2026-05-04T09:41:47Z"  # 1 second before capture
        t_exact = "2026-05-04T09:41:48Z"   # exact same second
        t_after = "2026-05-04T09:41:49Z"   # 1 second after capture

        meta = EvidenceFileMeta(
            file_id="test_ev",
            file_path="evidence/test.json",
            origin="test_origin",
            captured_at=t_capture,
        )

        # Audit at 1 second before capture: MUST be excluded
        self.assertFalse(meta.is_valid_for_audit(t_before))
        self.assertFalse(is_timestamp_le(t_capture, t_before))

        # Audit at exact capture second: MUST be included (captured_at <= audit_at)
        self.assertTrue(meta.is_valid_for_audit(t_exact))
        self.assertTrue(is_timestamp_le(t_capture, t_exact))

        # Audit at 1 second after capture: MUST be included
        self.assertTrue(meta.is_valid_for_audit(t_after))
        self.assertTrue(is_timestamp_le(t_capture, t_after))

        # 2. Test against real manifest file
        # evidence_01 is captured at 2026-09-15T11:59:39Z
        ev_01 = self.manifest.get_file_meta("evidence_01")
        self.assertIsNotNone(ev_01)
        cap = ev_01.captured_at
        self.assertTrue(cap.endswith("Z"))
        # 1 second before cap
        sec = int(cap[17:19])
        cap_minus_1s = f"{cap[:17]}{sec-1:02d}Z" if sec > 0 else f"{cap[:17]}00Z"
        if sec > 0:
            self.assertFalse(ev_01.is_valid_for_audit(cap_minus_1s))
        self.assertTrue(ev_01.is_valid_for_audit(cap))

    def test_output_contract_allowed_operations_and_states(self):
        """Verify all generated steps comply with AGENTS.md §6.4 allowed operations and states."""
        allowed_findings = {
            ("REPORT_REMAINING_RECORD", "PRESENT"),
            ("REPORT_EXPOSED_PII", "PRESENT"),
            ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
            ("REPORT_RESTORE_RISK", "ACTIVE"),
        }
        allowed_remediations = {
            ("DISABLE_DATA_FLOW", "DISABLED"),
            ("BLOCK_RESTORE", "BLOCKED"),
            ("DELETE_RECORD", "ABSENT"),
            ("REDACT_RECORD", "REDACTED"),
            ("ANONYMIZE_RECORD", "ANONYMIZED"),
        }
        allowed_verifications = {
            ("VERIFY_RECORD_ABSENT", "ABSENT"),
            ("VERIFY_RECORD_PRESENT", "PRESENT"),
            ("VERIFY_RECORD_REDACTED", "REDACTED"),
            ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
            ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
            ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
        }

        # 1. Test DELETE evaluation steps
        del_obs = ObservedResource("ev1", "account_service", "res1", "PRESENT", {"collection": "customer_profiles"})
        del_eval = self.engine.evaluate_resource(del_obs)
        f, r, v = del_eval["finding"], del_eval["remediation"], del_eval["verification"]
        self.assertIn((f["operation"], f["state"]), allowed_findings)
        self.assertIn((r["operation"], r["state"]), allowed_remediations)
        self.assertIn((v["operation"], v["state"]), allowed_verifications)

        # 2. Test REDACT evaluation steps
        red_obs = ObservedResource("ev2", "identity_service", "tomb1", "PRESENT", {"collection": "deleted_customer_references", "has_stable_user_id": True, "has_exposed_pii": True}, subject_user_id="u1")
        red_eval = self.engine.evaluate_resource(red_obs)
        f2, r2, v2 = red_eval["finding"], red_eval["remediation"], red_eval["verification"]
        self.assertIn((f2["operation"], f2["state"]), allowed_findings)
        self.assertIn((r2["operation"], r2["state"]), allowed_remediations)
        self.assertIn((v2["operation"], v2["state"]), allowed_verifications)

        # 3. Test ANONYMIZE evaluation steps
        anon_obs = ObservedResource("ev3", "analytics_platform", "an1", "PRESENT", {"collection": "customer_analytics_reports"})
        anon_eval = self.engine.evaluate_resource(anon_obs)
        f3, r3, v3 = anon_eval["finding"], anon_eval["remediation"], anon_eval["verification"]
        self.assertIn((f3["operation"], f3["state"]), allowed_findings)
        self.assertIn((r3["operation"], r3["state"]), allowed_remediations)
        self.assertIn((v3["operation"], v3["state"]), allowed_verifications)

        # 4. Test ACTIVE DATA FLOW steps
        flow_obs = ObservedResource("ev4", "integration_service", "sync_job_99", "ACTIVE")
        flow_step = self.engine.evaluate_resource(flow_obs)
        ff, rf, vf = flow_step["finding"], flow_step["remediation"], flow_step["verification"]
        self.assertIn((ff["operation"], ff["state"]), allowed_findings)
        self.assertIn((rf["operation"], rf["state"]), allowed_remediations)
        self.assertIn((vf["operation"], vf["state"]), allowed_verifications)

        # 5. Test RESTORE RISK steps
        risk_obs = ObservedResource("ev5", "backup_service", "backup_archive_44", "ACTIVE")
        risk_step = self.engine.evaluate_resource(risk_obs)
        fr, rr, vr = risk_step["finding"], risk_step["remediation"], risk_step["verification"]
        self.assertIn((fr["operation"], fr["state"]), allowed_findings)
        self.assertIn((rr["operation"], rr["state"]), allowed_remediations)
        self.assertIn((vr["operation"], vr["state"]), allowed_verifications)


        # 6. Verify required dictionary keys on all formatted steps
        raw = [f, r, v, ff, rf, vf]
        sorted_steps = self.engine.sort_and_renumber_steps(raw, is_case_complete=False)
        required_keys = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
        for s in sorted_steps:
            self.assertEqual(set(s.keys()), required_keys)
            self.assertIsInstance(s["step_no"], int)


if __name__ == "__main__":
    unittest.main()

