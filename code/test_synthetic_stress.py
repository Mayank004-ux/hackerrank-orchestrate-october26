"""Synthetic stress tests covering Codex architecture guidance edge cases:

1. Replica gap: a record remains in a replica after the primary copy is deleted.
2. Tombstone leak: a tombstone retains prohibited PII such as a phone number.
3. Future evidence: evidence captured after audit_at must not affect the earlier audit.
4. Identity history: multiple historical identifiers must resolve to the correct user.
5. Unknown mapping or insufficient evidence: raises UnknownMappingError without inventing findings.
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
    EvidenceFileMeta,
    EvidenceManifest,
    ObservedResource,
    extract_exposed_pii_fields,
    is_timestamp_le,
)
from code.identity import IdentityResolver, UserIdentity, normalize_phone
from code.policy import PolicyEngine, UnknownMappingError


class TestSyntheticStress(unittest.TestCase):
    """Synthetic edge case and stress tests."""

    @classmethod
    def setUpClass(cls):
        cls.engine = PolicyEngine(dataset_dir="dataset")
        cls.resolver = IdentityResolver(dataset_dir="dataset")

    def test_1_replica_gap(self):
        """1. Replica gap: record remains in replica after primary is deleted."""
        # Simulated scenario: primary copy was deleted, but replica database still has the record
        replica_resource = ObservedResource(
            evidence_id="evidence_replica_01",
            system_id="account_service",
            resource_id="account_gap_999",
            observed_state="PRESENT",
            details={"collection": "customer_profiles", "status": "active", "replica_source": "eu_west_replica"},
            subject_user_id="user_gap_01",
            subject_email="gap.user@example.com",
        )
        # Policy rule for account_service / customer_profiles is DELETE
        res = self.engine.evaluate_resource(replica_resource)
        finding = res.get("finding")
        rem = res.get("remediation")
        ver = res.get("verification")

        self.assertTrue(res["is_violation"])
        self.assertIsNotNone(finding)
        self.assertEqual(finding["operation"], "REPORT_REMAINING_RECORD")
        self.assertEqual(finding["state"], "PRESENT")
        self.assertEqual(finding["evidence_id"], "evidence_replica_01")

        self.assertIsNotNone(rem)
        self.assertEqual(rem["operation"], "DELETE_RECORD")
        self.assertEqual(rem["state"], "ABSENT")
        self.assertEqual(rem["evidence_id"], "")

        self.assertIsNotNone(ver)
        self.assertEqual(ver["operation"], "VERIFY_RECORD_ABSENT")
        self.assertEqual(ver["state"], "ABSENT")

        # Evaluation produces an INCOMPLETE status due to the replica violation
        self.assertTrue(res["is_violation"])
        case_status = "INCOMPLETE" if res["is_violation"] else "COMPLETE"
        self.assertEqual(case_status, "INCOMPLETE")

    def test_2_tombstone_leak(self):
        """2. Tombstone leak: tombstone retains prohibited PII such as phone number."""
        tombstone_record = {
            "resource_id": "tombstone_leak_01",
            "subject_reference": "user_leak_88",
            "phone": "+1-555-432-8765",  # Prohibited direct PII leaked
            "email": None,
            "name": "",
        }
        # Detect exposed direct PII
        exposed = extract_exposed_pii_fields(tombstone_record, DEFAULT_PROHIBITED_PII_FIELDS)
        self.assertIn("phone", exposed)

        # Because prohibited PII is exposed, the tombstone state is PRESENT (non-compliant)
        tombstone_resource = ObservedResource(
            evidence_id="evidence_tombstone_leak",
            system_id="identity_service",
            resource_id="tombstone_leak_01",
            observed_state="PRESENT",
            details={
                "collection": "deleted_customer_references",
                "has_stable_user_id": True,
                "has_exposed_pii": True,
                "exposed_fields": exposed,
                **tombstone_record,
            },
            subject_user_id="user_leak_88",
        )

        res = self.engine.evaluate_resource(tombstone_resource)
        finding = res.get("finding")
        rem = res.get("remediation")
        ver = res.get("verification")

        self.assertTrue(res["is_violation"])
        self.assertIsNotNone(finding)
        self.assertEqual(finding["operation"], "REPORT_EXPOSED_PII")
        self.assertEqual(finding["state"], "PRESENT")

        self.assertIsNotNone(rem)
        self.assertEqual(rem["operation"], "REDACT_RECORD")
        self.assertEqual(rem["state"], "REDACTED")

        self.assertIsNotNone(ver)
        self.assertEqual(ver["operation"], "VERIFY_RECORD_REDACTED")
        self.assertEqual(ver["state"], "REDACTED")

    def test_3_future_evidence(self):
        """3. Future evidence: evidence captured after audit_at must not affect earlier audit."""
        audit_at = "2026-09-01T12:00:00Z"

        meta_past = EvidenceFileMeta("ev_past", "evidence/records/past.json", "account_service", "2026-08-15T00:00:00Z")
        meta_exact = EvidenceFileMeta("ev_exact", "evidence/records/exact.json", "account_service", "2026-09-01T12:00:00Z")
        meta_future = EvidenceFileMeta("ev_future", "evidence/records/future.json", "account_service", "2026-09-01T12:00:01Z")
        meta_late = EvidenceFileMeta("ev_late", "evidence/records/late.json", "account_service", "2026-10-01T00:00:00Z")

        # Temporal filter checks
        self.assertTrue(meta_past.is_valid_for_audit(audit_at))
        self.assertTrue(meta_exact.is_valid_for_audit(audit_at))
        self.assertFalse(meta_future.is_valid_for_audit(audit_at))
        self.assertFalse(meta_late.is_valid_for_audit(audit_at))

        self.assertTrue(is_timestamp_le("2026-08-31T23:59:59Z", audit_at))
        self.assertFalse(is_timestamp_le("2026-09-01T12:00:01Z", audit_at))

    def test_4_identity_history(self):
        """4. Identity history: multiple historical identifiers resolve to the correct user."""
        # user_11 (Haruka Sato) has historical email and phone changes in user_audit_log.csv
        identity = self.resolver.resolve("user_11")
        self.assertIsNotNone(identity)
        self.assertEqual(identity.user_id, "user_11")

        # Verify historical email was recovered into all_emails
        self.assertIn("haruka.s183889@zoho.com", identity.all_emails)
        # Verify current email is in all_emails
        self.assertIn("haruka.s1838@zoho.com", identity.all_emails)
        # Verify resolution by historical email returns the exact same user_id
        resolved_by_old_email = self.resolver.resolve("haruka.s183889@zoho.com")
        self.assertIsNotNone(resolved_by_old_email)
        self.assertEqual(resolved_by_old_email.user_id, "user_11")

        # Verify normalized phone matches differently formatted versions
        self.assertTrue(any(normalize_phone(p) == "819076102507" for p in identity.all_phones))

    def test_5_unknown_mapping_or_insufficient_evidence(self):
        """5. Unknown mapping: raises UnknownMappingError rather than inventing findings."""
        unregistered_resource = ObservedResource(
            evidence_id="evidence_unknown",
            system_id="unregistered_service_999",
            resource_id="cache_entry_001",
            observed_state="PRESENT",
            details={"collection": "unregistered_collection"},
        )

        with self.assertRaises(UnknownMappingError) as ctx:
            self.engine.evaluate_resource(unregistered_resource)

        self.assertIn("unregistered_service_999", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
