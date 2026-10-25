"""Unit tests for the Milestone 1 deterministic backbone.

Tests cover:
1. Current and historical identity resolution.
2. Full dataset resolution across all 518 evaluation cases.
3. Strict timestamp filtering (captured_at <= audit_at).
4. SQL evidence reader (primary vs replica drift).
5. JSON evidence reader (tombstones, lookups, exposed PII vs redacted).
6. Resource-ID linking via system activity logs.
"""

from __future__ import annotations

import csv
import os
import sys
import unittest

# Ensure repository root is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from code.identity import IdentityResolver
from code.evidence_reader import (
    EvidenceManifest,
    JsonEvidenceReader,
    SqlEvidenceReader,
    is_timestamp_le,
)
from code.resource_linker import ResourceLinker


class TestIdentityResolution(unittest.TestCase):
    """Test identity resolution against current and historical datasets."""

    @classmethod
    def setUpClass(cls):
        cls.resolver = IdentityResolver(dataset_dir="dataset")

    def test_direct_identity_resolution(self):
        """Current email resolves to canonical user_id and profile."""
        ident = self.resolver.resolve("amina.elmasri@gmail.com")
        self.assertIsNotNone(ident)
        self.assertEqual(ident.user_id, "user_01")
        self.assertEqual(ident.primary_name, "Amina El-Masri")
        self.assertTrue(ident.matches("amina.elmasri@gmail.com"))
        self.assertTrue(ident.matches("+971 50 482 7316"))

    def test_case_insensitive_resolution(self):
        """Uppercase or mixed-case email resolves accurately."""
        # Case 38 in deletion_requests.csv uses uppercase
        ident = self.resolver.resolve("SIPHO.MOKOENA@GMAIL.COM")
        self.assertIsNotNone(ident)
        self.assertTrue(ident.matches("sipho.mokoena@gmail.com"))

    def test_historical_audit_log_resolution(self):
        """Historical email in user_audit_log.csv resolves to canonical user_id."""
        # In sample case 10, nadia.ionescu@yahoo.com was changed to n.petrescu@yahoo.com
        ident = self.resolver.resolve("nadia.ionescu@yahoo.com")
        self.assertIsNotNone(ident)
        self.assertEqual(ident.user_id, "user_10")
        self.assertIn("nadia.ionescu@yahoo.com", ident.all_emails)
        self.assertIn("n.petrescu@yahoo.com", ident.all_emails)

    def test_full_dataset_resolution(self):
        """Every single case in deletion_requests.csv (518 cases) resolves to a user_id."""
        with open("dataset/deletion_requests.csv", "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            cases = list(reader)

        self.assertEqual(len(cases), 518)
        direct_count = 0
        audit_count = 0

        for case in cases:
            em = case["email"].strip()
            ident = self.resolver.resolve(em)
            self.assertIsNotNone(ident, f"Failed to resolve {case['case_id']}: {em}")
            if em.lower() == ident.primary_email.lower():
                direct_count += 1
            else:
                audit_count += 1

        self.assertEqual(direct_count, 418)
        self.assertEqual(audit_count, 100)


class TestTimestampCutoff(unittest.TestCase):
    """Test strict temporal cutoff filtering: captured_at <= audit_at."""

    def test_is_timestamp_le(self):
        self.assertTrue(is_timestamp_le("2026-08-01T00:00:00Z", "2026-08-01T00:00:00Z"))
        self.assertTrue(is_timestamp_le("2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z"))
        self.assertFalse(is_timestamp_le("2026-08-03T00:00:00Z", "2026-08-02T00:00:00Z"))

    def test_manifest_cutoff_filtering(self):
        manifest = EvidenceManifest(dataset_dir="dataset")
        # Cutoff at 2026-07-01T00:00:00Z should exclude later evidence
        valid_files = manifest.get_valid_files(audit_at="2026-07-01T00:00:00Z")
        self.assertTrue(len(valid_files) > 0)
        for vf in valid_files:
            self.assertTrue(vf.captured_at <= "2026-07-01T00:00:00Z")

        # Evidence captured in September should not appear in July cutoff
        ev54 = manifest.get_file_meta("evidence_54")  # 2026-09-02T23:00:00Z
        self.assertIsNotNone(ev54)
        self.assertFalse(ev54.is_valid_for_audit("2026-07-01T00:00:00Z"))
        self.assertTrue(ev54.is_valid_for_audit("2026-09-03T00:00:00Z"))


class TestSqlEvidenceReader(unittest.TestCase):
    """Test SQL snapshot loading, SQLite execution, and replica drift detection."""

    @classmethod
    def setUpClass(cls):
        cls.resolver = IdentityResolver(dataset_dir="dataset")
        cls.sql_reader = SqlEvidenceReader(dataset_dir="dataset")

    def test_failover_replica_drift(self):
        """Account account_005 exists in failover replica but not in primary (evidence_54)."""
        ident = self.resolver.resolve("leila.haddad@yahoo.com")
        self.assertIsNotNone(ident)

        observed = self.sql_reader.inspect_sql_file(
            rel_path="evidence/databases/customer_accounts_failover_replica_20260902.sql",
            evidence_id="evidence_54",
            identity=ident,
            audit_at="2026-09-08T13:40:00Z",
        )
        # Should find account_005 in customer_profiles_failover_replica
        found = [o for o in observed if o.resource_id == "account_005"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].system_id, "account_service")
        self.assertEqual(found[0].observed_state, "PRESENT")
        self.assertEqual(found[0].details["table"], "customer_profiles_failover_replica")

    def test_search_index_sql_snapshot(self):
        """Search document search_001 exists in search primary snapshot (evidence_57)."""
        ident = self.resolver.resolve("jonas.berg@outlook.com")
        self.assertIsNotNone(ident)

        observed = self.sql_reader.inspect_sql_file(
            rel_path="evidence/databases/customer_search_primary_20260910.sql",
            evidence_id="evidence_57",
            identity=ident,
            audit_at="2026-09-10T09:15:00Z",
        )
        found = [o for o in observed if o.resource_id == "search_001"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].system_id, "search_service")
        self.assertEqual(found[0].observed_state, "PRESENT")


class TestJsonEvidenceReader(unittest.TestCase):
    """Test JSON snapshot bundles and service resource exports."""

    @classmethod
    def setUpClass(cls):
        cls.json_reader = JsonEvidenceReader(dataset_dir="dataset")

    def test_tombstones_and_audit_records(self):
        """Snapshot bundle (evidence_51) contains compliant and non-compliant tombstones."""
        observed = self.json_reader.read_file(
            rel_path="evidence/records/customer_data_snapshot_bundle_20260915.json",
            evidence_id="evidence_51",
            audit_at="2026-09-15T15:00:00Z",
        )
        res_by_id = {o.resource_id: o for o in observed}

        # tombstone_440: name, email, phone are null -> REDACTED (compliant tombstone)
        self.assertIn("tombstone_440", res_by_id)
        t440 = res_by_id["tombstone_440"]
        self.assertEqual(t440.system_id, "identity_service")
        self.assertEqual(t440.observed_state, "REDACTED")
        self.assertEqual(t440.subject_user_id, "user_541")

        # tombstone_9178: exposes Kofi Addo PII -> PRESENT (exposed PII)
        self.assertIn("tombstone_9178", res_by_id)
        t9178 = res_by_id["tombstone_9178"]
        self.assertEqual(t9178.system_id, "identity_service")
        self.assertEqual(t9178.observed_state, "PRESENT")
        self.assertEqual(t9178.subject_user_id, "user_542")

        # audit records: retained present
        self.assertIn("audit_record_6909", res_by_id)
        self.assertEqual(res_by_id["audit_record_6909"].system_id, "security_service")
        self.assertEqual(res_by_id["audit_record_6909"].observed_state, "PRESENT")

    def test_service_resource_export(self):
        """Service export (evidence_92) distinguishes absent profile (404) vs present profile (200)."""
        observed = self.json_reader.read_file(
            rel_path="evidence/records/service_resource_export_20260915_114455.json",
            evidence_id="evidence_92",
            audit_at="2026-09-15T15:00:00Z",
        )
        res_by_id = {o.resource_id: o for o in observed}

        # account_3136 is 404 -> ABSENT
        self.assertIn("account_3136", res_by_id)
        self.assertEqual(res_by_id["account_3136"].observed_state, "ABSENT")

        # account_5334 is 200 -> PRESENT
        self.assertIn("account_5334", res_by_id)
        self.assertEqual(res_by_id["account_5334"].observed_state, "PRESENT")


class TestResourceLinker(unittest.TestCase):
    """Test resource-ID linking via system_activity.csv."""

    @classmethod
    def setUpClass(cls):
        cls.resolver = IdentityResolver(dataset_dir="dataset")
        cls.linker = ResourceLinker(dataset_dir="dataset")

    def test_resource_linking_for_user(self):
        """Linker finds explicit activity associations for a user."""
        ident = self.resolver.resolve("haruka.s1838@zoho.com")  # user_11
        self.assertIsNotNone(ident)

        acts = self.linker.get_user_activities(ident, audit_at="2026-10-01T00:00:00Z")
        res_ids = {a.resource_id for a in acts}
        self.assertIn("account_5762", res_ids)

    def test_populate_user_resources(self):
        """ResourceLinker populates known_resource_ids including secondary target resources."""
        ident = self.resolver.resolve("haruka.s1838@zoho.com")  # user_11
        self.assertIsNotNone(ident)

        res_set = self.linker.populate_user_resources(ident, audit_at="2026-10-01T00:00:00Z")
        self.assertIn("account_5762", res_set)
        self.assertIn("account_5762", ident.known_resource_ids)

    def test_temporal_cutoff_in_activity(self):
        """Activities occurring after audit_at are strictly excluded."""
        ident = self.resolver.resolve("haruka.s1838@zoho.com")  # user_11
        # Activities for account_5762 were at 2026-08-28T10:47:43Z and 2026-09-26T11:07:01Z
        # An audit_at before 2026-08-28 (e.g. 2026-08-01) must exclude account_5762
        acts_early = self.linker.get_user_activities(ident, audit_at="2026-08-01T00:00:00Z")
        res_ids_early = {a.resource_id for a in acts_early}
        self.assertNotIn("account_5762", res_ids_early)


class TestCodexRegressionFindings(unittest.TestCase):
    """Regression tests for Codex's three findings."""

    @classmethod
    def setUpClass(cls):
        cls.resolver = IdentityResolver(dataset_dir="dataset")
        cls.manifest = EvidenceManifest(dataset_dir="dataset")
        cls.sql_reader = SqlEvidenceReader(dataset_dir="dataset")
        cls.json_reader = JsonEvidenceReader(dataset_dir="dataset")

    def test_finding1_resource_mapping_without_direct_identifiers(self):
        """Verify records can be linked through resource_id even when direct email/phone are absent."""
        # Create a synthetic UserIdentity with NO emails, phones, or names, only a known_resource_id
        from code.identity import UserIdentity
        ident = UserIdentity(
            user_id="user_test_unlinked",
            primary_name="",
            primary_email="",
            primary_phone="",
            primary_email_hash="",
            updated_at="2026-01-01T00:00:00Z",
        )
        ident.add_resource_id("account_006")  # linked resource

        # Even with no email/name on identity, matching should occur through source_resource_id=account_006
        observed = self.sql_reader.inspect_sql_file(
            rel_path="evidence/databases/customer_search_primary_20260910.sql",
            evidence_id="evidence_57",
            identity=ident,
            audit_at="2026-09-10T09:15:00Z",
        )
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0].resource_id, "search_001")
        self.assertIn("search_001", ident.known_resource_ids)

    def test_finding2_tombstone_preserves_stable_user_id_and_validates_pii_removal(self):
        """Validate that tombstones preserve stable user_id while checking removal of direct PII."""
        observed = self.json_reader.read_file(
            rel_path="evidence/records/customer_data_snapshot_bundle_20260915.json",
            evidence_id="evidence_51",
            audit_at="2026-09-15T15:00:00Z",
        )
        res_by_id = {o.resource_id: o for o in observed}

        # Compliant tombstone tombstone_440:
        # - stable user_id preserved (subject_reference=user_541)
        # - prohibited direct identifiers (name, email, phone, email_hash) are null
        # - observed_state must be REDACTED
        t440 = res_by_id["tombstone_440"]
        self.assertEqual(t440.observed_state, "REDACTED")
        self.assertEqual(t440.subject_user_id, "user_541")
        self.assertTrue(t440.details["has_stable_user_id"])
        self.assertFalse(t440.details["has_exposed_pii"])

        # Non-compliant tombstone tombstone_9178:
        # - stable user_id preserved (subject_reference=user_542)
        # - prohibited direct identifiers (name, email, phone) are exposed
        # - observed_state must be PRESENT
        t9178 = res_by_id["tombstone_9178"]
        self.assertEqual(t9178.observed_state, "PRESENT")
        self.assertEqual(t9178.subject_user_id, "user_542")
        self.assertTrue(t9178.details["has_stable_user_id"])
        self.assertTrue(t9178.details["has_exposed_pii"])

    def test_finding3_select_latest_sql_snapshot_per_system(self):
        """Validate selection of the latest SQL snapshot per origin with captured_at <= audit_at."""
        # For customer_data_inventory_capture at audit_at 2026-05-10:
        # Snapshots exist at: 2026-02-13, 2026-03-10, 2026-04-04, 2026-05-04, 2026-05-24...
        # The latest capture <= 2026-05-10 must be customer_data_inventory_20260504.sql
        latest_snaps = self.manifest.get_latest_sql_snapshots_by_origin(audit_at="2026-05-10T12:00:00Z")
        self.assertIn("customer_data_inventory_capture", latest_snaps)
        meta = latest_snaps["customer_data_inventory_capture"]
        self.assertEqual(meta.file_path, "evidence/databases/customer_data_inventory_20260504.sql")
        self.assertEqual(meta.captured_at, "2026-05-04T09:41:47Z")

        # Later audit_at 2026-08-01 should select customer_data_inventory_20260723.sql
        latest_snaps_aug = self.manifest.get_latest_sql_snapshots_by_origin(audit_at="2026-08-01T12:00:00Z")
        meta_aug = latest_snaps_aug["customer_data_inventory_capture"]
        self.assertEqual(meta_aug.file_path, "evidence/databases/customer_data_inventory_20260723.sql")

    def test_digit_only_phone_normalization(self):
        """Validate phone normalization to digits-only and flexible matching in UserIdentity."""
        from code.identity import normalize_phone

        # Direct normalization checks
        self.assertEqual(normalize_phone("+1 (555) 234-5678"), "15552345678")
        self.assertEqual(normalize_phone("555.234.5678"), "5552345678")
        self.assertEqual(normalize_phone("(555) 234-5678"), "5552345678")
        self.assertEqual(normalize_phone(""), "")
        self.assertEqual(normalize_phone(None), "")

        # Matching in UserIdentity
        user = self.resolver.resolve("user_01")
        self.assertIsNotNone(user)
        # user_01's phone in user_identities.csv
        orig_phone = user.primary_phone
        self.assertTrue(bool(orig_phone))
        # Formatted variations should match via digits-only normalization
        formatted_variant = f"({orig_phone[:3]}) {orig_phone[3:6]}-{orig_phone[6:]}" if len(orig_phone) >= 10 else f"{orig_phone}-ext"
        self.assertTrue(user.matches(formatted_variant))

    def test_configurable_prohibited_pii(self):
        """Validate configurable prohibited PII field detection in evidence_reader."""
        from code.evidence_reader import extract_exposed_pii_fields, DEFAULT_PROHIBITED_PII_FIELDS, JsonEvidenceReader

        test_record = {
            "name": "Jane Doe",
            "email": "jane@example.com",
            "ip_address": "192.168.1.1",
            "device_id": "dev_999",
            "notes": "",
        }

        # Default prohibited fields detect name, email
        exposed_default = extract_exposed_pii_fields(test_record)
        self.assertIn("name", exposed_default)
        self.assertIn("email", exposed_default)
        self.assertNotIn("ip_address", exposed_default)

        # Configurable custom prohibited fields
        custom_fields = set(DEFAULT_PROHIBITED_PII_FIELDS) | {"ip_address", "device_id"}
        exposed_custom = extract_exposed_pii_fields(test_record, prohibited_fields=custom_fields)
        self.assertIn("name", exposed_custom)
        self.assertIn("email", exposed_custom)
        self.assertIn("ip_address", exposed_custom)
        self.assertIn("device_id", exposed_custom)
        self.assertNotIn("notes", exposed_custom)  # empty string is not exposed

        # JsonEvidenceReader accepts custom prohibited fields
        reader = JsonEvidenceReader(dataset_dir="dataset", prohibited_pii_fields={"custom_secret"})
        self.assertEqual(reader.prohibited_pii_fields, {"custom_secret"})


if __name__ == "__main__":
    unittest.main()

