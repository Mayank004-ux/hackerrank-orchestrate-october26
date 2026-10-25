"""Structured evidence readers for SQL and JSON with strict timestamp filtering.

Adheres strictly to the temporal evidence cutoff: captured_at <= audit_at.
Supports SQLite-compatible SQL snapshots and JSON snapshot/export bundles.
"""

from __future__ import annotations

import csv
import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from code.identity import UserIdentity


def is_timestamp_le(t1: str, t2: str) -> bool:
    """Return True if t1 <= t2 in ISO-8601 UTC format.
    
    Falls back to lexicographical comparison which is valid for ISO-8601 UTC strings.
    """
    if not t1 or not t2:
        return False
    # ISO-8601 UTC format (YYYY-MM-DDTHH:MM:SSZ) sorts lexicographically
    return t1.strip() <= t2.strip()


@dataclass
class EvidenceFileMeta:
    """Metadata for an evidence file registered in evidence_files.csv."""
    file_id: str
    file_path: str
    origin: str
    captured_at: str

    def is_valid_for_audit(self, audit_at: str) -> bool:
        """Strict cutoff: captured_at must be <= audit_at."""
        return is_timestamp_le(self.captured_at, audit_at)


class EvidenceManifest:
    """Loads and queries the evidence manifest with strict timestamp filtering."""

    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.files_by_id: dict[str, EvidenceFileMeta] = {}
        self._load_manifest()

    def _load_manifest(self) -> None:
        path = os.path.join(self.dataset_dir, "evidence_files.csv")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Missing evidence manifest: {path}")

        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                fid = row["file_id"].strip()
                fpath = row["file_path"].strip()
                origin = row["origin"].strip()
                captured_at = row["captured_at"].strip()

                self.files_by_id[fid] = EvidenceFileMeta(
                    file_id=fid,
                    file_path=fpath,
                    origin=origin,
                    captured_at=captured_at,
                )

    def get_valid_files(self, audit_at: str) -> list[EvidenceFileMeta]:
        """Return all evidence files captured at or before audit_at."""
        return [meta for meta in self.files_by_id.values() if meta.is_valid_for_audit(audit_at)]

    def get_latest_sql_snapshots_by_origin(self, audit_at: str) -> dict[str, EvidenceFileMeta]:
        """Group SQL snapshots by origin and return the latest capture per origin with captured_at <= audit_at."""
        latest_by_origin: dict[str, EvidenceFileMeta] = {}
        for meta in self.files_by_id.values():
            if not meta.file_path.endswith(".sql"):
                continue
            if not meta.is_valid_for_audit(audit_at):
                continue
            origin = meta.origin
            if origin not in latest_by_origin or meta.captured_at > latest_by_origin[origin].captured_at:
                latest_by_origin[origin] = meta
        return latest_by_origin

    def get_file_meta(self, file_id: str) -> Optional[EvidenceFileMeta]:
        return self.files_by_id.get(file_id)


DEFAULT_PROHIBITED_PII_FIELDS: tuple[str, ...] = (
    "name",
    "full_name",
    "display_name",
    "email",
    "requester_email",
    "customer_email",
    "phone",
    "requester_phone",
    "email_hash",
    "address",
    "date_of_birth",
    "dob",
)


def extract_exposed_pii_fields(
    record: dict[str, Any],
    prohibited_fields: Optional[set[str] | tuple[str, ...]] = None,
) -> list[str]:
    """Check a record for exposed direct PII fields based on configurable field names.
    
    Returns a sorted list of field names that contain non-empty, non-null values.
    """
    if not record or not isinstance(record, dict):
        return []
    fields_to_check = set(prohibited_fields or DEFAULT_PROHIBITED_PII_FIELDS)
    exposed: list[str] = []
    for f in fields_to_check:
        val = record.get(f)
        if val is not None and str(val).strip() != "":
            exposed.append(f)
    return sorted(exposed)


@dataclass
class ObservedResource:
    """A resource observed within an evidence artifact."""
    evidence_id: str
    system_id: str
    resource_id: str
    observed_state: str  # e.g., 'PRESENT', 'ABSENT', 'ACTIVE', 'DISABLED', 'BLOCKED', 'REDACTED', 'ANONYMIZED'
    details: dict[str, Any] = field(default_factory=dict)
    subject_user_id: Optional[str] = None
    subject_email: Optional[str] = None


class JsonEvidenceReader:
    """Reads JSON snapshot bundles and service resource exports with configurable PII checking."""

    def __init__(
        self,
        dataset_dir: str = "dataset",
        prohibited_pii_fields: Optional[set[str] | tuple[str, ...]] = None,
    ):
        self.dataset_dir = dataset_dir
        self.prohibited_pii_fields = set(prohibited_pii_fields or DEFAULT_PROHIBITED_PII_FIELDS)

    def read_file(self, rel_path: str, evidence_id: str, audit_at: str) -> list[ObservedResource]:
        """Parse a JSON evidence file and extract observed resources.
        
        Applies strict temporal filtering on file and record timestamps.
        """
        full_path = os.path.join(self.dataset_dir, rel_path)
        if not os.path.exists(full_path):
            return []

        try:
            with open(full_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return []

        observed: list[ObservedResource] = []

        # 1. Snapshot bundles (customer_data_snapshot_bundle_*.json)
        if "snapshots" in data and isinstance(data["snapshots"], list):
            for snap in data["snapshots"]:
                snap_time = snap.get("captured_at", "")
                if snap_time and not is_timestamp_le(snap_time, audit_at):
                    continue

                data_store = snap.get("data_store", "")
                collection = snap.get("collection", "")
                records = snap.get("records", [])

                for rec in records:
                    res_id = rec.get("resource_id", "")
                    subj_ref = rec.get("subject_reference", "")
                    email = rec.get("email")

                    # Tombstones in identity_service
                    if data_store == "identity_service" and collection == "deleted_customer_references":
                        has_stable_user_id = bool(subj_ref and str(subj_ref).strip() != "")
                        exposed_fields = extract_exposed_pii_fields(rec, self.prohibited_pii_fields)
                        has_exposed_pii = len(exposed_fields) > 0

                        # Compliant tombstone: stable user_id preserved, direct PII removed -> REDACTED
                        # Non-compliant tombstone: direct PII exposed or user_id missing -> PRESENT
                        state = "REDACTED" if (has_stable_user_id and not has_exposed_pii) else "PRESENT"
                        observed.append(ObservedResource(
                            evidence_id=evidence_id,
                            system_id="identity_service",
                            resource_id=res_id,
                            observed_state=state,
                            details={
                                "has_stable_user_id": has_stable_user_id,
                                "has_exposed_pii": has_exposed_pii,
                                "exposed_fields": exposed_fields,
                                **rec,
                            },
                            subject_user_id=subj_ref,
                            subject_email=email,
                        ))

                    # Audit events in security_service
                    elif data_store == "security_service" and collection == "security_audit_events":
                        observed.append(ObservedResource(
                            evidence_id=evidence_id,
                            system_id="security_service",
                            resource_id=res_id,
                            observed_state="PRESENT",
                            details=rec,
                            subject_user_id=subj_ref,
                        ))

                    # Customer profiles in account_service
                    elif data_store == "account_service":
                        observed.append(ObservedResource(
                            evidence_id=evidence_id,
                            system_id="account_service",
                            resource_id=res_id,
                            observed_state="PRESENT",
                            details=rec,
                            subject_user_id=subj_ref,
                            subject_email=email,
                        ))

        # 2. Service resource exports (service_resource_export_*.json)
        elif "service_exports" in data and isinstance(data["service_exports"], dict):
            exports = data["service_exports"]

            # account_service
            if "account_service" in exports:
                for lookup in exports["account_service"].get("profile_lookups", []):
                    res_id = lookup.get("resource_id", "")
                    status_code = lookup.get("status_code", 0)
                    prof = lookup.get("profile")
                    state = "ABSENT" if (status_code == 404 or prof is None) else "PRESENT"
                    email = prof.get("email") if isinstance(prof, dict) else None
                    subj_ref = prof.get("customer_reference") if isinstance(prof, dict) else None

                    observed.append(ObservedResource(
                        evidence_id=evidence_id,
                        system_id="account_service",
                        resource_id=res_id,
                        observed_state=state,
                        details=lookup,
                        subject_user_id=subj_ref,
                        subject_email=email,
                    ))

            # search_service
            if "search_service" in exports:
                for query in exports["search_service"].get("index_queries", []):
                    res_id = query.get("resource_id", "")
                    result = query.get("result", "")
                    hits = query.get("hits", {})
                    docs = hits.get("documents", []) if isinstance(hits, dict) else []
                    total = hits.get("total", 0) if isinstance(hits, dict) else 0

                    if docs:
                        for doc in docs:
                            doc_res_id = doc.get("resource_id", res_id)
                            doc_email = doc.get("email") or query.get("query")
                            doc_ref = doc.get("customer_reference")
                            observed.append(ObservedResource(
                                evidence_id=evidence_id,
                                system_id="search_service",
                                resource_id=doc_res_id,
                                observed_state="PRESENT" if total > 0 else "ABSENT",
                                details=doc,
                                subject_user_id=doc_ref,
                                subject_email=doc_email,
                            ))
                    else:
                        state = "PRESENT" if (result == "hit" or total > 0) else "ABSENT"
                        email = query.get("email") or query.get("query")
                        subj_ref = query.get("customer_reference")
                        observed.append(ObservedResource(
                            evidence_id=evidence_id,
                            system_id="search_service",
                            resource_id=res_id,
                            observed_state=state,
                            details=query,
                            subject_user_id=subj_ref,
                            subject_email=email,
                        ))

            # analytics_platform
            if "analytics_platform" in exports:
                for prof in exports["analytics_platform"].get("profiles", []):
                    res_id = prof.get("resource_id", "")
                    email = prof.get("email")
                    subj_ref = prof.get("customer_reference")
                    # If email or phone or customer_reference is present, PII is exposed
                    has_pii = bool(email or prof.get("phone") or subj_ref)
                    state = "PRESENT" if has_pii else "ANONYMIZED"

                    observed.append(ObservedResource(
                        evidence_id=evidence_id,
                        system_id="analytics_platform",
                        resource_id=res_id,
                        observed_state=state,
                        details=prof,
                        subject_user_id=subj_ref,
                        subject_email=email,
                    ))

            # support_platform
            if "support_platform" in exports:
                for ticket in exports["support_platform"].get("tickets", []):
                    res_id = ticket.get("resource_id", "")
                    email = ticket.get("requester_email")
                    subj_ref = ticket.get("customer_reference")
                    has_pii = bool(email or ticket.get("requester_phone") or ticket.get("requester_name"))
                    state = "PRESENT" if has_pii else "REDACTED"

                    observed.append(ObservedResource(
                        evidence_id=evidence_id,
                        system_id="support_platform",
                        resource_id=res_id,
                        observed_state=state,
                        details=ticket,
                        subject_user_id=subj_ref,
                        subject_email=email,
                    ))

            # integration_service
            if "integration_service" in exports:
                for conn in exports["integration_service"].get("connectors", []):
                    res_id = conn.get("resource_id", "")
                    enabled = conn.get("enabled", False)
                    email = conn.get("customer_email")
                    subj_ref = conn.get("customer_reference")
                    state = "ACTIVE" if enabled else "DISABLED"

                    observed.append(ObservedResource(
                        evidence_id=evidence_id,
                        system_id="integration_service",
                        resource_id=res_id,
                        observed_state=state,
                        details=conn,
                        subject_user_id=subj_ref,
                        subject_email=email,
                    ))

            # backup_service
            if "backup_service" in exports:
                for rentry in exports["backup_service"].get("restore_entries", []):
                    res_id = rentry.get("resource_id", "")
                    restore_allowed = rentry.get("restore_allowed", False)
                    email = rentry.get("customer_email")
                    subj_ref = rentry.get("customer_reference")
                    state = "ACTIVE" if restore_allowed else "BLOCKED"

                    observed.append(ObservedResource(
                        evidence_id=evidence_id,
                        system_id="backup_service",
                        resource_id=res_id,
                        observed_state=state,
                        details=rentry,
                        subject_user_id=subj_ref,
                        subject_email=email,
                    ))

            # security_service
            if "security_service" in exports:
                for audit_rec in exports["security_service"].get("audit_records", []):
                    res_id = audit_rec.get("resource_id", "")
                    subj_ref = audit_rec.get("subject_reference")
                    observed.append(ObservedResource(
                        evidence_id=evidence_id,
                        system_id="security_service",
                        resource_id=res_id,
                        observed_state="PRESENT",
                        details=audit_rec,
                        subject_user_id=subj_ref,
                    ))

            # export_service
            if "export_service" in exports:
                for exp in exports["export_service"].get("exports", []):
                    res_id = exp.get("resource_id", "")
                    email = exp.get("customer_email") or exp.get("owner_email")
                    subj_ref = exp.get("customer_reference")
                    status = exp.get("export_status", "")
                    state = "PRESENT" if (status in ("ACTIVE", "AVAILABLE") or exp.get("object_key")) else "ABSENT"
                    if status in ("DELETED", "EXPIRED"):
                        state = "ABSENT"

                    observed.append(ObservedResource(
                        evidence_id=evidence_id,
                        system_id="export_service",
                        resource_id=res_id,
                        observed_state=state,
                        details=exp,
                        subject_user_id=subj_ref,
                        subject_email=email,
                    ))

        # 3. Root-level collection files (e.g. customer_export_jobs_*.json, customer_analytics_report_*.json)
        elif "collection" in data and "records" in data and isinstance(data["records"], list):
            captured_at = data.get("captured_at", "")
            if not captured_at or is_timestamp_le(captured_at, audit_at):
                col = data.get("collection", "")
                records = data.get("records", [])

                # Determine default system_id from collection name
                default_sys = "account_service"
                if "export" in col:
                    default_sys = "export_service"
                elif "analytics" in col:
                    default_sys = "analytics_platform"
                elif "connector" in col or "integration" in col:
                    default_sys = "integration_service"
                elif "audit" in col or "security" in col:
                    default_sys = "security_service"
                elif "search" in col:
                    default_sys = "search_service"
                elif "support" in col:
                    default_sys = "support_platform"

                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    res_id = rec.get("resource_id", "")
                    subj_ref = rec.get("user_id") or rec.get("customer_reference") or rec.get("subject_reference")
                    email = rec.get("email") or rec.get("owner_email") or rec.get("customer_email")

                    # Determine state based on service & fields
                    state = "PRESENT"
                    if default_sys == "export_service":
                        state = "PRESENT" if rec.get("download_available", True) and rec.get("status", "available") not in ("deleted", "expired") else "ABSENT"
                    elif default_sys == "analytics_platform":
                        has_pii = any(rec.get(f) for f in ("user_id", "email", "phone", "email_hash", "customer_reference"))
                        state = "PRESENT" if has_pii else "ANONYMIZED"
                    elif default_sys == "integration_service":
                        state = "ACTIVE" if rec.get("enabled", False) else "DISABLED"
                    elif default_sys == "backup_service":
                        state = "ACTIVE" if rec.get("restore_allowed", False) else "BLOCKED"

                    observed.append(ObservedResource(
                        evidence_id=evidence_id,
                        system_id=default_sys,
                        resource_id=res_id,
                        observed_state=state,
                        details={"collection": col, **rec},
                        subject_user_id=subj_ref,
                        subject_email=email,
                    ))

        # 4. Operational record exports (e.g. connector_configurations_*.json, customer_export_manifest_*.json, security_audit_ledger_*.json)
        elif "records" in data and isinstance(data["records"], list):
            captured_at = data.get("exported_at") or data.get("captured_at") or ""

            for rec in data["records"]:
                if not isinstance(rec, dict):
                    continue
                rec_time = rec.get("recorded_at") or captured_at
                if rec_time and not is_timestamp_le(rec_time, audit_at):
                    continue

                res_id = rec.get("resource_id", "")
                sys_id = rec.get("system") or rec.get("system_id") or "account_service"
                rec_type = rec.get("record_type", "")
                # Preserve raw evidence state directly from record
                obs_state = str(rec.get("result", "")).strip().upper() or "PRESENT"
                subj_ref = rec.get("subject_reference") or rec.get("customer_reference") or rec.get("user_id")

                email = None
                user_id = None
                if subj_ref:
                    if "@" in str(subj_ref):
                        email = str(subj_ref).strip()
                    else:
                        user_id = str(subj_ref).strip()

                cat = None
                if rec_type in ("USER_PROFILE", "SEARCH_INDEX_ENTRY", "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "ANALYTICS_PROFILE", "USER_EXPORT"):
                    cat = rec_type
                elif rec_type == "SECURITY_AUDIT_LOG":
                    cat = "SECURITY_AUDIT"
                elif rec_type == "LEGAL_HOLD_RECORD":
                    cat = "LEGAL_HOLD"
                elif rec_type == "DATA_FLOW":
                    cat = "ACTIVE_DATA_FLOW"
                elif rec_type == "BACKUP_ARCHIVE":
                    cat = "BACKUP_ARCHIVE"

                observed.append(ObservedResource(
                    evidence_id=evidence_id,
                    system_id=sys_id,
                    resource_id=res_id,
                    observed_state=obs_state,
                    details={"candidate_category": cat, **rec},
                    subject_user_id=user_id,
                    subject_email=email,
                ))

        return observed


class SqlEvidenceReader:
    """Reads SQLite-compatible SQL snapshot exports and inspects tables."""

    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir

    def inspect_sql_file(
        self,
        rel_path: str,
        evidence_id: str,
        identity: UserIdentity,
        audit_at: str,
    ) -> list[ObservedResource]:
        """Execute a SQL snapshot into an in-memory SQLite database and find matching records.
        
        Identifies whether matching records are present in primary or replica tables.
        """
        full_path = os.path.join(self.dataset_dir, rel_path)
        if not os.path.exists(full_path):
            return []

        try:
            with open(full_path, "r", encoding="utf-8") as f:
                sql_script = f.read()
        except Exception:
            return []

        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        try:
            con.executescript(sql_script)
        except Exception:
            con.close()
            return []

        observed: list[ObservedResource] = []

        # Find all user tables
        cursor = con.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cursor.fetchall()]

        # Query all tables for rows matching user identifiers or known resources
        emails_lower = [e.lower() for e in identity.all_emails]
        user_id = identity.user_id
        known_res_lower = {r.lower() for r in identity.known_resource_ids}

        for tbl in tables:
            query_cursor = con.execute(f"SELECT * FROM {tbl}")
            rows = query_cursor.fetchall()

            for row in rows:
                row_dict = dict(row)
                row_res_id = str(row_dict.get("resource_id", "")).strip()
                source_res_id = str(row_dict.get("source_resource_id", "")).strip()

                # Check if this row belongs to the user
                matches = False
                row_email = str(
                    row_dict.get("email", "")
                    or row_dict.get("customer_email", "")
                    or row_dict.get("owner_email", "")
                    or row_dict.get("requester_email", "")
                ).strip().lower()
                row_uid = str(
                    row_dict.get("user_id", "")
                    or row_dict.get("customer_reference", "")
                    or row_dict.get("subject_reference", "")
                ).strip()
                row_phone = str(
                    row_dict.get("phone", "")
                    or row_dict.get("owner_phone", "")
                    or row_dict.get("requester_phone", "")
                ).strip()
                row_hash = str(row_dict.get("email_hash", "")).strip().lower()

                if row_email and row_email in emails_lower:
                    matches = True
                elif row_uid and row_uid == user_id:
                    matches = True
                elif row_phone and identity.matches(row_phone):
                    matches = True
                elif row_hash and row_hash in identity.all_hashes:
                    matches = True
                elif row_res_id and row_res_id.lower() in known_res_lower:
                    matches = True
                elif source_res_id and source_res_id.lower() in known_res_lower:
                    matches = True

                # Also inspect embedded JSON fields if present (record_json, document, details)
                for j_col in ("record_json", "document", "details"):
                    if j_col in row_dict and row_dict[j_col]:
                        try:
                            j_data = json.loads(row_dict[j_col]) if isinstance(row_dict[j_col], str) else row_dict[j_col]
                            if isinstance(j_data, dict):
                                j_email = str(j_data.get("email", "")).strip().lower()
                                j_uid = str(j_data.get("user_id", "") or j_data.get("subject_reference", "") or j_data.get("customer_reference", "")).strip()
                                j_res = str(j_data.get("resource_id", "")).strip().lower()

                                if "document" in j_data and isinstance(j_data["document"], dict):
                                    doc = j_data["document"]
                                    doc_email = str(doc.get("email", "")).strip().lower()
                                    doc_uid = str(doc.get("customer_reference", "") or doc.get("user_id", "")).strip()
                                    if doc_email and doc_email in emails_lower:
                                        matches = True
                                        row_email = doc_email
                                    if doc_uid and doc_uid == user_id:
                                        matches = True
                                        row_uid = doc_uid

                                if j_email and j_email in emails_lower:
                                    matches = True
                                    row_email = j_email
                                if j_uid and j_uid == user_id:
                                    matches = True
                                    row_uid = j_uid
                                if j_res and j_res in known_res_lower:
                                    matches = True
                        except Exception:
                            pass

                if matches and row_res_id:
                    identity.add_resource_id(row_res_id)
                    if source_res_id:
                        identity.add_resource_id(source_res_id)

                    # Determine system_id and collection:
                    # Explicit system/origin columns take precedence over table name heuristic
                    row_sys = str(row_dict.get("system_id", "") or row_dict.get("origin_system", "")).strip()
                    row_col = str(row_dict.get("collection", "") or row_dict.get("collection_name", "")).strip()
                    if row_sys:
                        sys_id = row_sys
                    else:
                        sys_id = "account_service"
                        if "search" in tbl:
                            sys_id = "search_service"
                        elif "analytics" in tbl:
                            sys_id = "analytics_platform"
                        elif "support" in tbl:
                            sys_id = "support_platform"
                        elif "export" in tbl:
                            sys_id = "export_service"
                        elif "backup" in tbl:
                            sys_id = "backup_service"
                        elif "security" in tbl or "audit" in tbl:
                            sys_id = "security_service"
                        elif "connector" in tbl:
                            sys_id = "integration_service"

                    # Determine observed state based on table / inventory semantics
                    obs_state = "PRESENT"
                    if "restore_allowed" in row_dict:
                        val = str(row_dict["restore_allowed"]).strip()
                        obs_state = "ACTIVE" if val in ("1", "true", "True") else "BLOCKED"
                    elif "enabled" in row_dict:
                        val = str(row_dict["enabled"]).strip()
                        obs_state = "ACTIVE" if val in ("1", "true", "True") else "DISABLED"
                    elif sys_id == "analytics_platform" or "analytics" in tbl:
                        has_direct_id = bool(row_email or row_uid or row_dict.get("phone") or row_dict.get("email_hash"))
                        obs_state = "PRESENT" if has_direct_id else "ANONYMIZED"

                    observed.append(ObservedResource(
                        evidence_id=evidence_id,
                        system_id=sys_id,
                        resource_id=row_res_id,
                        observed_state=obs_state,
                        details={"table": tbl, "collection": row_col or tbl, **row_dict},
                        subject_user_id=row_uid or user_id,
                        subject_email=row_email or None,
                    ))

        con.close()
        return observed
