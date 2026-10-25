"""Deterministic PolicyEngine for Ghost Data Still Exists.

Applies deletion_rules.csv to evaluated resources and data flows.
Enforces the repository's permitted-operation contract, strict step ordering,
and evidence citation rules.
"""

from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from code.evidence_reader import (
    DEFAULT_PROHIBITED_PII_FIELDS,
    ObservedResource,
    extract_exposed_pii_fields,
    is_timestamp_le,
)


class UnknownMappingError(ValueError):
    """Raised when a system_id and collection mapping is ambiguous or not supported."""
    pass


@dataclass
class DeletionRule:
    """Represents a rule loaded dynamically from deletion_rules.csv."""
    rule_id: str
    data_category: str
    condition: str
    required_action: str  # DELETE, REDACT, ANONYMIZE, RETAIN


@dataclass
class AuditStep:
    """A single step in the steps_json output array."""
    step_no: int
    phase: str  # FINDING, REMEDIATION, VERIFICATION
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_no": self.step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


# Strict operation precedence per problem statement table
PHASE_PRECEDENCE = {
    "FINDING": 1,
    "REMEDIATION": 2,
    "VERIFICATION": 3,
}

OPERATION_PRECEDENCE = {
    # Findings
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
    # Remediation
    "DISABLE_DATA_FLOW": 5,
    "BLOCK_RESTORE": 6,
    "DELETE_RECORD": 7,
    "REDACT_RECORD": 8,
    "ANONYMIZE_RECORD": 9,
    # Verification
    "VERIFY_RECORD_ABSENT": 10,
    "VERIFY_RECORD_PRESENT": 11,
    "VERIFY_RECORD_REDACTED": 12,
    "VERIFY_RECORD_ANONYMIZED": 13,
    "VERIFY_DATA_FLOW_DISABLED": 14,
    "VERIFY_RESTORE_BLOCKED": 15,
}

# Grounded mapping from (system_id, collection) to data_category
SYSTEM_COLLECTION_TO_CATEGORY: dict[tuple[str, str], str] = {
    ("account_service", "customer_profiles"): "USER_PROFILE",
    ("account_service", "profile_lookups"): "USER_PROFILE",
    ("account_service", "customer_profiles_primary"): "USER_PROFILE",
    ("account_service", "customer_profiles_failover_replica"): "USER_PROFILE",
    ("account_service", "customer_profiles_read_replica"): "USER_PROFILE",
    ("identity_service", "deleted_customer_references"): "ACCOUNT_TOMBSTONE",
    ("identity_service", "tombstones"): "ACCOUNT_TOMBSTONE",
    ("search_service", "customer_search_documents"): "SEARCH_INDEX_ENTRY",
    ("search_service", "index_queries"): "SEARCH_INDEX_ENTRY",
    ("search_service", "search_documents_primary"): "SEARCH_INDEX_ENTRY",
    ("cache_service", "cache_entries"): "CACHE_ENTRY",
    ("support_platform", "support_conversations"): "SUPPORT_MESSAGE",
    ("support_platform", "tickets"): "SUPPORT_MESSAGE",
    ("support_platform", "support_records"): "SUPPORT_MESSAGE",
    ("support_platform", "support_attachments"): "SUPPORT_ATTACHMENT",
    ("analytics_platform", "customer_analytics_reports"): "ANALYTICS_PROFILE",
    ("analytics_platform", "profiles"): "ANALYTICS_PROFILE",
    ("analytics_platform", "customer_analytics_profiles"): "ANALYTICS_PROFILE",
    ("analytics_platform", "product_telemetry"): "PRODUCT_TELEMETRY",
    ("export_service", "customer_exports"): "USER_EXPORT",
    ("export_service", "exports"): "USER_EXPORT",
    ("export_service", "customer_export_jobs"): "USER_EXPORT",
    ("export_service", "customer_export_manifest"): "USER_EXPORT",
    ("marketing_platform", "marketing_profiles"): "MARKETING_PROFILE",
    ("notification_service", "email_delivery_logs"): "EMAIL_DELIVERY_LOG",
    ("email_delivery_service", "email_delivery_logs"): "EMAIL_DELIVERY_LOG",
    ("security_service", "security_audit_events"): "SECURITY_AUDIT_LOG",
    ("security_service", "audit_records"): "SECURITY_AUDIT_LOG",
    ("security_service", "security_audit_records"): "SECURITY_AUDIT_LOG",
    ("security_service", "security_audit_ledger"): "SECURITY_AUDIT_LOG",
    ("legal_service", "retained_order_records"): "LEGAL_HOLD_RECORD",
    ("backup_service", "backup_restore_entries"): "BACKUP_ARCHIVE",
    ("backup_service", "restore_entries"): "BACKUP_ARCHIVE",
    ("integration_service", "connector_configurations"): "ACTIVE_DATA_FLOW",
    ("integration_service", "connector_subscriptions"): "ACTIVE_DATA_FLOW",
    ("support_platform", "support_replica"): "SUPPORT_MESSAGE",
    ("search_service", "customer_search_index"): "SEARCH_INDEX_ENTRY",
    ("search_service", "customer_search_indexes"): "SEARCH_INDEX_ENTRY",
}


def classify_request_intent_heuristic(request_text: str) -> str:
    """HEURISTIC_TEMPORARY: Keyword-based request intent detection.
    
    Used only as an explicitly labelled temporary heuristic during development;
    not a substitute for final multilingual intent classification.
    """
    if not request_text:
        return "DELETION"
    text = str(request_text).lower()

    # Explicit non-deletion patterns: access, download/export copy, tax invoice requests
    non_del_keywords = [
        "download my account information",
        "copy of last year",
        "copy of my invoice",
        "copy of invoices",
        "portable format",
        "leave my profile",
        "keep the account active",
        "opt-out of marketing",
        "unsubscribe from newsletter",
    ]
    for kw in non_del_keywords:
        if kw in text:
            # Check if deletion is requested alongside
            if not any(w in text for w in ("delete", "erase", "remove", "close", "supprimer", "eliminar")):
                return "NOT_APPLICABLE"

    return "DELETION"


class PolicyEngine:
    """Loads deletion_rules.csv and evaluates observed resources against deletion policy."""

    def __init__(
        self,
        dataset_dir: str = "dataset",
        prohibited_pii_fields: Optional[set[str] | tuple[str, ...]] = None,
    ):
        self.dataset_dir = dataset_dir
        self.prohibited_pii_fields = set(prohibited_pii_fields or DEFAULT_PROHIBITED_PII_FIELDS)
        self.rules_by_category: dict[str, DeletionRule] = {}
        self._load_rules()

    def _load_rules(self) -> None:
        """Load deletion_rules.csv dynamically; do not hardcode rule actions."""
        path = os.path.join(self.dataset_dir, "deletion_rules.csv")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Missing deletion rules file: {path}")

        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rid = row["rule_id"].strip()
                cat = row["data_category"].strip()
                cond = row.get("condition", "").strip()
                action = row["required_action"].strip().upper()

                self.rules_by_category[cat] = DeletionRule(
                    rule_id=rid,
                    data_category=cat,
                    condition=cond,
                    required_action=action,
                )

    def get_category_for_system_collection(self, system_id: str, collection: str) -> str:
        """Map (system_id, collection) to data_category.
        
        Flags ambiguous or unknown mappings rather than silently guessing.
        """
        col_clean = collection.strip()
        if col_clean in self.rules_by_category:
            return col_clean
        if col_clean in ("ACTIVE_DATA_FLOW", "DATA_FLOW"):
            return "ACTIVE_DATA_FLOW"

        key = (system_id.strip(), col_clean)
        if key in SYSTEM_COLLECTION_TO_CATEGORY:
            return SYSTEM_COLLECTION_TO_CATEGORY[key]
        raise UnknownMappingError(
            f"Unknown or ambiguous evidence mapping for system='{system_id}', collection='{collection}'"
        )

    def get_rule_for_category(self, data_category: str) -> DeletionRule:
        cat = data_category.strip()
        if cat in self.rules_by_category:
            return self.rules_by_category[cat]
        raise UnknownMappingError(f"No deletion rule loaded for category: '{data_category}'")

    def evaluate_resource(
        self,
        observed: ObservedResource,
        collection_override: Optional[str] = None,
        audit_at: Optional[str] = None,
    ) -> dict[str, Any]:
        """Evaluate a single observed resource against policy rules.
        
        Returns:
            dict containing:
                - is_violation: bool
                - is_compliant: bool
                - finding: Optional[dict]
                - remediation: Optional[dict]
                - verification: Optional[dict]
                - rule_action: str
                - data_category: str
        """
        sys_id = observed.system_id
        res_id = observed.resource_id
        ev_id = observed.evidence_id
        state = observed.observed_state

        # 1. Special Handling: Active Data Flows (integration_service)
        if sys_id == "integration_service":
            if state == "ACTIVE":
                return {
                    "is_violation": True,
                    "is_compliant": False,
                    "rule_action": "DISABLE",
                    "data_category": "ACTIVE_DATA_FLOW",
                    "finding": {
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REPORT_ACTIVE_DATA_FLOW",
                        "state": "ACTIVE",
                        "evidence_id": ev_id,
                    },
                    "remediation": {
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "DISABLE_DATA_FLOW",
                        "state": "DISABLED",
                        "evidence_id": "",
                    },
                    "verification": {
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_DATA_FLOW_DISABLED",
                        "state": "DISABLED",
                        "evidence_id": ev_id,
                    },
                }
            else:
                return {
                    "is_violation": False,
                    "is_compliant": True,
                    "rule_action": "DISABLE",
                    "data_category": "ACTIVE_DATA_FLOW",
                    "finding": None,
                    "remediation": None,
                    "verification": {
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_DATA_FLOW_DISABLED",
                        "state": "DISABLED",
                        "evidence_id": ev_id,
                    },
                }

        # 2. Special Handling: Restore Risks (backup_service)
        if sys_id == "backup_service" and ("restore" in res_id.lower() or "backup" in res_id.lower()):
            if state == "ACTIVE":
                return {
                    "is_violation": True,
                    "is_compliant": False,
                    "rule_action": "BLOCK",
                    "data_category": "BACKUP_ARCHIVE",
                    "finding": {
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REPORT_RESTORE_RISK",
                        "state": "ACTIVE",
                        "evidence_id": ev_id,
                    },
                    "remediation": {
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "BLOCK_RESTORE",
                        "state": "BLOCKED",
                        "evidence_id": "",
                    },
                    "verification": {
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RESTORE_BLOCKED",
                        "state": "BLOCKED",
                        "evidence_id": ev_id,
                    },
                }
            else:
                return {
                    "is_violation": False,
                    "is_compliant": True,
                    "rule_action": "BLOCK",
                    "data_category": "BACKUP_ARCHIVE",
                    "finding": None,
                    "remediation": None,
                    "verification": {
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RESTORE_BLOCKED",
                        "state": "BLOCKED",
                        "evidence_id": ev_id,
                    },
                }

        # Determine candidate category or collection
        candidate_cat = observed.details.get("candidate_category")
        if candidate_cat and candidate_cat in self.rules_by_category:
            category = candidate_cat
        else:
            collection = collection_override or observed.details.get("collection") or observed.details.get("table")
            if not collection:
                # Infer collection from resource prefix if unambiguous
                if res_id.startswith("account_"):
                    collection = "customer_profiles"
                elif res_id.startswith("tombstone_"):
                    collection = "deleted_customer_references"
                elif res_id.startswith("search_"):
                    collection = "customer_search_documents"
                elif res_id.startswith("analytics_"):
                    collection = "customer_analytics_reports"
                elif res_id.startswith("support_"):
                    collection = "support_conversations"
                elif res_id.startswith("export_"):
                    collection = "customer_exports"
                elif res_id.startswith("audit_record_"):
                    collection = "security_audit_events"
                elif res_id.startswith("legal_hold_"):
                    collection = "retained_order_records"
                else:
                    collection = "unknown"

            category = self.get_category_for_system_collection(sys_id, collection)

        rule = self.get_rule_for_category(category)

        action = rule.required_action

        # Evaluate based on required action
        # 3. DELETE Action
        if action == "DELETE":
            if state in ("PRESENT", "FOUND", "ACTIVE"):
                return {
                    "is_violation": True,
                    "is_compliant": False,
                    "rule_action": "DELETE",
                    "data_category": category,
                    "finding": {
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REPORT_REMAINING_RECORD",
                        "state": "PRESENT",
                        "evidence_id": ev_id,
                    },
                    "remediation": {
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "DELETE_RECORD",
                        "state": "ABSENT",
                        "evidence_id": "",
                    },
                    "verification": {
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RECORD_ABSENT",
                        "state": "ABSENT",
                        "evidence_id": ev_id,
                    },
                }
            else:  # ABSENT
                return {
                    "is_violation": False,
                    "is_compliant": True,
                    "rule_action": "DELETE",
                    "data_category": category,
                    "finding": None,
                    "remediation": None,
                    "verification": {
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RECORD_ABSENT",
                        "state": "ABSENT",
                        "evidence_id": ev_id,
                    },
                }

        # 4. REDACT Action (Tombstones and Support Messages)
        elif action == "REDACT":
            # For ACCOUNT_TOMBSTONE: check stable user_id preservation and PII removal
            if category == "ACCOUNT_TOMBSTONE":
                has_stable = observed.details.get("has_stable_user_id", True)
                has_exposed = observed.details.get("has_exposed_pii", False)
                if state == "PRESENT" or has_exposed or not has_stable:
                    return {
                        "is_violation": True,
                        "is_compliant": False,
                        "rule_action": "REDACT",
                        "data_category": category,
                        "finding": {
                            "phase": "FINDING",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "REPORT_EXPOSED_PII",
                            "state": "PRESENT",
                            "evidence_id": ev_id,
                        },
                        "remediation": {
                            "phase": "REMEDIATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "REDACT_RECORD",
                            "state": "REDACTED",
                            "evidence_id": "",
                        },
                        "verification": {
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_REDACTED",
                            "state": "REDACTED",
                            "evidence_id": ev_id,
                        },
                    }
                else:  # REDACTED
                    return {
                        "is_violation": False,
                        "is_compliant": True,
                        "rule_action": "REDACT",
                        "data_category": category,
                        "finding": None,
                        "remediation": None,
                        "verification": {
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_REDACTED",
                            "state": "REDACTED",
                            "evidence_id": ev_id,
                        },
                    }
            else:  # Standard REDACT (support message, email delivery log)
                if state in ("PRESENT", "IDENTIFIABLE", "FOUND"):
                    return {
                        "is_violation": True,
                        "is_compliant": False,
                        "rule_action": "REDACT",
                        "data_category": category,
                        "finding": {
                            "phase": "FINDING",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "REPORT_EXPOSED_PII",
                            "state": "PRESENT",
                            "evidence_id": ev_id,
                        },
                        "remediation": {
                            "phase": "REMEDIATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "REDACT_RECORD",
                            "state": "REDACTED",
                            "evidence_id": "",
                        },
                        "verification": {
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_REDACTED",
                            "state": "REDACTED",
                            "evidence_id": ev_id,
                        },
                    }
                else:
                    return {
                        "is_violation": False,
                        "is_compliant": True,
                        "rule_action": "REDACT",
                        "data_category": category,
                        "finding": None,
                        "remediation": None,
                        "verification": {
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_REDACTED",
                            "state": "REDACTED",
                            "evidence_id": ev_id,
                        },
                    }

        # 5. ANONYMIZE Action (Analytics and Telemetry)
        elif action == "ANONYMIZE":
            if state in ("PRESENT", "IDENTIFIABLE"):
                # Following repository contract: REPORT_EXPOSED_PII / PRESENT
                return {
                    "is_violation": True,
                    "is_compliant": False,
                    "rule_action": "ANONYMIZE",
                    "data_category": category,
                    "finding": {
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REPORT_EXPOSED_PII",
                        "state": "PRESENT",
                        "evidence_id": ev_id,
                    },
                    "remediation": {
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "ANONYMIZE_RECORD",
                        "state": "ANONYMIZED",
                        "evidence_id": "",
                    },
                    "verification": {
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RECORD_ANONYMIZED",
                        "state": "ANONYMIZED",
                        "evidence_id": ev_id,
                    },
                }
            else:  # ANONYMIZED
                return {
                    "is_violation": False,
                    "is_compliant": True,
                    "rule_action": "ANONYMIZE",
                    "data_category": category,
                    "finding": None,
                    "remediation": None,
                    "verification": {
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RECORD_ANONYMIZED",
                        "state": "ANONYMIZED",
                        "evidence_id": ev_id,
                    },
                }

        # 6. RETAIN Action (Security Audit Logs, Legal Hold)
        elif action == "RETAIN":
            is_condition_active = True
            if category == "SECURITY_AUDIT_LOG":
                # Condition: "Record is within the supplied retention period"
                ret_until = observed.details.get("retention_until") or observed.details.get("retained_until")
                if ret_until and audit_at:
                    if not is_timestamp_le(audit_at, ret_until):
                        is_condition_active = False
                elif observed.details.get("status") in ("EXPIRED", "DELETED"):
                    is_condition_active = False
            elif category == "LEGAL_HOLD_RECORD":
                # Condition: "A supplied legal hold is active"
                status = str(observed.details.get("status", "")).upper()
                ret_until = observed.details.get("retained_until") or observed.details.get("retention_until")
                if status in ("RELEASED", "LIFTED", "INACTIVE", "EXPIRED"):
                    is_condition_active = False
                elif ret_until and audit_at and not is_timestamp_le(audit_at, ret_until):
                    is_condition_active = False

            if is_condition_active:
                if state in ("PRESENT", "FOUND", "RETAINED"):
                    return {
                        "is_violation": False,
                        "is_compliant": True,
                        "rule_action": "RETAIN",
                        "data_category": category,
                        "finding": None,
                        "remediation": None,
                        "verification": {
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_PRESENT",
                            "state": "PRESENT",
                            "evidence_id": ev_id,
                        },
                    }
                else:  # ABSENT -> Required retained record is missing!
                    # Mark deletion as incomplete without inventing an unsupported finding operation
                    return {
                        "is_violation": True,
                        "is_compliant": False,
                        "missing_required_retention": True,
                        "rule_action": "RETAIN",
                        "data_category": category,
                        "finding": None,
                        "remediation": None,
                        "verification": None,
                    }
            else:
                # Retention condition does NOT apply (retention expired or hold released/inactive)
                # Subject personal data should not remain once retention expires
                if state in ("PRESENT", "FOUND", "ACTIVE"):
                    return {
                        "is_violation": True,
                        "is_compliant": False,
                        "rule_action": "DELETE",
                        "data_category": category,
                        "finding": {
                            "phase": "FINDING",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "REPORT_REMAINING_RECORD",
                            "state": "PRESENT",
                            "evidence_id": ev_id,
                        },
                        "remediation": {
                            "phase": "REMEDIATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "DELETE_RECORD",
                            "state": "ABSENT",
                            "evidence_id": "",
                        },
                        "verification": {
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ABSENT",
                            "state": "ABSENT",
                            "evidence_id": ev_id,
                        },
                    }
                else:
                    return {
                        "is_violation": False,
                        "is_compliant": True,
                        "rule_action": "DELETE",
                        "data_category": category,
                        "finding": None,
                        "remediation": None,
                        "verification": {
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ABSENT",
                            "state": "ABSENT",
                            "evidence_id": ev_id,
                        },
                    }

        raise UnknownMappingError(f"Unhandled rule action '{action}' for category '{category}'")

    def sort_and_renumber_steps(
        self,
        raw_steps: list[dict[str, Any]],
        is_case_complete: bool,
    ) -> list[dict[str, Any]]:
        """Order steps strictly by phase, operation precedence, system_id, and resource_id.
        
        Renumber step_no consecutively starting at 1.
        For complete cases, verification steps cite evidence.
        For incomplete cases, remediation and post-remediation verification use empty evidence_id.
        """
        def sort_key(s: dict[str, Any]) -> tuple:
            p_val = PHASE_PRECEDENCE.get(s["phase"], 99)
            o_val = OPERATION_PRECEDENCE.get(s["operation"], 99)
            sys_val = str(s.get("system_id", ""))
            res_val = str(s.get("resource_id", ""))
            return (p_val, o_val, sys_val, res_val)

        sorted_steps = sorted(raw_steps, key=sort_key)
        formatted: list[dict[str, Any]] = []

        for idx, s in enumerate(sorted_steps, start=1):
            phase = s["phase"]
            ev_id = str(s.get("evidence_id", ""))

            # Evidence citation rules:
            # - Incomplete remediation: evidence_id = ""
            # - Incomplete verification: evidence_id = ""
            # - Complete verification: evidence_id must be preserved
            # - Findings: evidence_id must be preserved
            if not is_case_complete and phase in ("REMEDIATION", "VERIFICATION"):
                ev_id = ""

            formatted.append({
                "step_no": idx,
                "phase": phase,
                "system_id": s["system_id"],
                "resource_id": s["resource_id"],
                "operation": s["operation"],
                "state": s["state"],
                "evidence_id": ev_id,
            })

        return formatted
