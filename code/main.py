"""End-to-end pipeline runner for Ghost Data Still Exists.

Processes deletion requests, resolves identities, extracts multi-source evidence,
evaluates policy rules, and generates the challenge-required output.csv.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import sys
from typing import Any, Optional

try:
    import pypdf
except ImportError:
    pypdf = None

# Ensure repository root is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

logger = logging.getLogger(__name__)

from code.evidence_reader import (
    DEFAULT_PROHIBITED_PII_FIELDS,
    EvidenceManifest,
    JsonEvidenceReader,
    ObservedResource,
    SqlEvidenceReader,
    extract_exposed_pii_fields,
    is_timestamp_le,
    is_valid_iso_timestamp,
)
from code.identity import IdentityResolver, UserIdentity, normalize_phone
from code.policy import PolicyEngine, UnknownMappingError, classify_request_intent_heuristic
from code.resource_linker import ResourceLinker


def get_observation_timestamp(obs: ObservedResource) -> str:
    """Extract effective observation timestamp from an ObservedResource."""
    if obs.observed_at and is_valid_iso_timestamp(obs.observed_at):
        return obs.observed_at.strip()
    det = obs.details if isinstance(obs.details, dict) else {}
    for k in ("captured_at", "recorded_at", "event_time", "timestamp", "exported_at", "snapshot_time"):
        val = det.get(k)
        if val and isinstance(val, str) and is_valid_iso_timestamp(val):
            return val.strip()
    return ""


class DeletionAuditPipeline:
    """Orchestrates identity resolution, evidence extraction, policy evaluation, and output serialization."""

    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.resolver = IdentityResolver(dataset_dir)
        self.manifest = EvidenceManifest(dataset_dir)
        self.json_reader = JsonEvidenceReader(dataset_dir)
        self.sql_reader = SqlEvidenceReader(dataset_dir)
        self.linker = ResourceLinker(dataset_dir)
        self.engine = PolicyEngine(dataset_dir)
        self.diagnostics: list[dict[str, Any]] = []

    def record_diagnostic(
        self,
        case_id: str,
        system_id: str,
        resource_id: str,
        error_type: str,
        message: str,
    ) -> None:
        """Record diagnostic information for policy evaluation failures without exposing sensitive data."""
        self.diagnostics.append({
            "case_id": case_id,
            "system_id": system_id,
            "resource_id": resource_id,
            "error_type": error_type,
            "message": message,
        })

    def get_diagnostics(self, case_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Retrieve recorded diagnostics, optionally filtered by case_id."""
        if case_id:
            return [d for d in self.diagnostics if d["case_id"] == case_id]
        return list(self.diagnostics)

    def clear_diagnostics(self) -> None:
        """Clear recorded diagnostics."""
        self.diagnostics.clear()

    def extract_text_handover_resources(
        self,
        rel_path: str,
        evidence_id: str,
        identity: UserIdentity,
        audit_at: str,
    ) -> list[ObservedResource]:
        """Extract observed resources from shift handover text files."""
        path = os.path.join(self.dataset_dir, rel_path)
        if not os.path.exists(path):
            return []

        observed: list[ObservedResource] = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_str = line.strip()
                if not line_str or line_str.startswith("#") or not line_str.startswith("-"):
                    continue

                parts = [p.strip() for p in line_str.lstrip("-").split("|")]
                if len(parts) >= 6:
                    ts, sys_id, res_id, cat, state_str, ident_str = parts[:6]
                    if not is_timestamp_le(ts, audit_at):
                        continue

                    # Check match against user identity
                    if identity.matches(ident_str) or res_id in identity.known_resource_ids:
                        s_upper = state_str.upper()
                        if s_upper in ("NOT_FOUND", "ABSENT", "404"):
                            obs_state = "ABSENT"
                        elif s_upper in ("ACTIVE", "BLOCKED", "DISABLED", "ANONYMIZED", "IDENTIFIABLE"):
                            obs_state = s_upper
                        else:
                            obs_state = "PRESENT"

                        observed.append(ObservedResource(
                            evidence_id=evidence_id,
                            system_id=sys_id,
                            resource_id=res_id,
                            observed_state=obs_state,
                            details={"collection": cat, "candidate_category": cat, "raw_state": state_str, "captured_at": ts},
                            subject_user_id=identity.user_id,
                            subject_email=ident_str,
                            observed_at=ts,
                        ))
        return observed

    def extract_log_resources(
        self,
        rel_path: str,
        evidence_id: str,
        identity: UserIdentity,
        audit_at: str,
    ) -> list[ObservedResource]:
        """Extract observed resources from structured log files with trace grouping."""
        path = os.path.join(self.dataset_dir, rel_path)
        if not os.path.exists(path):
            return []

        observed: list[ObservedResource] = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [l.strip() for l in f if l.strip()]

        # 1. Group by trace_id if present
        traces: dict[str, list[str]] = {}
        non_trace_lines: list[str] = []

        for line in lines:
            t_match = re.search(r'\btrace_id=["\']?([a-zA-Z0-9_-]+)["\']?', line)
            if t_match:
                tid = t_match.group(1)
                if tid not in traces:
                    traces[tid] = []
                traces[tid].append(line)
            else:
                non_trace_lines.append(line)

        # Process trace groups
        for tid, tlines in traces.items():
            full_trace_str = " ".join(tlines)
            full_lower = full_trace_str.lower()

            # Check timestamp of trace
            ts_match = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", tlines[0])
            if ts_match and not is_timestamp_le(ts_match.group(1), audit_at):
                continue
            trace_ts = ts_match.group(1) if ts_match else ""

            # Extract resource_id, service, and lookup keys using [:=] to support key=value and JSON "key":"value"
            res_match = re.search(r'\bresource_id["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)["\']?', full_trace_str)
            # If system= is specified, that is the authoritative target system; otherwise fallback to service=
            sys_m = re.search(r'\bsystem["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)["\']?', full_trace_str)
            svc_m = re.search(r'\bservice["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)["\']?', full_trace_str)
            raw_svc = sys_m.group(1) if sys_m else (svc_m.group(1) if svc_m else "")
            lookup_match = re.search(r'\b(?:lookup_key|match_key|owner_key)["\']?\s*[:=]\s*["\']?([^"\', ]+)["\']?', full_trace_str)

            if not res_match or not raw_svc:
                continue

            res_id = res_match.group(1)

            # Canonicalize subservices
            canonical_sys = raw_svc
            if raw_svc == "support_replica":
                canonical_sys = "support_platform"
            elif raw_svc == "search_index_service":
                canonical_sys = "search_service"
            sys_id = canonical_sys

            # Match user identity using word boundaries to prevent substring collisions (e.g. user_43 in user_437)
            matches_user = False
            if lookup_match and identity.matches(lookup_match.group(1)):
                matches_user = True
            elif re.search(r'\b' + re.escape(identity.user_id) + r'\b', full_trace_str, re.IGNORECASE):
                matches_user = True
            elif any(re.search(r'\b' + re.escape(e) + r'\b', full_trace_str, re.IGNORECASE) for e in identity.all_emails):
                matches_user = True
            elif any(re.search(r'\b' + re.escape(h) + r'\b', full_trace_str, re.IGNORECASE) for h in identity.all_hashes):
                matches_user = True
            elif res_id in identity.known_resource_ids:
                matches_user = True

            if not matches_user:
                continue

            # Determine observed state per service semantics
            obs_state = "PRESENT"
            candidate_cat: Optional[str] = None
            if sys_id == "account_service":
                if "rows=0" in full_trace_str or 'rows":"0"' in full_trace_str or "404" in full_trace_str or "not_found" in full_lower:
                    obs_state = "ABSENT"
                else:
                    obs_state = "PRESENT"
            elif sys_id == "security_service":
                obs_state = "PRESENT" if ("rows=1" in full_trace_str or 'rows":"1"' in full_trace_str or "passed" in full_trace_str) else "ABSENT"
            elif sys_id == "integration_service":
                obs_state = "ACTIVE" if ("enabled=true" in full_trace_str or 'enabled":"true"' in full_trace_str) else "DISABLED"
            elif sys_id == "backup_service":
                if "restore_allowed=true" in full_trace_str or 'restore_allowed":"true"' in full_trace_str or 'eligible":"true"' in full_trace_str or 'deletion_block":"false"' in full_trace_str:
                    obs_state = "ACTIVE"
                elif "restore_allowed=false" in full_trace_str or 'restore_allowed":"false"' in full_trace_str or 'deletion_block":"true"' in full_trace_str:
                    obs_state = "BLOCKED"
                else:
                    obs_state = "ACTIVE"
            elif sys_id == "search_service":
                if "result=hit" in full_trace_str or 'result":"hit"' in full_trace_str or "total_hits=1" in full_trace_str or 'total_hits":"1"' in full_trace_str:
                    obs_state = "PRESENT"
                else:
                    obs_state = "ABSENT"
            elif sys_id == "support_platform":
                if "marker_found=false" in full_trace_str:
                    obs_state = "PRESENT"
                    candidate_cat = "SUPPORT_ATTACHMENT"
                else:
                    has_email = any(
                        e.lower() in full_lower for e in identity.all_emails
                        if (f"requester_email={e.lower()}" in full_lower
                            or f'requester_email":"{e.lower()}"' in full_lower
                            or f'matched_value="{e.lower()}"' in full_lower
                            or f'email={e.lower()}' in full_lower
                            or f'email":"{e.lower()}"' in full_lower)
                    )
                    obs_state = "PRESENT" if has_email else "REDACTED"
            candidate_cat = candidate_cat or None
            if sys_id == "analytics_platform":
                if "email_opt_in" in full_lower or "marketing" in full_lower:
                    candidate_cat = "MARKETING_PROFILE"
                    obs_state = "PRESENT" if ("rows=1" in full_trace_str or 'rows":"1"' in full_trace_str) else "ABSENT"
                else:
                    has_pii = any(
                        e.lower() in full_lower for e in identity.all_emails
                        if f"email={e.lower()}" in full_lower or f'email":"{e.lower()}"' in full_lower
                    ) or any(
                        h.lower() in full_lower for h in identity.all_hashes
                        if f"correlation_key={h.lower()}" in full_lower or f'correlation_key":"{h.lower()}"' in full_lower
                    )
                    obs_state = "PRESENT" if has_pii else "ANONYMIZED"

            det = {"trace_lines": tlines, "raw_service": raw_svc, "captured_at": trace_ts}
            if candidate_cat:
                det["candidate_category"] = candidate_cat

            observed.append(ObservedResource(
                evidence_id=evidence_id,
                system_id=sys_id,
                resource_id=res_id,
                observed_state=obs_state,
                details=det,
                subject_user_id=identity.user_id,
                observed_at=trace_ts,
            ))

        # Process standalone lines (like syslog or search diagnostics)
        for line_str in non_trace_lines:
            line_lower = line_str.lower()
            matches_user = (
                any(re.search(r'\b' + re.escape(e) + r'\b', line_str, re.IGNORECASE) for e in identity.all_emails)
                or bool(re.search(r'\b' + re.escape(identity.user_id) + r'\b', line_str, re.IGNORECASE))
                or any(re.search(r'\b' + re.escape(h) + r'\b', line_str, re.IGNORECASE) for h in identity.all_hashes)
                or any(re.search(r'\b' + re.escape(r) + r'\b', line_str, re.IGNORECASE) for r in identity.known_resource_ids)
            )
            if not matches_user:
                continue

            ts_match = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", line_str)
            if ts_match and not is_timestamp_le(ts_match.group(1), audit_at):
                continue
            line_ts = ts_match.group(1) if ts_match else ""

            res_match = re.search(r'\bresource_id=["\']?([a-zA-Z0-9_-]+)["\']?', line_str)
            sys_m = re.search(r'\bsystem=["\']?([a-zA-Z0-9_-]+)["\']?', line_str)
            svc_m = re.search(r'\bservice=["\']?([a-zA-Z0-9_-]+)["\']?', line_str)

            if res_match and (sys_m or svc_m):
                res_id = res_match.group(1)
                sys_id = sys_m.group(1) if sys_m else svc_m.group(1)
                # Canonicalize
                if sys_id == "support_replica":
                    sys_id = "support_platform"
                elif sys_id == "search_index_service":
                    sys_id = "search_service"

                obs_state = "ABSENT" if ("not_found" in line_lower or "rows=0" in line_str or "404" in line_str) else "PRESENT"

                observed.append(ObservedResource(
                    evidence_id=evidence_id,
                    system_id=sys_id,
                    resource_id=res_id,
                    observed_state=obs_state,
                    details={"log_line": line_str, "captured_at": line_ts},
                    subject_user_id=identity.user_id,
                    observed_at=line_ts,
                ))

        return observed


    def extract_pdf_resources(
        self,
        rel_path: str,
        evidence_id: str,
        identity: UserIdentity,
        audit_at: str,
    ) -> list[ObservedResource]:
        """Extract observed resources from PDF documents."""
        if pypdf is None:
            return []

        path = os.path.join(self.dataset_dir, rel_path)
        if not os.path.exists(path):
            return []

        try:
            reader = pypdf.PdfReader(path)
            full_text = "\n".join(page.extract_text() or "" for page in reader.pages)
        except Exception:
            return []

        text_lower = full_text.lower()
        matches_user = (
            any(e.lower() in text_lower for e in identity.all_emails)
            or identity.user_id.lower() in text_lower
            or any(r.lower() in text_lower for r in identity.known_resource_ids)
        )
        if not matches_user:
            return []

        fmeta = self.manifest.get_file_meta(evidence_id)
        pdf_cap = fmeta.captured_at if fmeta else ""

        observed: list[ObservedResource] = []
        # Support attachment pattern
        sup_match = re.search(r'\b(support_\d+)\b', full_text)
        if sup_match:
            is_attachment = ("attachment" in rel_path.lower() or "delivery_correction" in rel_path.lower())
            col_name = "support_attachments" if is_attachment else "support_conversations"
            cat_name = "SUPPORT_ATTACHMENT" if is_attachment else "SUPPORT_MESSAGE"
            observed.append(ObservedResource(
                evidence_id=evidence_id,
                system_id="support_platform",
                resource_id=sup_match.group(1),
                observed_state="PRESENT",
                details={"collection": col_name, "candidate_category": cat_name, "source": "pdf_document", "captured_at": pdf_cap},
                subject_user_id=identity.user_id,
                observed_at=pdf_cap,
            ))

        # Legal hold pattern
        legal_match = re.search(r'\b(legal_hold_\d+)\b', full_text)
        if legal_match:
            observed.append(ObservedResource(
                evidence_id=evidence_id,
                system_id="legal_service",
                resource_id=legal_match.group(1),
                observed_state="PRESENT",
                details={"collection": "retained_order_records", "source": "pdf_document", "captured_at": pdf_cap},
                subject_user_id=identity.user_id,
                observed_at=pdf_cap,
            ))

        return observed

    def collect_case_evidence(
        self,
        identity: UserIdentity,
        audit_at: str,
        requested_at: str = "",
    ) -> list[ObservedResource]:
        """Collect all observed resources across SQL, JSON, logs, text, and PDF evidence <= audit_at."""
        valid_files = self.manifest.get_valid_files(audit_at)
        observed_all: list[ObservedResource] = []

        # 1. Populate known resources from system activity first
        self.linker.populate_user_resources(identity, audit_at=audit_at)

        # 2. Iterate valid evidence files
        for fmeta in valid_files:
            if requested_at and not is_timestamp_le(requested_at, fmeta.captured_at):
                continue
            rel = fmeta.file_path
            fid = fmeta.file_id

            if rel.endswith(".json"):
                items = self.json_reader.read_file(rel, fid, audit_at)
                # Filter items belonging to this identity
                for item in items:
                    if not item.observed_at:
                        item.observed_at = item.details.get("captured_at") or item.details.get("recorded_at") or fmeta.captured_at
                    if self._resource_matches_identity(item, identity):
                        observed_all.append(item)
            elif rel.endswith(".sql"):
                items = self.sql_reader.inspect_sql_file(rel, fid, identity, audit_at)
                for item in items:
                    if not item.observed_at:
                        item.observed_at = fmeta.captured_at
                observed_all.extend(items)
            elif rel.endswith(".log"):
                items = self.extract_log_resources(rel, fid, identity, audit_at)
                for item in items:
                    if not item.observed_at:
                        item.observed_at = fmeta.captured_at
                observed_all.extend(items)
            elif rel.endswith(".txt"):
                items = self.extract_text_handover_resources(rel, fid, identity, audit_at)
                for item in items:
                    if not item.observed_at:
                        item.observed_at = fmeta.captured_at
                observed_all.extend(items)
            elif rel.endswith(".pdf"):
                items = self.extract_pdf_resources(rel, fid, identity, audit_at)
                for item in items:
                    if not item.observed_at:
                        item.observed_at = fmeta.captured_at
                observed_all.extend(items)

        return observed_all

    def _resource_matches_identity(self, obs: ObservedResource, identity: UserIdentity) -> bool:
        """Check if an observed resource belongs to the given subject identity."""
        if obs.subject_user_id and obs.subject_user_id.strip().lower() == identity.user_id.lower():
            return True
        if obs.subject_email and identity.matches(obs.subject_email):
            return True
        if obs.resource_id in identity.known_resource_ids:
            return True

        # Check inside details
        det = obs.details
        if isinstance(det, dict):
            # Check direct reference fields
            for k in ("customer_reference", "subject_reference", "user_id"):
                v = det.get(k)
                if v and str(v).strip().lower() == identity.user_id.lower():
                    return True
            for k in ("email", "customer_email", "owner_email", "requester_email", "query"):
                v = det.get(k)
                if v and identity.matches(str(v).strip()):
                    return True
            # Profile sub-dict
            prof = det.get("profile")
            if isinstance(prof, dict):
                p_em = prof.get("email")
                if p_em and identity.matches(str(p_em).strip()):
                    return True
                p_ref = prof.get("customer_reference")
                if p_ref and str(p_ref).strip().lower() == identity.user_id.lower():
                    return True

        return False


    def select_historical_resources(
        self,
        observed_resources: list[ObservedResource],
        audit_at: str,
    ) -> dict[tuple[str, str], ObservedResource]:
        """Select the relevant historical observation for each (system_id, resource_id) at audit_at.

        Adheres strictly to the following requirements:
        1. Grounded identification: Keyed by (system_id, resource_id) so distinct systems remain distinct.
        2. Cutoff enforcement: Observations recorded after audit_at are strictly discarded.
        3. Valid timestamp precedence: Observations with valid timestamps <= audit_at take precedence over
           observations with missing or invalid timestamps.
        4. Chronological progression: Newer valid observations supersede older ones (e.g. newer ABSENT over older PRESENT).
        5. Conflict resolution at the same latest timestamp:
           - Per AGENTS.md §6.1 / §6.5, if any copy/replica remains at that time, data exists (PRESENT / ACTIVE / IDENTIFIABLE).
           - Deterministic tie-breaking on evidence_id and details.
        """
        grouped: dict[tuple[str, str], list[ObservedResource]] = {}

        for obs in observed_resources:
            sys_id = (obs.system_id or "").strip()
            res_id = (obs.resource_id or "").strip()
            if not sys_id or not res_id:
                continue

            obs_ts = get_observation_timestamp(obs)
            if obs_ts and not is_timestamp_le(obs_ts, audit_at):
                # Strictly after audit cutoff -> discard
                continue

            key = (sys_id, res_id)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(obs)

        selected: dict[tuple[str, str], ObservedResource] = {}

        for key, obs_list in sorted(grouped.items()):
            if len(obs_list) == 1:
                selected[key] = obs_list[0]
                continue

            # Partition into timestamped (valid <= audit_at) and untimestamped
            timestamped = [o for o in obs_list if get_observation_timestamp(o)]
            untimestamped = [o for o in obs_list if not get_observation_timestamp(o)]

            if timestamped:
                latest_ts = max(get_observation_timestamp(o) for o in timestamped)
                latest_candidates = [o for o in timestamped if get_observation_timestamp(o) == latest_ts]
            else:
                latest_candidates = untimestamped

            if len(latest_candidates) == 1:
                selected[key] = latest_candidates[0]
                continue

            # Multiple/conflicting observations at the latest timestamp:
            # Check for remaining copies (PRESENT / ACTIVE / IDENTIFIABLE)
            violation_states = ("PRESENT", "ACTIVE", "IDENTIFIABLE")
            violations = [o for o in latest_candidates if o.observed_state in violation_states]
            if violations:
                violations.sort(key=lambda o: (bool(o.evidence_id), str(o.evidence_id), str(o.details)), reverse=True)
                selected[key] = violations[0]
            else:
                latest_candidates.sort(key=lambda o: (bool(o.evidence_id), str(o.evidence_id), str(o.details)), reverse=True)
                selected[key] = latest_candidates[0]

        return selected

    def evaluate_case(self, request_row: dict[str, str]) -> tuple[str, str, list[dict[str, Any]]]:
        """Evaluate a single deletion request and return (case_id, deletion_status, steps)."""
        case_id = request_row["case_id"].strip()
        email = request_row["email"].strip()
        audit_at = request_row["audit_at"].strip()
        req_text = request_row.get("request_text", "").strip()

        # 1. Authorization check
        intent = classify_request_intent_heuristic(req_text)
        if intent == "NOT_APPLICABLE":
            return case_id, "NOT_APPLICABLE", []
        if intent in ("AMBIGUOUS", "UNKNOWN"):
            msg = f"Ambiguous or unknown request intent for case '{case_id}': cannot safely classify as authorized deletion."
            logger.warning(msg)
            self.record_diagnostic(case_id, "policy_service", "request_intent", "AmbiguousIntentError", msg)
            return case_id, "INCOMPLETE", []

        # 2. Identity resolution and resource linking
        identity = self.resolver.resolve(email)
        if not identity:
            # Authorized deletion request where identity could not be resolved:
            # Must NOT be classified as NOT_APPLICABLE (since request is authorized).
            # Must NOT be classified as COMPLETE (since identity/resource absence cannot be established).
            # Must NOT fabricate resources or evidence.
            msg = f"Identity resolution failed for authorized request in case '{case_id}'"
            logger.warning(msg)
            self.record_diagnostic(case_id, "identity_service", "unresolved_identity", "IdentityResolutionError", msg)
            return case_id, "INCOMPLETE", []

        self.linker.populate_user_resources(identity, audit_at)

        # 3. Evidence extraction
        requested_at = request_row.get("requested_at", "").strip()
        observed_resources = self.collect_case_evidence(identity, audit_at, requested_at)

        # 4. Deduplicate resources and select historical state for each (system_id, resource_id) at audit_at
        selected_resources = self.select_historical_resources(observed_resources, audit_at)

        # 5. Evaluate policy rules on each observed resource
        raw_steps: list[dict[str, Any]] = []
        is_violation_found = False
        evaluation_failed = False

        for (sys_id, res_id), obs in sorted(selected_resources.items()):
            try:
                res_eval = self.engine.evaluate_resource(obs, audit_at=audit_at)
            except UnknownMappingError as err:
                logger.warning(
                    "Unknown mapping for case '%s', resource '%s:%s': %s",
                    case_id, sys_id, res_id, err,
                )
                self.record_diagnostic(case_id, sys_id, res_id, "UnknownMappingError", str(err))
                is_violation_found = True
                evaluation_failed = True
                continue
            except Exception as err:
                logger.error(
                    "Policy evaluation failure for case '%s', resource '%s:%s': %s: %s",
                    case_id, sys_id, res_id, type(err).__name__, err,
                )
                self.record_diagnostic(case_id, sys_id, res_id, type(err).__name__, str(err))
                is_violation_found = True
                evaluation_failed = True
                continue

            if res_eval.get("is_violation"):
                is_violation_found = True
                if res_eval.get("finding"):
                    raw_steps.append(res_eval["finding"])
                if res_eval.get("remediation"):
                    raw_steps.append(res_eval["remediation"])
                if res_eval.get("verification"):
                    raw_steps.append(res_eval["verification"])
            elif res_eval.get("is_compliant"):
                if res_eval.get("verification"):
                    raw_steps.append(res_eval["verification"])

        # Determine deletion status
        # A case is COMPLETE only if:
        # 1. No violation was found and policy evaluation completed without failure
        # 2. Primary account absence is proven by evidence
        # 3. All applicable retention obligations (e.g. required security audit record within supplied
        #    retention period or active legal hold) are verified as satisfied by discovered evidence.
        uid = identity.user_id
        acc_info = self.linker.get_user_resource(uid, "account_service", audit_at)
        has_acc_step = any(s["system_id"] == "account_service" for s in raw_steps)
        acc_has_evidence = False
        if has_acc_step:
            acc_has_evidence = any(s["system_id"] == "account_service" and bool(s.get("evidence_id")) for s in raw_steps)
        elif acc_info and acc_info[1] and not str(acc_info[1]).startswith("activity_") and (acc_info[0].startswith("account_") or acc_info[0].startswith("tombstone_")):
            acc_has_evidence = True

        # Check applicable retention obligations:
        retention_satisfied = True

        # Security audit log obligation (rule_12: "Record is within the supplied retention period"):
        # Evaluated when a security audit record is grounded in evidence or required by active compliance extract.
        # We do not assume every historical event in user_audit_log requires indefinite retention.
        aud_info = self.linker.get_user_resource(uid, "security_service", audit_at)
        if aud_info and not aud_info[1]:
            retention_satisfied = False

        # Legal hold obligation (rule_13: "A supplied legal hold is active"):
        # Evaluated when a legal hold is grounded in evidence for this user.
        legal_info = self.linker.get_user_resource(uid, "legal_service", audit_at)
        if legal_info and not legal_info[1]:
            retention_satisfied = False

        # Check explicit or test-grounded active retention obligations
        active_obligations = getattr(identity, "active_retention_obligations", set())
        for svc in active_obligations:
            svc_in_steps = any(
                s["system_id"] == svc and s["operation"] == "VERIFY_RECORD_PRESENT" and bool(s.get("evidence_id"))
                for s in raw_steps
            )
            svc_info = self.linker.get_user_resource(uid, svc, audit_at)
            if not svc_in_steps and not (svc_info and svc_info[1]):
                retention_satisfied = False

        is_complete = (not is_violation_found) and (not evaluation_failed) and acc_has_evidence and retention_satisfied
        case_status = "COMPLETE" if is_complete else "INCOMPLETE"

        # 1. Primary account verification in account_service
        if not has_acc_step and acc_info and (acc_info[0].startswith("account_") or acc_info[0].startswith("tombstone_")):
            acc_id, evid = acc_info
            evid_clean = evid if not str(evid).startswith("activity_") else ""
            if is_complete and evid_clean:
                raw_steps.append({
                    "step_no": 999,
                    "phase": "VERIFICATION",
                    "system_id": "account_service",
                    "resource_id": acc_id,
                    "operation": "VERIFY_RECORD_ABSENT",
                    "state": "ABSENT",
                    "evidence_id": evid_clean,
                })
            elif not is_complete:
                raw_steps.append({
                    "step_no": 999,
                    "phase": "VERIFICATION",
                    "system_id": "account_service",
                    "resource_id": acc_id,
                    "operation": "VERIFY_RECORD_ABSENT",
                    "state": "ABSENT",
                    "evidence_id": "",
                })

        # 2. Retained security audit record verification
        has_audit = any(s["system_id"] == "security_service" for s in raw_steps)
        if not has_audit:
            aud_info = self.linker.get_user_resource(uid, "security_service", audit_at)
            if aud_info:
                aud_id, evid = aud_info
                aud_cap = self.linker.get_resource_captured_at(uid, "security_service", aud_id, audit_at)
                if (is_complete and evid) or (not is_complete and is_timestamp_le(requested_at, aud_cap)):
                    raw_steps.append({
                        "step_no": 999,
                        "phase": "VERIFICATION",
                        "system_id": "security_service",
                        "resource_id": aud_id,
                        "operation": "VERIFY_RECORD_PRESENT",
                        "state": "PRESENT",
                        "evidence_id": evid if is_complete else "",
                    })

        # 3. Anonymized analytics verification (for COMPLETE cases)
        if is_complete:
            has_ana = any(s["system_id"] == "analytics_platform" for s in raw_steps)
            if not has_ana:
                ana_info = self.linker.get_user_resource(uid, "analytics_platform", audit_at)
                if ana_info and ana_info[1]:
                    ana_id, evid = ana_info
                    raw_steps.append({
                        "step_no": 999,
                        "phase": "VERIFICATION",
                        "system_id": "analytics_platform",
                        "resource_id": ana_id,
                        "operation": "VERIFY_RECORD_ANONYMIZED",
                        "state": "ANONYMIZED",
                        "evidence_id": evid,
                    })

        # Step deduplication: ensure duplicate observations or rules do not create duplicate audit steps
        deduped_raw_steps: list[dict[str, Any]] = []
        seen_step_signatures: set[tuple[str, str, str, str]] = set()

        for s in raw_steps:
            sig = (s["phase"], s["system_id"], s["resource_id"], s["operation"])
            if sig not in seen_step_signatures:
                seen_step_signatures.add(sig)
                deduped_raw_steps.append(s)
            else:
                for existing in deduped_raw_steps:
                    if (existing["phase"], existing["system_id"], existing["resource_id"], existing["operation"]) == sig:
                        if not existing.get("evidence_id") and s.get("evidence_id"):
                            existing["evidence_id"] = s["evidence_id"]

        # Ensure strict evidence_id conformance:
        # In INCOMPLETE cases, post-remediation verification must have evidence_id = ""
        # In COMPLETE cases, verification steps must have non-empty evidence_id
        filtered_steps = []
        for s in deduped_raw_steps:
            if not is_complete and s["phase"] in ("REMEDIATION", "VERIFICATION"):
                s["evidence_id"] = ""
                filtered_steps.append(s)
            elif is_complete and s["phase"] == "VERIFICATION":
                if s.get("evidence_id"):
                    filtered_steps.append(s)
            else:
                filtered_steps.append(s)

        # Deterministic sorting and consecutive renumbering
        sorted_steps = self.engine.sort_and_renumber_steps(
            filtered_steps,
            is_case_complete=is_complete,
        )

        return case_id, case_status, sorted_steps

    def run_pipeline(
        self,
        requests_file: str = "dataset/deletion_requests.csv",
        output_file: str = "output.csv",
    ) -> int:
        """Run the full deletion-audit pipeline and write the output CSV.
        
        Returns the number of processed requests.
        """
        if not os.path.exists(requests_file):
            raise FileNotFoundError(f"Missing requests file: {requests_file}")

        with open(requests_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            requests = list(reader)

        output_rows: list[dict[str, Any]] = []

        for req in requests:
            cid, status, steps = self.evaluate_case(req)
            steps_json_str = json.dumps(steps, separators=(",", ":"))
            output_rows.append({
                "case_id": cid,
                "deletion_status": status,
                "steps_json": steps_json_str,
            })

        # Ensure rows are sorted by case_id
        output_rows.sort(key=lambda r: r["case_id"])

        # Ensure target directory exists
        out_dir = os.path.dirname(os.path.abspath(output_file))
        if out_dir and not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)

        with open(output_file, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
            writer.writeheader()
            for r in output_rows:
                writer.writerow(r)

        return len(output_rows)


def main():
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists — Deletion Audit Pipeline")
    parser.add_argument("--dataset-dir", default="dataset", help="Path to dataset directory")
    parser.add_argument("--requests-file", default="dataset/deletion_requests.csv", help="Path to input requests CSV")
    parser.add_argument("--output", default="output.csv", help="Path to destination output.csv")
    args = parser.parse_args()

    pipeline = DeletionAuditPipeline(dataset_dir=args.dataset_dir)
    count = pipeline.run_pipeline(requests_file=args.requests_file, output_file=args.output)
    print(f"Pipeline successfully generated {args.output} with {count} evaluated requests.")


if __name__ == "__main__":
    main()
