"""Resource-ID linker using system_activity.csv.

Extracts explicit and implicit links between resources, user IDs, and emails
while enforcing the strict temporal cutoff (event_time <= audit_at).
"""

from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from code.evidence_reader import EvidenceManifest, is_timestamp_le
from code.identity import IdentityResolver, UserIdentity


@dataclass
class ActivityLink:
    """A link between a resource and subject established by system activity."""
    activity_id: str
    event_time: str
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str
    linked_user_id: Optional[str] = None
    linked_email: Optional[str] = None


def infer_service_from_resource_id(rid: str, default: str = "account_service") -> str:
    """Infer the hosting service from a resource ID prefix when logs lack explicit service tags."""
    r = rid.strip().lower()
    if r.startswith("account_") or r.startswith("tombstone_"):
        return "account_service"
    if r.startswith("audit_record_") or r.startswith("security_"):
        return "security_service"
    if r.startswith("data_flow_") or r.startswith("connector_"):
        return "integration_service"
    if r.startswith("search_"):
        return "search_service"
    if r.startswith("support_"):
        return "support_platform"
    if r.startswith("analytics_"):
        return "analytics_platform"
    if r.startswith("backup_"):
        return "backup_service"
    return default


class ResourceLinker:
    """Parses and queries activity-based and evidence-based resource links up to audit_at."""

    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.resolver = IdentityResolver(dataset_dir)
        self.manifest = EvidenceManifest(dataset_dir)
        self.all_activities: list[ActivityLink] = []
        self.raw_grounded_entries: list[tuple[str, str, str, str, str]] = [] # uid, sys_name, rid, evid, cap_at
        self.account_ids_by_user: dict[str, list[tuple[str, str]]] = {} # uid -> list of (cap_at, rid)
        self.known_resource_owners: dict[str, list[tuple[str, str]]] = {} # rid -> list of (cap_at, uid)
        self.known_resource_owners_by_system: dict[tuple[str, str], list[tuple[str, str]]] = {} # (sys_name, rid) -> list of (cap_at, uid)
        self.snapshot_present_accounts: list[tuple[str, str, set[str]]] = [] # evid, cap_at, present_ids
        self.empty_account_snapshots: list[tuple[str, str]] = [] # evid, cap_at
        self.snapshot_404_accounts: list[tuple[str, str, str]] = [] # evid, cap_at, rid
        self.request_windows: list[dict[str, str]] = []
        self._load_request_windows()
        self._index_all_evidence()
        self._load_system_activity()
        self._index_snapshot_absence_proofs()

    def _load_request_windows(self) -> None:
        """Load deletion request timeframes to ground workflow activities without hardcoding."""
        for fname in ("sample_deletion_requests.csv", "deletion_requests.csv"):
            fpath = os.path.join(self.dataset_dir, fname)
            if not os.path.exists(fpath):
                continue
            with open(fpath, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    em = row.get("email", "").strip()
                    req_at = row.get("requested_at", "").strip()
                    rep_at = row.get("reported_at", "").strip()
                    aud_at = row.get("audit_at", "").strip()
                    cid = row.get("case_id", "").strip()
                    rep_stat = row.get("reported_status", "").strip()
                    if em and req_at and rep_at:
                        ident = self.resolver.resolve(em)
                        if ident:
                            try:
                                dt_rep = datetime.fromisoformat(rep_at.replace("Z", "+00:00")) + timedelta(hours=2)
                                max_rep = dt_rep.isoformat().replace("+00:00", "Z")
                            except Exception:
                                max_rep = rep_at
                            self.request_windows.append({
                                "case_id": cid,
                                "user_id": ident.user_id.lower(),
                                "email": em.lower(),
                                "requested_at": req_at,
                                "reported_at": rep_at,
                                "max_reported_at": max_rep,
                                "audit_at": aud_at,
                                "reported_status": rep_stat,
                            })

    def _load_system_activity(self) -> None:
        path = os.path.join(self.dataset_dir, "system_activity.csv")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Missing system activity log: {path}")

        user_re = re.compile(r"\b(user_\d+)\b", re.IGNORECASE)
        email_re = re.compile(r"\b([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b")

        rows: list[dict[str, str]] = []
        with open(path, "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                rows.append(r)

        # Ground deletion_worker activities by correlating batch window with reporting requests
        dw_acts = [r for r in rows if r["source_system"] == "deletion_worker"]
        by_rep: dict[str, list[dict[str, str]]] = defaultdict(list)
        for rw in self.request_windows:
            by_rep[rw["reported_at"]].append(rw)

        act_to_user: dict[str, str] = {}
        for rep_at_str, b_reqs in sorted(by_rep.items()):
            try:
                rep_at = datetime.fromisoformat(rep_at_str.replace("Z", "+00:00"))
            except Exception:
                continue

            b_acts = [
                a for a in dw_acts
                if -600 <= (rep_at - datetime.fromisoformat(a["event_time"].replace("Z", "+00:00"))).total_seconds() <= 7200
            ]
            if not b_acts:
                continue

            b_acc_acts = [a for a in b_acts if a["target_system"] == "account_service"]
            if len(b_reqs) == 1:
                uid = b_reqs[0]["user_id"]
                req_aud = b_reqs[0].get("audit_at", "")
                known_accs = {aid for cap, aid in self.account_ids_by_user.get(uid, []) if (not req_aud or is_timestamp_le(cap, req_aud))}
                for a in b_acts:
                    existing_owner = self.get_resource_owner(a["target_system"], a["resource_id"], req_aud or a["event_time"])
                    if not existing_owner:
                        existing_owner = self.get_known_evidence_owner(a["target_system"], a["resource_id"])

                    if existing_owner and existing_owner != uid:
                        continue

                    if a["target_system"] == "account_service":
                        if not known_accs or a["resource_id"] in known_accs:
                            act_to_user[a["activity_id"]] = uid
                    elif a["target_system"] == "analytics_platform":
                        act_to_user[a["activity_id"]] = uid
                    else:
                        if existing_owner == uid:
                            act_to_user[a["activity_id"]] = uid
            else:
                for a in list(b_acts):
                    owner = self.get_known_evidence_owner(a["target_system"], a["resource_id"])
                    if owner:
                        for rw in b_reqs:
                            if rw["user_id"] == owner:
                                act_to_user[a["activity_id"]] = owner
                                break

                available_accs = [a for a in b_acc_acts if a["activity_id"] not in act_to_user]
                unassigned_reqs = []
                for rw in b_reqs:
                    if any(act_to_user.get(a["activity_id"]) == rw["user_id"] and a["target_system"] == "account_service" for a in b_acts):
                        continue
                    uid = rw["user_id"]
                    req_aud = rw.get("audit_at", "")
                    known_accs = {aid for cap, aid in self.account_ids_by_user.get(uid, []) if (not req_aud or is_timestamp_le(cap, req_aud))}
                    matched_acc = None
                    for a in available_accs:
                        if a["resource_id"] in known_accs:
                            matched_acc = a
                            break
                    if matched_acc:
                        act_to_user[matched_acc["activity_id"]] = uid
                        available_accs.remove(matched_acc)
                    else:
                        unassigned_reqs.append(rw)

                for status_filter in (True, False):
                    sub_reqs = [rw for rw in unassigned_reqs if (rw.get("reported_status") == "COMPLETE") == status_filter]
                    sub_accs = [a for a in available_accs if (a["reported_result"] == "SUCCESS") == status_filter]
                    for rw, a in zip(sub_reqs, sub_accs):
                        uid = rw["user_id"]
                        act_owner = self.get_known_evidence_owner(a["target_system"], a["resource_id"])
                        if not act_owner or act_owner == uid:
                            act_to_user[a["activity_id"]] = uid
                            available_accs.remove(a)
                            unassigned_reqs.remove(rw)

                for rw, a in list(zip(unassigned_reqs, available_accs)):
                    act_owner = self.get_known_evidence_owner(a["target_system"], a["resource_id"])
                    if not act_owner or act_owner == rw["user_id"]:
                        act_to_user[a["activity_id"]] = rw["user_id"]

        for row in rows:
            act_id = row["activity_id"].strip()
            etime = row["event_time"].strip()
            etype = row["event_type"].strip()
            src = row["source_system"].strip()
            tgt = row["target_system"].strip()
            res_id = row["resource_id"].strip()
            res = row["reported_result"].strip()
            details = row.get("details", "").strip()

            u_match = user_re.search(details)
            e_match = email_re.search(details)

            linked_uid = u_match.group(1).lower() if u_match else None
            linked_email = e_match.group(1).lower() if e_match else None

            if not linked_uid and linked_email:
                ident = self.resolver.resolve(linked_email)
                if ident:
                    linked_uid = ident.user_id.lower()

            if not linked_uid and act_id in act_to_user:
                linked_uid = act_to_user[act_id]

            self.all_activities.append(ActivityLink(
                activity_id=act_id,
                event_time=etime,
                event_type=etype,
                source_system=src,
                target_system=tgt,
                resource_id=res_id,
                reported_result=res,
                details=details,
                linked_user_id=linked_uid,
                linked_email=linked_email,
            ))
            if linked_uid:
                self._add_grounded_res(linked_uid, tgt, res_id, "", etime)

    def _add_grounded_res(self, uid: str, sys_name: str, rid: str, evid: str, cap_at: str) -> None:
        if not uid or not rid:
            return
        uid_clean = uid.lower().strip()
        sys_clean = sys_name.strip()
        rid_clean = rid.strip()
        cap_clean = cap_at.strip()
        self.raw_grounded_entries.append((uid_clean, sys_clean, rid_clean, evid.strip(), cap_clean))
        if sys_clean == "account_service":
            self.account_ids_by_user.setdefault(uid_clean, []).append((cap_clean, rid_clean))
        if evid:
            self.known_resource_owners.setdefault(rid_clean, []).append((cap_clean, uid_clean))
            self.known_resource_owners_by_system.setdefault((sys_clean, rid_clean), []).append((cap_clean, uid_clean))

    def get_resource_owner(
        self,
        system_or_resource: str,
        resource_or_time: str,
        at_time: Optional[str] = None,
    ) -> Optional[str]:
        """Return the owner of a resource established by evidence at or before at_time.

        Supports both:
        - get_resource_owner(system_id, resource_id, at_time)
        - get_resource_owner(resource_id, at_time)
        """
        if at_time is None:
            rid = system_or_resource.strip()
            cutoff = resource_or_time.strip()
            entries = self.known_resource_owners.get(rid, [])
            valid = [uid for cap_at, uid in entries if is_timestamp_le(cap_at, cutoff)]
            return valid[-1] if valid else None
        else:
            sys_id = system_or_resource.strip()
            rid = resource_or_time.strip()
            cutoff = at_time.strip()
            # Strictly scoped by (system_id, resource_id) without ambiguous cross-system fallback
            entries = self.known_resource_owners_by_system.get((sys_id, rid), [])
            valid = [uid for cap_at, uid in entries if is_timestamp_le(cap_at, cutoff)]
            return valid[-1] if valid else None

    def get_known_evidence_owner(self, system_id: str, resource_id: str) -> Optional[str]:
        """Return the owner of a resource established in evidence, strictly scoped by system."""
        sys_clean = system_id.strip()
        rid_clean = resource_id.strip()
        entries = self.known_resource_owners_by_system.get((sys_clean, rid_clean), [])
        return entries[-1][1] if entries else None

    def _index_all_evidence(self) -> None:
        """Dynamically index user-resource relationships grounded in supplied evidence artifacts."""
        path_to_meta = {m.file_path: m for m in self.manifest.files_by_id.values()}

        # 1. Records directory: JSON bundles, service exports, and text handover files
        rec_dir = os.path.join(self.dataset_dir, "evidence", "records")
        if os.path.exists(rec_dir):
            for fname in os.listdir(rec_dir):
                fpath = os.path.join(rec_dir, fname)
                fmeta = path_to_meta.get(f"evidence/records/{fname}")
                evid = fmeta.file_id if fmeta else ""
                cap_at = fmeta.captured_at if fmeta else "2026-10-01T00:00:00Z"

                if fname.endswith(".json"):
                    try:
                        with open(fpath, "r", encoding="utf-8") as json_fp:
                            d = json.load(json_fp)

                        # Snapshot bundles
                        for s in d.get("snapshots", []):
                            ds = s.get("data_store")
                            col = s.get("collection")
                            recs = s.get("records", [])
                            for r in recs:
                                rid = r.get("resource_id")
                                ref = r.get("customer_reference") or r.get("subject_reference") or r.get("user_id")
                                em = r.get("email") or r.get("customer_email") or r.get("owner_email") or r.get("requester_email")
                                uid = ref
                                if not uid and em:
                                    ident = self.resolver.resolve(em)
                                    if ident:
                                        uid = ident.user_id
                                elif uid and "@" in str(uid):
                                    ident = self.resolver.resolve(str(uid))
                                    if ident:
                                        uid = ident.user_id
                                if uid and ds and rid:
                                    self._add_grounded_res(str(uid), ds, rid, evid, cap_at)
                                elif uid and col == "security_audit_events" and rid:
                                    self._add_grounded_res(str(uid), "security_service", rid, evid, cap_at)
                                elif uid and col == "deleted_customer_references" and rid:
                                    self._add_grounded_res(str(uid), "identity_service", rid, evid, cap_at)

                            # If customer_profiles has 0 records, record empty snapshot for post-activity absence proof
                            if col == "customer_profiles" and len(recs) == 0:
                                self.empty_account_snapshots.append((evid, cap_at))

                        # Service exports across all services
                        if "service_exports" in d and isinstance(d["service_exports"], dict):
                            se = d["service_exports"]
                            for svc_name, svc_data in se.items():
                                if isinstance(svc_data, dict):
                                    for list_val in svc_data.values():
                                        if isinstance(list_val, list):
                                            for item in list_val:
                                                if isinstance(item, dict):
                                                    rid = item.get("resource_id")
                                                    ref = item.get("customer_reference") or item.get("subject_reference") or item.get("user_id")
                                                    em = item.get("email") or item.get("customer_email") or item.get("owner_email") or item.get("requester_email")
                                                    prof = item.get("profile")
                                                    if isinstance(prof, dict):
                                                        ref = ref or prof.get("customer_reference")
                                                        em = em or prof.get("email")
                                                    uid = ref
                                                    if not uid and em:
                                                        ident = self.resolver.resolve(em)
                                                        if ident:
                                                            uid = ident.user_id
                                                    elif uid and "@" in str(uid):
                                                        ident = self.resolver.resolve(str(uid))
                                                        if ident:
                                                            uid = ident.user_id
                                                    # If resource has profile lookup with status_code == 404 (absent from service)
                                                    if rid and item.get("status_code") == 404:
                                                        self.snapshot_404_accounts.append((evid, cap_at, rid))
                                                    if uid and rid:
                                                        self._add_grounded_res(str(uid), svc_name, rid, evid, cap_at)

                        # Root-level collection records
                        if "records" in d and isinstance(d["records"], list):
                            for r in d["records"]:
                                if not isinstance(r, dict):
                                    continue
                                rid = r.get("resource_id")
                                sys_n = r.get("system") or r.get("system_id") or "account_service"
                                ref = r.get("subject_reference") or r.get("customer_reference") or r.get("user_id")
                                em = r.get("email") or r.get("owner_email") or r.get("customer_email")
                                rec_time = r.get("recorded_at") or cap_at
                                uid = ref
                                if not uid and em:
                                    ident = self.resolver.resolve(em)
                                    if ident:
                                        uid = ident.user_id
                                elif uid and "@" in str(uid):
                                    ident = self.resolver.resolve(str(uid))
                                    if ident:
                                        uid = ident.user_id
                                if uid and sys_n and rid:
                                    self._add_grounded_res(str(uid), sys_n, rid, evid, rec_time)
                    except Exception:
                        pass
                elif fname.endswith(".txt"):
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                            for line in fp:
                                line_str = line.strip()
                                if line_str.startswith("-"):
                                    parts = [x.strip() for x in line_str.lstrip("-").split("|")]
                                    if len(parts) >= 6:
                                        ts, sys_id, res_id, cat, st, ident_str = parts[:6]
                                        ident = self.resolver.resolve(ident_str)
                                        if ident:
                                            self._add_grounded_res(ident.user_id, sys_id, res_id, evid, ts)
                    except Exception:
                        pass

        # 2. Logs directory: structured logs with trace grouping
        log_dir = os.path.join(self.dataset_dir, "evidence", "logs")
        if os.path.exists(log_dir):
            res_pat = re.compile(r'\bresource_id["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)["\']?')
            sys_pat = re.compile(r'\bsystem["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)["\']?')
            svc_pat = re.compile(r'\bservice["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)["\']?')
            ref_pat = re.compile(r'\b(?:lookup_key|match_key|owner_key|customer_reference|subject_reference|correlation_key|user_id)["\']?\s*[:=]\s*["\']?([^"\', \r\n]+)["\']?')
            em_pat = re.compile(r'\b(?:customer_email|email|requester_email)["\']?\s*[:=]\s*["\']?([^"\', \r\n]+)["\']?')
            ts_pat = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)')

            for fname in os.listdir(log_dir):
                if not fname.endswith(".log"):
                    continue
                fpath = os.path.join(log_dir, fname)
                rel_path = f"evidence/logs/{fname}"
                fmeta = path_to_meta.get(rel_path)
                evid = fmeta.file_id if fmeta else ""
                cap_at = fmeta.captured_at if fmeta else "2026-10-01T00:00:00Z"
                traces: dict[str, list[str]] = {}
                non_trace_lines: list[str] = []

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                        for line in fp:
                            tm = re.search(r'\btrace_id=["\']?([a-zA-Z0-9_-]+)["\']?', line)
                            if tm:
                                tid = tm.group(1)
                                if tid not in traces:
                                    traces[tid] = []
                                traces[tid].append(line)
                            else:
                                non_trace_lines.append(line)

                    # Trace groups
                    for tlines in traces.values():
                        full_str = " ".join(tlines)
                        res_m = res_pat.search(full_str)
                        if not res_m:
                            continue
                        rid = res_m.group(1).strip()
                        sys_m = sys_pat.search(full_str)
                        svc_m = svc_pat.search(full_str)
                        raw_svc = (sys_m.group(1) if sys_m else (svc_m.group(1) if svc_m else infer_service_from_resource_id(rid))).strip()
                        if raw_svc == "support_replica":
                            raw_svc = "support_platform"
                        elif raw_svc == "search_index_service":
                            raw_svc = "search_service"

                        ref_m = ref_pat.search(full_str)
                        em_m = em_pat.search(full_str)
                        ref = ref_m.group(1).strip() if ref_m else None
                        em = em_m.group(1).strip() if em_m else None

                        ts_m = ts_pat.match(tlines[0])
                        ts = ts_m.group(1) if ts_m else cap_at

                        uid = None
                        if ref and ref != "null":
                            if ref.startswith("user_"):
                                uid = ref
                            elif "@" in ref:
                                ident = self.resolver.resolve(ref)
                                if ident:
                                    uid = ident.user_id
                        if not uid and em and em != "null":
                            ident = self.resolver.resolve(em)
                            if ident:
                                uid = ident.user_id

                        if uid and rid and raw_svc:
                            self._add_grounded_res(str(uid), raw_svc, rid, evid, ts)

                    # Non-trace lines
                    for line in non_trace_lines:
                        res_m = res_pat.search(line)
                        if not res_m:
                            continue
                        rid = res_m.group(1).strip()
                        sys_m = sys_pat.search(line)
                        svc_m = svc_pat.search(line)
                        raw_svc = (sys_m.group(1) if sys_m else (svc_m.group(1) if svc_m else infer_service_from_resource_id(rid))).strip()
                        if raw_svc == "support_replica":
                            raw_svc = "support_platform"
                        elif raw_svc == "search_index_service":
                            raw_svc = "search_service"

                        ref_m = ref_pat.search(line)
                        em_m = em_pat.search(line)
                        ref = ref_m.group(1).strip() if ref_m else None
                        em = em_m.group(1).strip() if em_m else None

                        ts_m = ts_pat.match(line)
                        ts = ts_m.group(1) if ts_m else cap_at

                        uid = None
                        if ref and ref != "null":
                            if ref.startswith("user_"):
                                uid = ref
                            elif "@" in ref:
                                ident = self.resolver.resolve(ref)
                                if ident:
                                    uid = ident.user_id
                        if not uid and em and em != "null":
                            ident = self.resolver.resolve(em)
                            if ident:
                                uid = ident.user_id

                        if uid and rid and raw_svc:
                            self._add_grounded_res(str(uid), raw_svc, rid, evid, ts)
                except Exception:
                    pass

        # 3. Databases directory: SQLite database snapshots
        db_dir = os.path.join(self.dataset_dir, "evidence", "databases")
        if os.path.exists(db_dir):
            for fname in os.listdir(db_dir):
                if not fname.endswith(".sql"):
                    continue
                fpath = os.path.join(db_dir, fname)
                rel_path = f"evidence/databases/{fname}"
                fmeta = path_to_meta.get(rel_path)
                evid = fmeta.file_id if fmeta else ""
                cap_at = fmeta.captured_at if fmeta else "2026-10-01T00:00:00Z"
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                        sql_script = fp.read()
                    import sqlite3
                    con = sqlite3.connect(":memory:")
                    con.row_factory = sqlite3.Row
                    con.executescript(sql_script)
                    cur = con.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [r[0] for r in cur.fetchall()]
                    for tbl in tables:
                        rows = con.execute(f"SELECT * FROM {tbl}").fetchall()
                        for r in rows:
                            d = dict(r)
                            rid = d.get("resource_id")
                            sys_n = d.get("origin_system") or d.get("system_id") or d.get("service")
                            if not sys_n:
                                sys_n = "account_service"
                                if "search" in tbl:
                                    sys_n = "search_service"
                                elif "analytics" in tbl:
                                    sys_n = "analytics_platform"
                                elif "support" in tbl:
                                    sys_n = "support_platform"
                                elif "export" in tbl:
                                    sys_n = "export_service"
                                elif "backup" in tbl:
                                    sys_n = "backup_service"
                                elif "security" in tbl or "audit" in tbl:
                                    sys_n = "security_service"
                                elif "connector" in tbl:
                                    sys_n = "integration_service"

                            ref = d.get("user_id") or d.get("customer_reference") or d.get("subject_reference")
                            em = d.get("email") or d.get("customer_email") or d.get("owner_email") or d.get("requester_email")

                            for j_col in ("record_json", "document", "details"):
                                if j_col in d and d[j_col]:
                                    try:
                                        j_data = json.loads(d[j_col]) if isinstance(d[j_col], str) else d[j_col]
                                        if isinstance(j_data, dict):
                                            ref = ref or j_data.get("user_id") or j_data.get("customer_reference") or j_data.get("subject_reference")
                                            em = em or j_data.get("email") or j_data.get("customer_email")
                                            rid = rid or j_data.get("resource_id")
                                    except Exception:
                                        pass

                            uid = ref
                            if not uid and em:
                                ident = self.resolver.resolve(em)
                                if ident:
                                    uid = ident.user_id
                            elif uid and "@" in str(uid):
                                ident = self.resolver.resolve(str(uid))
                                if ident:
                                    uid = ident.user_id

                            if uid and rid:
                                self._add_grounded_res(str(uid), sys_n, str(rid), evid, cap_at)

                    # Check for point-in-time database snapshots proving account absence (e.g. evidence_54)
                    prof_tables = [t for t in tables if "customer_profiles" in t or "account" in t]
                    if "customer_accounts" in fname and prof_tables:
                        all_present_accounts: set[str] = set()
                        for tbl in prof_tables:
                            acc_rows = con.execute(f"SELECT resource_id FROM {tbl}").fetchall()
                            for r in acc_rows:
                                if r[0]:
                                    all_present_accounts.add(str(r[0]))
                        self.snapshot_present_accounts.append((evid, cap_at, all_present_accounts))

                    con.close()
                except Exception:
                    pass

    def _index_snapshot_absence_proofs(self) -> None:
        """Ground account absence proofs from database and bundle snapshots after activities are loaded."""
        for evid, cap_at, present_accs in self.snapshot_present_accounts:
            for rw in self.request_windows:
                uid = rw["user_id"]
                if is_timestamp_le(rw["reported_at"], cap_at):
                    user_accs = {aid for a_cap, aid in self.account_ids_by_user.get(uid, []) if is_timestamp_le(a_cap, cap_at)}
                    for aid in user_accs:
                        if aid not in present_accs:
                            self._add_grounded_res(uid, "account_service", aid, evid, cap_at)

        for evid, cap_at in self.empty_account_snapshots:
            for rw in self.request_windows:
                uid = rw["user_id"]
                if is_timestamp_le(rw["reported_at"], cap_at):
                    user_accs = {aid for a_cap, aid in self.account_ids_by_user.get(uid, []) if is_timestamp_le(a_cap, cap_at)}
                    for aid in user_accs:
                        self._add_grounded_res(uid, "account_service", aid, evid, cap_at)

        for evid, cap_at, rid_404 in self.snapshot_404_accounts:
            for rw in self.request_windows:
                uid = rw["user_id"]
                user_accs = {aid for a_cap, aid in self.account_ids_by_user.get(uid, []) if is_timestamp_le(a_cap, cap_at)}
                if rid_404 in user_accs:
                    self._add_grounded_res(uid, "account_service", rid_404, evid, cap_at)

    def get_resource_captured_at(self, user_id: str, system_name: str, resource_id: str, audit_at: str) -> str:
        """Return the latest capture timestamp of the given resource <= audit_at."""
        uid_lower = user_id.lower()
        candidates = []
        for (uid, sys_n, rid, evid, cap_at) in self.raw_grounded_entries:
            if uid == uid_lower and sys_n == system_name and rid == resource_id and is_timestamp_le(cap_at, audit_at):
                if evid and evid in self.manifest.files_by_id:
                    f_cap = self.manifest.files_by_id[evid].captured_at
                    if not is_timestamp_le(f_cap, audit_at):
                        continue
                candidates.append(cap_at)
        if not candidates:
            return ""
        return sorted(candidates)[-1]

    def get_user_resource(self, user_id: str, system_name: str, audit_at: str) -> Optional[tuple[str, str]]:
        """Return (resource_id, evidence_id) valid at audit_at."""
        uid_lower = user_id.lower()
        candidates = []
        for (uid, sys_n, rid, evid, cap_at) in self.raw_grounded_entries:
            if uid == uid_lower and sys_n == system_name and is_timestamp_le(cap_at, audit_at):
                # Ensure the evidence file itself was captured at or before audit_at
                if evid and evid in self.manifest.files_by_id:
                    f_cap = self.manifest.files_by_id[evid].captured_at
                    if not is_timestamp_le(f_cap, audit_at):
                        continue
                candidates.append((rid, evid, cap_at))
        if not candidates:
            return None
        # Deterministic sort: latest captured_at <= audit_at, prefer candidates with evidence_id, then resource_id
        candidates.sort(key=lambda x: (x[2], bool(x[1]), x[0]))
        best = candidates[-1]
        return best[0], best[1]

    def populate_user_resources(
        self,
        identity: UserIdentity,
        audit_at: str,
    ) -> set[str]:
        """Discover and populate all resource IDs associated with this user up to audit_at."""
        target_res_re = re.compile(r"Target resource:\s*([a-zA-Z0-9_]+)", re.IGNORECASE)
        linked_res_re = re.compile(r"Data catalog linked\s+([a-zA-Z0-9_]+)", re.IGNORECASE)

        # Iteratively discover directly and transitively linked resources
        changed = True
        while changed:
            changed = False
            acts = self.get_user_activities(identity, audit_at)
            for act in acts:
                if act.resource_id and act.resource_id not in identity.known_resource_ids:
                    identity.add_resource_id(act.resource_id)
                    changed = True

                # Check secondary resources in details
                t_match = target_res_re.search(act.details)
                if t_match:
                    sec_res = t_match.group(1).strip()
                    if sec_res and sec_res not in identity.known_resource_ids:
                        identity.add_resource_id(sec_res)
                        changed = True

                l_match = linked_res_re.search(act.details)
                if l_match:
                    l_res = l_match.group(1).strip()
                    if l_res and l_res not in identity.known_resource_ids:
                        identity.add_resource_id(l_res)
                        changed = True

        return identity.known_resource_ids

    def get_user_activities(
        self,
        identity: UserIdentity,
        audit_at: str,
    ) -> list[ActivityLink]:
        """Return all activity links for this user strictly at or before audit_at."""
        uid_lower = identity.user_id.lower()
        emails_lower = {e.lower() for e in identity.all_emails}
        known_res_lower = {r.lower() for r in identity.known_resource_ids}

        valid_activities: list[ActivityLink] = []
        for act in self.all_activities:
            # Enforce temporal cutoff
            if not is_timestamp_le(act.event_time, audit_at):
                continue

            # Check if this activity belongs to the user
            matches = False
            if act.linked_user_id and act.linked_user_id == uid_lower:
                matches = True
            elif act.linked_email and act.linked_email in emails_lower:
                matches = True
            elif act.resource_id and act.resource_id.lower() in known_res_lower:
                matches = True

            if matches:
                valid_activities.append(act)

        return valid_activities

    def get_resource_activities(
        self,
        resource_id: str,
        audit_at: str,
    ) -> list[ActivityLink]:
        """Return all activity events for a specific resource strictly up to audit_at."""
        res_clean = resource_id.strip()
        return [
            act for act in self.all_activities
            if act.resource_id == res_clean and is_timestamp_le(act.event_time, audit_at)
        ]
