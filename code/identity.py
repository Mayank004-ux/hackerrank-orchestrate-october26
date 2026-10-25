"""Identity resolution module for Ghost Data Still Exists.

Resolves subject identities across current profiles (user_identities.csv)
and historical identity changes (user_audit_log.csv).
"""

from __future__ import annotations

import csv
import os
from dataclasses import dataclass, field
from typing import Optional


def normalize_phone(phone: str) -> str:
    """Normalize a phone number to digits only for consistent matching."""
    if not phone:
        return ""
    return "".join(c for c in str(phone) if c.isdigit())


@dataclass
class UserIdentity:
    """Canonical representation of a user's current and historical identity."""
    user_id: str
    primary_name: str
    primary_email: str
    primary_phone: str
    primary_email_hash: str
    updated_at: str
    all_emails: set[str] = field(default_factory=set)
    all_phones: set[str] = field(default_factory=set)
    all_hashes: set[str] = field(default_factory=set)
    known_resource_ids: set[str] = field(default_factory=set)
    audit_history: list[dict] = field(default_factory=list)

    def add_resource_id(self, resource_id: str) -> None:
        """Register a known resource ID associated with this subject."""
        if resource_id and str(resource_id).strip():
            self.known_resource_ids.add(str(resource_id).strip())

    def matches(self, value: str) -> bool:
        """Check if a given string matches any of this user's known identifiers or resources."""
        if not value:
            return False
        val_clean = str(value).strip().lower()
        if val_clean == self.user_id.lower():
            return True
        if val_clean in {e.lower() for e in self.all_emails}:
            return True
        if val_clean in {p.lower() for p in self.all_phones}:
            return True

        # Check digit-only normalized phone comparison
        val_digits = normalize_phone(val_clean)
        if val_digits and any(normalize_phone(p) == val_digits for p in self.all_phones if normalize_phone(p)):
            return True

        if val_clean in {h.lower() for h in self.all_hashes}:
            return True
        if val_clean in {r.lower() for r in self.known_resource_ids}:
            return True
        if val_clean == self.primary_name.strip().lower():
            return True
        return False


class IdentityResolver:
    """Loads and resolves user identities from participant-facing CSV files."""

    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.users_by_id: dict[str, UserIdentity] = {}
        self.email_to_user_id: dict[str, str] = {}
        self._load_current_identities()
        self._load_audit_logs()

    def _load_current_identities(self) -> None:
        path = os.path.join(self.dataset_dir, "user_identities.csv")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Missing user identities file: {path}")

        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                name = row.get("name", "").strip()
                email = row.get("email", "").strip()
                phone = row.get("phone", "").strip()
                e_hash = row.get("email_hash", "").strip()
                updated_at = row.get("updated_at", "").strip()

                user_ident = UserIdentity(
                    user_id=uid,
                    primary_name=name,
                    primary_email=email,
                    primary_phone=phone,
                    primary_email_hash=e_hash,
                    updated_at=updated_at,
                )
                if email:
                    norm_email = email.lower()
                    user_ident.all_emails.add(norm_email)
                    self.email_to_user_id[norm_email] = uid
                if phone:
                    user_ident.all_phones.add(phone)
                    norm_phone = normalize_phone(phone)
                    if norm_phone:
                        user_ident.all_phones.add(norm_phone)
                if e_hash:
                    user_ident.all_hashes.add(e_hash.lower())

                self.users_by_id[uid] = user_ident

    def _load_audit_logs(self) -> None:
        path = os.path.join(self.dataset_dir, "user_audit_log.csv")
        if not os.path.exists(path):
            return

        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row.get("user_id", "").strip()
                if uid not in self.users_by_id:
                    continue

                user_ident = self.users_by_id[uid]
                user_ident.audit_history.append(row)

                field_name = row.get("field_name", "").strip()
                old_val = row.get("old_value", "").strip()
                new_val = row.get("new_value", "").strip()

                if field_name == "email":
                    for val in (old_val, new_val):
                        if val:
                            norm_val = val.lower()
                            user_ident.all_emails.add(norm_val)
                            # Only set if not already set by current email
                            if norm_val not in self.email_to_user_id:
                                self.email_to_user_id[norm_val] = uid
                elif field_name == "phone":
                    for val in (old_val, new_val):
                        if val:
                            user_ident.all_phones.add(val)
                            norm_val = normalize_phone(val)
                            if norm_val:
                                user_ident.all_phones.add(norm_val)
                elif field_name == "email_hash":
                    for val in (old_val, new_val):
                        if val:
                            user_ident.all_hashes.add(val.strip().lower())
                elif field_name in ("name", "full_name"):
                    for val in (old_val, new_val):
                        if val:
                            user_ident.primary_name = val.strip()

    def resolve(self, identifier: str) -> Optional[UserIdentity]:
        """Resolve a current email, historical email, or user_id to a UserIdentity."""
        if not identifier:
            return None
        clean_id = identifier.strip()

        # Check direct user_id
        if clean_id in self.users_by_id:
            return self.users_by_id[clean_id]

        # Check email (case-insensitive)
        norm_email = clean_id.lower()
        if norm_email in self.email_to_user_id:
            uid = self.email_to_user_id[norm_email]
            return self.users_by_id.get(uid)

        return None
