"""
mitre_attack_validator.py

Real MITRE ATT&CK v14 technique-ID validation against the enterprise STIX
bundle -- replaces the previous regex-only format check (^T\\d{4}(\\.\\d{3})?$),
which accepted any well-formed string including hallucinated/deprecated IDs.

A technique ID is now classified against the actual matrix:
  - ACTIVE      : present in v14 enterprise, not revoked, not deprecated
  - DEPRECATED  : present in the bundle but revoked or x_mitre_deprecated
  - INVALID     : well-formed (T#### / T####.###) but NOT in the matrix at all
                  (i.e. a hallucinated identifier)
  - MALFORMED   : does not match the ATT&CK ID format

Usage:
    v = MitreAttackValidator("data/enterprise-attack.json")
    v.classify("T1566")        -> "ACTIVE"
    v.is_valid("T1566")        -> True   (active only)
    v.technique_meta("T1566")  -> {"name":..., "tactics":[...], "description":...}
"""

import json
import re

VALID_TID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class MitreAttackValidator:
    def __init__(self, stix_path):
        self.active = {}       # tid -> {name, description, tactics}
        self.deprecated = {}   # tid -> {name, description, tactics}
        self.successors = {}   # old/revoked tid -> current successor tid
        self._load(stix_path)

    def _load(self, stix_path):
        with open(stix_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        stixid_to_tid = {}
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            tid = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    tid = ref["external_id"].strip()
                    break
            if not tid:
                continue
            stixid_to_tid[obj["id"]] = tid

            meta = {
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "tactics": [p.get("phase_name", "")
                            for p in obj.get("kill_chain_phases", [])
                            if p.get("kill_chain_name") == "mitre-attack"],
            }
            is_dead = bool(obj.get("revoked", False)) or bool(obj.get("x_mitre_deprecated", False))
            if is_dead:
                # keep the first non-dead definition if a tid appears twice
                self.deprecated.setdefault(tid, meta)
            else:
                self.active[tid] = meta

        # revoked-by relationships: old tid -> current successor tid
        for obj in bundle.get("objects", []):
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
                src = stixid_to_tid.get(obj.get("source_ref"))
                dst = stixid_to_tid.get(obj.get("target_ref"))
                if src and dst:
                    self.successors[src] = dst

    # ---- public API -------------------------------------------------------
    def classify(self, tid):
        tid = str(tid).strip()
        if not VALID_TID_RE.match(tid):
            return "MALFORMED"
        if tid in self.active:
            return "ACTIVE"
        if tid in self.deprecated:
            return "DEPRECATED"
        return "INVALID"

    def is_valid(self, tid):
        """True only for active v14 techniques (strict)."""
        return self.classify(tid) == "ACTIVE"

    def is_recognised(self, tid):
        """True if the ID exists in the matrix at all (active or deprecated)."""
        return self.classify(tid) in ("ACTIVE", "DEPRECATED")

    def technique_meta(self, tid):
        tid = str(tid).strip()
        return self.active.get(tid) or self.deprecated.get(tid)

    def active_techniques(self):
        """dict tid -> meta for all active techniques (for embedding mutation)."""
        return dict(self.active)

    def suggest(self, tid):
        """Return an active replacement for a non-active id, or None.
        Order: official revoked-by successor -> parent technique (for a bad
        sub-technique) -> None."""
        tid = str(tid).strip()
        if self.classify(tid) == "ACTIVE":
            return tid
        if tid in self.successors and self.is_valid(self.successors[tid]):
            return self.successors[tid]
        if "." in tid and self.is_valid(tid.split(".")[0]):
            return tid.split(".")[0]
        return None

    def counts(self):
        return {"active": len(self.active), "deprecated": len(self.deprecated)}
