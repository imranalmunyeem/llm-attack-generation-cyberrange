"""Audit residual co-occurrence leakage in the external real-vs-random test."""

from __future__ import annotations

import argparse
import json
from itertools import combinations
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "mitre" / "enterprise-attack-14.1-active-techniques.json"
EXTERNAL = ROOT / "results" / "external_realism_validation.json"
OUTPUT = ROOT / "results" / "external_leakage_audit.json"


def all_pairs(tids: list[str]) -> set[tuple[str, str]]:
    return {tuple(sorted(pair)) for pair in combinations(sorted(set(tids)), 2)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    index = json.loads(INDEX.read_text(encoding="utf-8"))
    external = json.loads(EXTERNAL.read_text(encoding="utf-8"))
    group_pairs = {group: all_pairs([tid for tid in tids if tid in index["active"]]) for group, tids in index.get("group_techniques", {}).items()}
    rows = []
    total_pairs = 0
    residual_pairs = 0
    source_only_pairs = 0
    for sample in external.get("sampled_sources", []):
        group = sample.get("group")
        pairs = all_pairs([tid for tid in sample.get("real_techniques", []) if tid in index["active"]])
        other = set().union(*(pairs2 for g, pairs2 in group_pairs.items() if g != group)) if group_pairs else set()
        source = group_pairs.get(group, set())
        residual = pairs & other
        source_only = (pairs & source) - other
        rows.append(
            {
                "group": group,
                "pair_count": len(pairs),
                "residual_pairs_seen_in_other_groups": len(residual),
                "source_only_pairs": len(source_only),
                "source_group_excluded": True,
            }
        )
        total_pairs += len(pairs)
        residual_pairs += len(residual)
        source_only_pairs += len(source_only)
    result = {
        "schema_version": 1,
        "chains": len(rows),
        "source_group_exclusion_applied": all(row["source_group_excluded"] for row in rows),
        "total_pairs": total_pairs,
        "residual_leakage_pairs": residual_pairs,
        "residual_leakage_rate": round(residual_pairs / max(1, total_pairs), 6),
        "source_only_pairs_excluded": source_only_pairs,
        "per_chain": rows,
    }
    OUTPUT.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
