"""
Validate generated AdverSim scenarios against real-world threat actor behavior
from the MITRE ATT&CK knowledge base.

The script downloads ATT&CK Enterprise STIX data, extracts technique sets used
by documented groups, builds co-occurrence matrices, and reports overlap,
Spearman correlation, and top matching groups.

Output defaults to an ignored generated-data directory.
"""

import json
import os
import re
import math
import requests
import numpy as np
from collections import defaultdict, Counter
from scipy import stats

# ─────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DATASET   = os.path.join(BASE_DIR, "dataset", "full_dataset.jsonl")
OUT_DIR   = os.path.join(BASE_DIR, "data", "generated", "attck_groups_validation")
os.makedirs(OUT_DIR, exist_ok=True)

ATTCK_URL = ("https://raw.githubusercontent.com/mitre/cti/master/"
             "enterprise-attack/enterprise-attack.json")
ATTCK_CACHE = os.path.join(OUT_DIR, "enterprise-attack.json")

VALID_TID = re.compile(r'^T\d{4}(\.\d{3})?$')


# ─────────────────────────────────────────────
# STEP 1: Download / load ATT&CK STIX data
# ─────────────────────────────────────────────
def load_attck_stix():
    if os.path.exists(ATTCK_CACHE):
        print("[ATT&CK] Loading from cache...")
        with open(ATTCK_CACHE, encoding="utf-8") as f:
            return json.load(f)
    print("[ATT&CK] Downloading enterprise ATT&CK STIX v14...")
    resp = requests.get(ATTCK_URL, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    with open(ATTCK_CACHE, "w", encoding="utf-8") as f:
        json.dump(data, f)
    print(f"[ATT&CK] Saved to {ATTCK_CACHE}")
    return data


# ─────────────────────────────────────────────
# STEP 2: Extract technique sequences per group
# ─────────────────────────────────────────────
def extract_group_techniques(stix_data):
    """
    Returns dict: {group_name: [list of technique IDs used by group]}
    Uses relationship objects to link groups → techniques.
    """
    objects = stix_data.get("objects", [])

    # Map IDs to objects
    id_to_obj = {o["id"]: o for o in objects if "id" in o}

    # Find all groups (intrusion-set)
    groups = {o["id"]: o["name"]
              for o in objects
              if o.get("type") == "intrusion-set"}

    # Find technique IDs (attack-pattern)
    tech_id_to_name = {}
    for o in objects:
        if o.get("type") == "attack-pattern":
            ext = o.get("external_references", [])
            for ref in ext:
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id", "")
                    if VALID_TID.match(tid):
                        tech_id_to_name[o["id"]] = tid

    # Build group → techniques via relationships
    group_techs = defaultdict(list)
    for o in objects:
        if o.get("type") != "relationship":
            continue
        if o.get("relationship_type") not in ("uses",):
            continue
        src = o.get("source_ref", "")
        tgt = o.get("target_ref", "")
        if src in groups and tgt in tech_id_to_name:
            group_name = groups[src]
            tid = tech_id_to_name[tgt]
            group_techs[group_name].append(tid)

    return dict(group_techs)


# ─────────────────────────────────────────────
# STEP 3: Build co-occurrence from group data
# ─────────────────────────────────────────────
def build_real_cooccurrence(group_techs):
    """
    Build technique co-occurrence counts from real group data.
    Since ATT&CK groups don't have ordered sequences, we use
    all pairwise co-occurrence within a group's technique set.
    Returns: Counter of (tid_i, tid_j) pairs
    """
    cooc = Counter()
    for group_name, techs in group_techs.items():
        if len(techs) < 2:
            continue
        # Generate all ordered pairs within the group's technique set
        for i, t1 in enumerate(techs):
            for j, t2 in enumerate(techs):
                if i != j and VALID_TID.match(t1) and VALID_TID.match(t2):
                    cooc[(t1, t2)] += 1
    return cooc


# ─────────────────────────────────────────────
# STEP 4: Build co-occurrence from generated corpus
# ─────────────────────────────────────────────
def load_generated_corpus(path=DATASET):
    scenarios = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, str):
                    obj = json.loads(obj)
                scenarios.append(obj)
            except Exception:
                pass
    print(f"[CORPUS] Loaded {len(scenarios)} scenarios")
    return scenarios


def build_generated_cooccurrence(scenarios):
    """
    Build transition co-occurrence from consecutive attack stages.
    """
    cooc = Counter()
    for s in scenarios:
        stages = s.get("attack_stages", [])
        for i in range(len(stages) - 1):
            techs_i = [t.get("technique_id", "")
                       for t in stages[i].get("techniques", [])
                       if VALID_TID.match(t.get("technique_id", ""))]
            techs_j = [t.get("technique_id", "")
                       for t in stages[i + 1].get("techniques", [])
                       if VALID_TID.match(t.get("technique_id", ""))]
            for ti in techs_i:
                for tj in techs_j:
                    cooc[(ti, tj)] += 1
    return cooc


# ─────────────────────────────────────────────
# STEP 5: Compare the two co-occurrence patterns
# ─────────────────────────────────────────────
def compare_cooccurrences(real_cooc, gen_cooc):
    """
    Compare real vs generated technique co-occurrence patterns.

    Metrics:
    - Overlap fraction: what % of generated pairs appear in real data
    - Spearman correlation on shared technique pairs
    - Precision/recall style overlap statistics
    """
    real_pairs = set(real_cooc.keys())
    gen_pairs  = set(gen_cooc.keys())
    shared     = real_pairs & gen_pairs

    # Overlap fraction: of generated transitions, how many appear in real data?
    overlap_fraction = len(shared) / max(len(gen_pairs), 1)

    # Weighted overlap: sum of generated counts for pairs that appear in real data
    gen_total_weight = sum(gen_cooc.values())
    gen_overlap_weight = sum(gen_cooc[p] for p in shared)
    weighted_overlap = gen_overlap_weight / max(gen_total_weight, 1)

    # Spearman correlation on shared pairs
    if len(shared) >= 10:
        real_vals = [real_cooc[p] for p in shared]
        gen_vals  = [gen_cooc[p]  for p in shared]
        rho, p_val = stats.spearmanr(real_vals, gen_vals)
    else:
        rho, p_val = 0.0, 1.0

    # Top-10 most frequent generated pairs that appear in real data
    top_validated = sorted(
        [(p, gen_cooc[p]) for p in shared],
        key=lambda x: -x[1]
    )[:10]

    # Top-10 generated pairs NOT in real data
    top_novel = sorted(
        [(p, gen_cooc[p]) for p in gen_pairs - real_pairs],
        key=lambda x: -x[1]
    )[:10]

    return {
        "n_generated_pairs": len(gen_pairs),
        "n_real_pairs": len(real_pairs),
        "n_shared_pairs": len(shared),
        "overlap_fraction": round(overlap_fraction, 4),
        "weighted_overlap": round(weighted_overlap, 4),
        "spearman_rho": round(rho, 4),
        "spearman_p": round(p_val, 6),
        "significant": p_val < 0.05,
        "top_10_validated_pairs": [(f"{p[0]}→{p[1]}", c)
                                   for p, c in top_validated],
        "top_10_novel_pairs": [(f"{p[0]}→{p[1]}", c)
                               for p, c in top_novel],
    }


# ─────────────────────────────────────────────
# STEP 6: Group-level matching
# ─────────────────────────────────────────────
def find_best_matching_groups(group_techs, scenarios):
    """
    For each ATT&CK group, compute Jaccard similarity between
    the group's technique set and the generated corpus's technique set.
    Returns the top-10 best-matching groups.
    """
    gen_techs = set()
    for s in scenarios:
        for stage in s.get("attack_stages", []):
            for t in stage.get("techniques", []):
                tid = t.get("technique_id", "")
                if VALID_TID.match(str(tid)):
                    gen_techs.add(tid)

    matches = []
    for group_name, techs in group_techs.items():
        if len(techs) < 3:
            continue
        group_set = set(t for t in techs if VALID_TID.match(t))
        intersection = len(gen_techs & group_set)
        union = len(gen_techs | group_set)
        jaccard = intersection / max(union, 1)
        coverage = intersection / max(len(group_set), 1)
        matches.append({
            "group": group_name,
            "jaccard": round(jaccard, 4),
            "coverage": round(coverage, 4),
            "group_techniques": len(group_set),
            "matched": intersection,
        })

    return sorted(matches, key=lambda x: -x["jaccard"])[:15]


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print("\n" + "=" * 60)
    print("  ATT&CK Groups External Validation")
    print("=" * 60)

    # Load ATT&CK STIX
    stix = load_attck_stix()
    group_techs = extract_group_techniques(stix)
    print(f"[ATT&CK] Found {len(group_techs)} groups with technique data")
    total_group_techs = sum(len(v) for v in group_techs.values())
    print(f"[ATT&CK] Total technique assignments: {total_group_techs}")

    # Load generated corpus
    scenarios = load_generated_corpus()

    # Build co-occurrence matrices
    print("\n[ANALYSIS] Building co-occurrence matrices...")
    real_cooc = build_real_cooccurrence(group_techs)
    gen_cooc  = build_generated_cooccurrence(scenarios)
    print(f"  Real-world pairs:  {len(real_cooc):,}")
    print(f"  Generated pairs:   {len(gen_cooc):,}")

    # Compare
    print("\n[ANALYSIS] Comparing co-occurrence patterns...")
    comparison = compare_cooccurrences(real_cooc, gen_cooc)

    print(f"\n  Overlap fraction:    {comparison['overlap_fraction']:.1%}")
    print(f"  Weighted overlap:    {comparison['weighted_overlap']:.1%}")
    print(f"  Spearman ρ:          {comparison['spearman_rho']:.4f}")
    print(f"  Spearman p:          {comparison['spearman_p']:.6f}")
    print(f"  Significant (p<.05): {comparison['significant']}")

    # Group matching
    print("\n[ANALYSIS] Finding best-matching threat actor groups...")
    top_groups = find_best_matching_groups(group_techs, scenarios)
    comparison["top_15_matching_groups"] = top_groups

    print("\n  Top 5 best-matching ATT&CK groups:")
    for g in top_groups[:5]:
        print(f"    {g['group']:30}: Jaccard={g['jaccard']:.3f}, "
              f"Coverage={g['coverage']:.1%} ({g['matched']}/{g['group_techniques']} techs)")

    # Save results
    # Convert any non-serialisable types
    def make_serialisable(obj):
        if isinstance(obj, dict):
            return {k: make_serialisable(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [make_serialisable(i) for i in obj]
        if isinstance(obj, (bool,)):
            return bool(obj)
        if hasattr(obj, 'item'):          # numpy scalar
            return obj.item()
        return obj

    out_path = os.path.join(OUT_DIR, "attck_groups_validation.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(make_serialisable(comparison), f, indent=2)

    print(f"\n[SAVED] Results → {out_path}")
    print("\nSummary:")
    print(f"  Technique pair overlap:  {comparison['overlap_fraction']:.1%}")
    print(f"  Weighted overlap:        {comparison['weighted_overlap']:.1%}")
    print(f"  Spearman ρ (co-occur):   {comparison['spearman_rho']:.4f}")
    print(f"  Spearman p-value:        {comparison['spearman_p']:.6f}")
    print(f"  Top group match:         {top_groups[0]['group']} "
          f"(Jaccard={top_groups[0]['jaccard']:.3f})")
    return comparison


if __name__ == "__main__":
    main()
