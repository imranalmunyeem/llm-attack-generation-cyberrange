"""Phase 7 human realism validation harness.

Commands:
  prepare  - create a blinded, stratified annotator packet
  analyze  - aggregate completed annotator CSV files and compute agreement

Raw completed rating files must stay under annotation/raw/ and are ignored by
git. The tracked outputs are the blank packet, anonymized aggregate summaries,
and a pending/complete status JSON.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
from collections import defaultdict
from itertools import product
from pathlib import Path
from typing import Any

import numpy as np
from scipy import stats


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "full_dataset_v14clean.jsonl"
INDEX_PATH = ROOT / "mitre" / "enterprise-attack-14.1-active-techniques.json"
PACKET_DIR = ROOT / "annotation" / "study_packet"
RAW_RATINGS_DIR = ROOT / "annotation" / "raw" / "phase7"
REVIEWER_PROFILE_PATH = ROOT / "annotation" / "reviewer_profile_phase7.json"
RESULTS_JSON = ROOT / "results" / "human_validation.json"
AGGREGATE_CSV = ROOT / "results" / "human_ratings_summary.csv"
AUDIT_MD = ROOT / "results" / "human_validation_audit.md"

DIMENSIONS = [
    "attck_alignment",
    "stage_sequence",
    "overall_realism",
]


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            rows.append(json.loads(obj) if isinstance(obj, str) else obj)
    return rows


def load_index() -> dict[str, Any]:
    return json.loads(INDEX_PATH.read_text(encoding="utf-8"))


def stable_blind_id(seed: int, scenario_id: str) -> str:
    digest = hashlib.sha256(f"{seed}:{scenario_id}".encode()).hexdigest()
    return f"ADV-{digest[:10].upper()}"


def scenario_tids(scenario: dict[str, Any]) -> list[str]:
    tids = []
    for stage in scenario.get("attack_stages", []) or []:
        for technique in stage.get("techniques", []) or []:
            tid = str(technique.get("technique_id", "")).strip()
            if tid:
                tids.append(tid)
    return tids


def group_pairs(index: dict[str, Any], active: set[str]) -> set[tuple[str, str]]:
    pairs = set()
    for tids in index.get("group_techniques", {}).values():
        clean = sorted({tid for tid in tids if tid in active})
        for i, left in enumerate(clean):
            for right in clean[i + 1 :]:
                pairs.add((left, right))
    return pairs


def realism_features(scenario: dict[str, Any], active: set[str], pairs: set[tuple[str, str]]) -> dict[str, float]:
    tids = scenario_tids(scenario)
    active_ratio = sum(1 for tid in tids if tid in active) / max(1, len(tids))
    stages = scenario.get("attack_stages", []) or []
    graph = scenario.get("attack_graph", {}) or {}
    edges = graph.get("edges", []) or []
    structure = min(1.0, (len(stages) / 4) * 0.6 + (len(edges) / max(1, len(stages) - 1)) * 0.4)
    transition_pairs = [tuple(sorted((a, b))) for a, b in zip(tids, tids[1:]) if a != b]
    coherence = sum(1 for pair in transition_pairs if pair in pairs) / max(1, len(transition_pairs))
    return {
        "active_validity": round(active_ratio, 6),
        "structure": round(structure, 6),
        "transition_coherence": round(coherence, 6),
        "rs_current": round(0.4 * active_ratio + 0.35 * structure + 0.25 * coherence, 6),
    }


def format_stages(scenario: dict[str, Any]) -> str:
    chunks = []
    for i, stage in enumerate(scenario.get("attack_stages", []) or [], start=1):
        techs = []
        for technique in stage.get("techniques", []) or []:
            tid = str(technique.get("technique_id", "")).strip()
            name = str(technique.get("technique_name", "")).strip()
            if tid:
                techs.append(f"{tid} {name}".strip())
        chunks.append(f"{i}. {stage.get('stage_name', 'Stage')}: {', '.join(techs[:3])}")
    return " | ".join(chunks)


def stratified_sample(rows: list[dict[str, Any]], n: int, seed: int) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[
            (
                row.get("attack_type", "Unknown"),
                row.get("environment_type", "Unknown"),
                row.get("difficulty", "Unknown"),
            )
        ].append(row)
    sample = []
    per_group = max(1, n // max(1, len(groups)))
    for key in sorted(groups):
        group = groups[key][:]
        rng.shuffle(group)
        sample.extend(group[: min(per_group, len(group))])
    if len(sample) < n:
        chosen_ids = {id(row) for row in sample}
        remaining = [row for row in rows if id(row) not in chosen_ids]
        rng.shuffle(remaining)
        sample.extend(remaining[: n - len(sample)])
    rng.shuffle(sample)
    return sample[:n]


def prepare(args: argparse.Namespace) -> int:
    scenarios = stratified_sample(load_jsonl(args.dataset), args.n, args.seed)
    index = load_index()
    active = set(index["active"])
    pairs = group_pairs(index, active)
    args.out.mkdir(parents=True, exist_ok=True)

    scenario_rows = []
    template_rows = []
    key_rows = []
    for sample_index, scenario in enumerate(scenarios, start=1):
        scenario_id = str(scenario.get("scenario_id", "unknown"))
        blind_id = stable_blind_id(args.seed, f"{sample_index}:{scenario_id}")
        features = realism_features(scenario, active, pairs)
        scenario_rows.append(
            {
                "blind_id": blind_id,
                "attack_type": scenario.get("attack_type", ""),
                "environment_type": scenario.get("environment_type", ""),
                "difficulty": scenario.get("difficulty", ""),
                "narrative": scenario.get("narrative", ""),
                "attack_stages_and_techniques": format_stages(scenario),
                "stage_count": len(scenario.get("attack_stages", []) or []),
            }
        )
        template_rows.append(
            {
                "blind_id": blind_id,
                "attck_alignment": "",
                "stage_sequence": "",
                "overall_realism": "",
                "confidence_1_5": "",
                "comments_optional": "",
            }
        )
        key_rows.append({"blind_id": blind_id, "sample_index": sample_index, "scenario_id": scenario_id, **features})

    write_csv(args.out / "phase7_scenarios_blinded.csv", scenario_rows)
    write_csv(args.out / "phase7_rating_template.csv", template_rows)
    write_csv(args.out / "phase7_blind_key.csv", key_rows)
    (args.out / "phase7_instructions.md").write_text(instructions_text(args.n), encoding="utf-8")
    status = {
        "status": "awaiting_human_ratings",
        "scenario_count": args.n,
        "required_annotators_min": 3,
        "recommended_annotators": 5,
        "packet_dir": str(args.out.relative_to(ROOT) if args.out.is_relative_to(ROOT) else args.out),
        "raw_ratings_dir": "annotation/raw/phase7",
        "note": "Do not commit completed annotator CSVs; only aggregate outputs should enter git.",
    }
    RESULTS_JSON.parent.mkdir(parents=True, exist_ok=True)
    clear_aggregate_csv()
    RESULTS_JSON.write_text(json.dumps(status, indent=2), encoding="utf-8")
    AUDIT_MD.write_text(audit_pending_text(status), encoding="utf-8")
    print(f"prepared {args.n} blinded scenarios in {args.out}")
    return 0


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def clear_aggregate_csv() -> None:
    if AGGREGATE_CSV.exists():
        AGGREGATE_CSV.unlink()


def load_reviewer_profile(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def instructions_text(n: int) -> str:
    return f"""# AdverSim Phase 7 Annotation Instructions

Thank you for helping evaluate synthetic cyber attack scenario realism.

You will rate {n} blinded scenarios. The study should take about 45-60 minutes.

Files:
- `phase7_scenarios_blinded.csv`: read-only scenario packet.
- `phase7_rating_template.csv`: fill this file and return it.

You should not receive `phase7_blind_key.csv`; that file is reserved for the
research team after ratings are returned.

Rate each scenario from 1 to 5:

- `attck_alignment`: are the ATT&CK technique IDs plausible for the scenario?
- `stage_sequence`: does the attack sequence make operational sense?
- `overall_realism`: could this scenario plausibly occur in a real incident?
- `confidence_1_5`: how confident are you in your rating?

Scale:
- 1 = clearly unrealistic or incorrect
- 2 = mostly weak/questionable
- 3 = mixed or partially plausible
- 4 = mostly realistic
- 5 = highly realistic

Please do not discuss ratings with other annotators. Do not try to infer model
scores; the packet is intentionally blinded.
"""


def parse_rating(value: str) -> int | None:
    try:
        parsed = int(str(value).strip())
    except ValueError:
        return None
    return parsed if 1 <= parsed <= 5 else None


def load_ratings(ratings_dir: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(ratings_dir.glob("*.csv")):
        annotator_hash = hashlib.sha256(path.name.encode()).hexdigest()[:10]
        with path.open(newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                blind_id = row.get("blind_id", "").strip()
                if not blind_id:
                    continue
                parsed = {"annotator": annotator_hash, "blind_id": blind_id}
                for dim in DIMENSIONS:
                    parsed[dim] = parse_rating(row.get(dim, ""))
                rows.append(parsed)
    return rows


def krippendorff_alpha_ordinal(items: dict[str, list[int]]) -> float | None:
    pairs_do = []
    all_values = []
    for vals in items.values():
        vals = [v for v in vals if v is not None]
        all_values.extend(vals)
        if len(vals) < 2:
            continue
        for i, left in enumerate(vals):
            for right in vals[i + 1 :]:
                pairs_do.append((left - right) ** 2)
    if not pairs_do or len(all_values) < 2:
        return None
    observed = statistics.mean(pairs_do)
    expected_pairs = [(a - b) ** 2 for a in all_values for b in all_values if a != b]
    expected = statistics.mean(expected_pairs) if expected_pairs else 0
    if expected == 0:
        return None
    return round(1 - observed / expected, 6)


def bootstrap_spearman(x: list[float], y: list[float], seed: int, n_boot: int = 2000) -> list[float] | None:
    if len(x) < 3:
        return None
    rng = random.Random(seed)
    vals = []
    n = len(x)
    for _ in range(n_boot):
        idx = [rng.randrange(n) for _ in range(n)]
        sx = [x[i] for i in idx]
        sy = [y[i] for i in idx]
        rho, _ = safe_spearman(sx, sy)
        if rho is not None:
            vals.append(rho)
    if not vals:
        return None
    lo, hi = np.percentile(vals, [2.5, 97.5])
    return [round(float(lo), 6), round(float(hi), 6)]


def grid_weights(step: float = 0.05) -> list[tuple[float, float, float]]:
    values = [round(i * step, 10) for i in range(int(1 / step) + 1)]
    out = []
    for a, b in product(values, values):
        c = round(1 - a - b, 10)
        if c < 0:
            continue
        out.append((a, b, c))
    return out


def analyze(args: argparse.Namespace) -> int:
    key_path = args.packet_dir / "phase7_blind_key.csv"
    if not key_path.exists():
        raise FileNotFoundError(f"missing blind key: {key_path}")
    key_rows = {}
    with key_path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key_rows[row["blind_id"]] = row
    ratings = load_ratings(args.ratings_dir)
    annotators = sorted({row["annotator"] for row in ratings})
    reviewer_profile = load_reviewer_profile(args.reviewer_profile)
    if len(annotators) < args.min_annotators:
        status = {
            "status": "awaiting_human_ratings",
            "scenario_count": len(key_rows),
            "annotators_received": len(annotators),
            "required_annotators_min": args.min_annotators,
            "recommended_annotators": 5,
            "packet_dir": str(args.packet_dir.relative_to(ROOT) if args.packet_dir.is_relative_to(ROOT) else args.packet_dir),
            "raw_ratings_dir": str(args.ratings_dir.relative_to(ROOT) if args.ratings_dir.is_relative_to(ROOT) else args.ratings_dir),
            "note": "Do not commit completed annotator CSVs; only aggregate outputs should enter git.",
        }
        if reviewer_profile:
            status["reviewer_profile"] = reviewer_profile
        clear_aggregate_csv()
        RESULTS_JSON.write_text(json.dumps(status, indent=2), encoding="utf-8")
        AUDIT_MD.write_text(audit_pending_text(status), encoding="utf-8")
        print(f"need at least {args.min_annotators} annotators; found {len(annotators)}")
        return 0

    by_dim_item: dict[str, dict[str, list[int]]] = {dim: defaultdict(list) for dim in DIMENSIONS}
    by_item: dict[str, dict[str, list[int]]] = defaultdict(lambda: {dim: [] for dim in DIMENSIONS})
    for row in ratings:
        bid = row["blind_id"]
        if bid not in key_rows:
            continue
        for dim in DIMENSIONS:
            val = row[dim]
            if val is not None:
                by_dim_item[dim][bid].append(val)
                by_item[bid][dim].append(val)

    aggregate_rows = []
    for bid, dims in sorted(by_item.items()):
        key = key_rows[bid]
        row = {
            "blind_id": bid,
            "n_annotators": max(len(vals) for vals in dims.values()),
            "mean_attck_alignment": mean_or_none(dims["attck_alignment"]),
            "mean_stage_sequence": mean_or_none(dims["stage_sequence"]),
            "mean_overall_realism": mean_or_none(dims["overall_realism"]),
            "rs_current": float(key["rs_current"]),
            "active_validity": float(key["active_validity"]),
            "structure": float(key["structure"]),
            "transition_coherence": float(key["transition_coherence"]),
        }
        aggregate_rows.append(row)
    write_csv(AGGREGATE_CSV, aggregate_rows)

    usable = [row for row in aggregate_rows if row["mean_overall_realism"] is not None]
    rs = [row["rs_current"] for row in usable]
    human = [row["mean_overall_realism"] / 5 for row in usable]
    rho, rho_p = safe_spearman(rs, human)
    split_rng = random.Random(args.seed)
    split = usable[:]
    split_rng.shuffle(split)
    train = split[: max(1, int(len(split) * 0.7))]
    test = split[max(1, int(len(split) * 0.7)) :]
    best = fit_weights(train)
    test_rho = eval_weights(test, best["weights"])

    result = {
        "status": "complete",
        "scenario_count": len(aggregate_rows),
        "annotator_count": len(annotators),
        "reviewer_profile": reviewer_profile,
        "krippendorff_alpha_ordinal": {
            dim: krippendorff_alpha_ordinal(by_dim_item[dim]) for dim in DIMENSIONS
        },
        "rs_vs_human_overall": {
            "spearman_rho": round(float(rho), 6) if rho is not None and not math.isnan(rho) else None,
            "p_value": float(rho_p) if rho_p is not None and not math.isnan(rho_p) else None,
            "bootstrap_95ci": bootstrap_spearman(rs, human, args.seed),
        },
        "weight_refit": {
            "train_n": len(train),
            "test_n": len(test),
            "original_weights": [0.4, 0.35, 0.25],
            "best_train_weights": best["weights"],
            "best_train_spearman": best["rho"],
            "test_spearman": test_rho,
            "note": "Weights are fit on train split against mean overall realism and evaluated on held-out scenarios.",
        },
    }
    RESULTS_JSON.write_text(json.dumps(result, indent=2), encoding="utf-8")
    AUDIT_MD.write_text(audit_complete_text(result), encoding="utf-8")
    print(f"wrote {RESULTS_JSON}")
    print(f"wrote {AGGREGATE_CSV}")
    return 0


def mean_or_none(vals: list[int]) -> float | None:
    clean = [v for v in vals if v is not None]
    return round(sum(clean) / len(clean), 6) if clean else None


def safe_spearman(x: list[float], y: list[float]) -> tuple[float | None, float | None]:
    if len(x) < 3 or len(y) < 3:
        return None, None
    if len(set(x)) < 2 or len(set(y)) < 2:
        return None, None
    result = stats.spearmanr(x, y)
    rho = result.correlation
    p_value = result.pvalue
    if rho is None or math.isnan(rho):
        return None, None
    clean_p = None if p_value is None or math.isnan(p_value) else float(p_value)
    return round(float(rho), 6), clean_p


def fit_weights(rows: list[dict[str, Any]]) -> dict[str, Any]:
    y = [row["mean_overall_realism"] / 5 for row in rows]
    best = {"weights": [0.4, 0.35, 0.25], "rho": None}
    for weights in grid_weights():
        x = [weighted_score(row, weights) for row in rows]
        rho, _ = safe_spearman(x, y)
        if rho is None:
            continue
        if best["rho"] is None or rho > best["rho"]:
            best = {"weights": list(weights), "rho": rho}
    return best


def eval_weights(rows: list[dict[str, Any]], weights: list[float]) -> float | None:
    if len(rows) < 3:
        return None
    x = [weighted_score(row, tuple(weights)) for row in rows]
    y = [row["mean_overall_realism"] / 5 for row in rows]
    rho, _ = safe_spearman(x, y)
    return rho


def weighted_score(row: dict[str, Any], weights: tuple[float, float, float] | list[float]) -> float:
    return (
        weights[0] * row["active_validity"]
        + weights[1] * row["structure"]
        + weights[2] * row["transition_coherence"]
    )


def audit_pending_text(status: dict[str, Any]) -> str:
    return """# Phase 7 Human Realism Validation

Status: awaiting independent human ratings.

Prepared packet:

- `annotation/study_packet/phase7_scenarios_blinded.csv`
- `annotation/study_packet/phase7_rating_template.csv`
- `annotation/study_packet/phase7_instructions.md`

Raw completed annotator files must be placed in `annotation/raw/phase7/`.
That directory is ignored by git. Do not commit raw annotator identities,
comments, or per-person rating sheets.

Current status:

```json
%s
```
""" % json.dumps(status, indent=2)


def audit_complete_text(result: dict[str, Any]) -> str:
    return """# Phase 7 Human Realism Validation

Status: complete.

Annotators: {annotator_count}
Scenarios: {scenario_count}

Krippendorff ordinal alpha:

```json
{alpha}
```

R(S) vs mean human overall realism:

```json
{rho}
```

Weight refit:

```json
{weights}
```

Reviewer profile:

```json
{reviewer_profile}
```
""".format(
        annotator_count=result["annotator_count"],
        scenario_count=result["scenario_count"],
        alpha=json.dumps(result["krippendorff_alpha_ordinal"], indent=2),
        rho=json.dumps(result["rs_vs_human_overall"], indent=2),
        weights=json.dumps(result["weight_refit"], indent=2),
        reviewer_profile=json.dumps(result.get("reviewer_profile"), indent=2),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--dataset", type=Path, default=CORPUS_PATH)
    prep.add_argument("--out", type=Path, default=PACKET_DIR)
    prep.add_argument("--n", type=int, default=150)
    prep.add_argument("--seed", type=int, default=7007)

    ana = sub.add_parser("analyze")
    ana.add_argument("--packet-dir", type=Path, default=PACKET_DIR)
    ana.add_argument("--ratings-dir", type=Path, default=RAW_RATINGS_DIR)
    ana.add_argument("--reviewer-profile", type=Path, default=REVIEWER_PROFILE_PATH)
    ana.add_argument("--min-annotators", type=int, default=3)
    ana.add_argument("--seed", type=int, default=7007)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.cmd == "prepare":
        return prepare(args)
    if args.cmd == "analyze":
        return analyze(args)
    raise ValueError(args.cmd)


if __name__ == "__main__":
    raise SystemExit(main())
