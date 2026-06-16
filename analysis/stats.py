"""Phase 2 statistical rigor and effect-size framing.

This script consolidates the statistical claims that can be supported by the
current checkout. It computes confidence intervals, Holm-Bonferroni corrected
p-values, and an ATT&CK external-validation permutation/null model without
touching the cached validation JSON.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any, Callable

import numpy as np
from scipy import stats

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

RESULTS_PATH = ROOT / "results" / "stats_table.json"
AUDIT_PATH = ROOT / "results" / "stats_audit.md"
REGISTRY_PATH = ROOT / "results" / "registry.json"
CORPUS_PATH = ROOT / "full_dataset_v14clean.jsonl"
INDEX_PATH = ROOT / "mitre" / "enterprise-attack-14.1-active-techniques.json"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


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


def percentile_ci(values: list[float], alpha: float = 0.05) -> list[float] | None:
    if not values:
        return None
    lo, hi = np.percentile(values, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return [round(float(lo), 6), round(float(hi), 6)]


def bootstrap_ci(
    data: list[Any],
    statistic: Callable[[list[Any]], float],
    *,
    n_boot: int,
    seed: int,
) -> list[float] | None:
    if not data:
        return None
    rng = random.Random(seed)
    vals = []
    n = len(data)
    for _ in range(n_boot):
        sample = [data[rng.randrange(n)] for _ in range(n)]
        vals.append(statistic(sample))
    return percentile_ci(vals)


def holm_bonferroni(p_values: dict[str, float | None]) -> dict[str, float | None]:
    valid = [(key, p) for key, p in p_values.items() if p is not None and not math.isnan(p)]
    m = len(valid)
    adjusted: dict[str, float | None] = {key: None for key in p_values}
    running_max = 0.0
    for rank, (key, p) in enumerate(sorted(valid, key=lambda item: item[1]), start=1):
        adj = min(1.0, p * (m - rank + 1))
        running_max = max(running_max, adj)
        adjusted[key] = round(running_max, 10)
    return adjusted


def fisher_z_ci(r: float, n: int) -> list[float] | None:
    if n <= 3 or abs(r) >= 1:
        return None
    z = math.atanh(r)
    se = 1 / math.sqrt(n - 3)
    lo = math.tanh(z - 1.96 * se)
    hi = math.tanh(z + 1.96 * se)
    return [round(lo, 6), round(hi, 6)]


def cliff_delta(x: list[float], y: list[float]) -> float:
    gt = lt = 0
    for a in x:
        for b in y:
            if a > b:
                gt += 1
            elif a < b:
                lt += 1
    denom = len(x) * len(y)
    return (gt - lt) / denom if denom else 0.0


def minimum_detectable_correlation(n: int, power: float = 0.80, alpha: float = 0.05) -> float:
    """Approximate two-sided minimum detectable Pearson/Spearman correlation."""
    z_alpha = stats.norm.ppf(1 - alpha / 2)
    z_power = stats.norm.ppf(power)
    fisher_effect = (z_alpha + z_power) / math.sqrt(max(n - 3, 1))
    return round(math.tanh(fisher_effect), 4)


def load_index() -> dict[str, Any]:
    data = load_json(INDEX_PATH)
    if not data:
        raise FileNotFoundError(f"Missing compact v14.1 index: {INDEX_PATH}")
    return data


def active_ids(index: dict[str, Any]) -> set[str]:
    return set(index.get("active", {}).keys())


def scenario_techniques(scenario: dict[str, Any], active: set[str]) -> list[str]:
    tids = []
    for stage in scenario.get("attack_stages", []) or []:
        for technique in stage.get("techniques", []) or []:
            tid = str(technique.get("technique_id", "")).strip()
            if tid in active:
                tids.append(tid)
    return tids


def generated_transition_pairs(scenarios: list[dict[str, Any]], active: set[str]) -> Counter[tuple[str, str]]:
    pairs: Counter[tuple[str, str]] = Counter()
    for scenario in scenarios:
        stages = scenario.get("attack_stages", []) or []
        for i in range(len(stages) - 1):
            left = [
                str(t.get("technique_id", "")).strip()
                for t in stages[i].get("techniques", []) or []
                if str(t.get("technique_id", "")).strip() in active
            ]
            right = [
                str(t.get("technique_id", "")).strip()
                for t in stages[i + 1].get("techniques", []) or []
                if str(t.get("technique_id", "")).strip() in active
            ]
            for a in left:
                for b in right:
                    if a != b:
                        pairs[tuple(sorted((a, b)))] += 1
    return pairs


def group_pair_counts_from_index(index: dict[str, Any], active: set[str]) -> tuple[Counter[tuple[str, str]], dict[str, set[str]]]:
    """Build group pair counts from the committed compact v14.1 index."""
    group_techs = {
        group: {tid for tid in tids if tid in active}
        for group, tids in index.get("group_techniques", {}).items()
    }
    group_techs = {group: tids for group, tids in group_techs.items() if tids}
    pair_counts: Counter[tuple[str, str]] = Counter()
    for tids in group_techs.values():
        for a, b in combinations(sorted(tids), 2):
            pair_counts[(a, b)] += 1
    return pair_counts, dict(group_techs)


def compare_pairs(
    gen_pairs: Counter[tuple[str, str]],
    real_pairs: Counter[tuple[str, str]],
) -> dict[str, float | int | None]:
    pairs = list(gen_pairs)
    shared = [p for p in pairs if real_pairs.get(p, 0) > 0]
    overlap = len(shared) / max(1, len(pairs))
    total_weight = sum(gen_pairs.values())
    weighted = sum(gen_pairs[p] for p in shared) / max(1, total_weight)
    if len(pairs) >= 3 and len(set(real_pairs.get(p, 0) for p in pairs)) > 1:
        rho, p = stats.spearmanr([gen_pairs[p] for p in pairs], [real_pairs.get(p, 0) for p in pairs])
    else:
        rho, p = float("nan"), None
    return {
        "n_generated_pairs": len(pairs),
        "n_shared_pairs": len(shared),
        "transition_corroboration": round(overlap, 6),
        "weighted_transition_corroboration": round(weighted, 6),
        "spearman_rho": None if math.isnan(float(rho)) else round(float(rho), 6),
        "spearman_p": None if p is None else float(p),
    }


def permutation_null(
    scenarios: list[dict[str, Any]],
    active: set[str],
    real_pairs: Counter[tuple[str, str]],
    *,
    n_perm: int,
    seed: int,
) -> dict[str, Any]:
    observed_pairs = generated_transition_pairs(scenarios, active)
    observed = compare_pairs(observed_pairs, real_pairs)

    corpus_ids = sorted({tid for scenario in scenarios for tid in scenario_techniques(scenario, active)})
    rng = random.Random(seed)
    overlap_vals = []
    weighted_vals = []
    rho_vals = []

    for _ in range(n_perm):
        shuffled = corpus_ids[:]
        rng.shuffle(shuffled)
        mapping = dict(zip(corpus_ids, shuffled))
        perm_pairs: Counter[tuple[str, str]] = Counter()
        for (a, b), count in observed_pairs.items():
            pa, pb = mapping[a], mapping[b]
            if pa != pb:
                perm_pairs[tuple(sorted((pa, pb)))] += count
        metrics = compare_pairs(perm_pairs, real_pairs)
        overlap_vals.append(float(metrics["transition_corroboration"]))
        weighted_vals.append(float(metrics["weighted_transition_corroboration"]))
        if metrics["spearman_rho"] is not None:
            rho_vals.append(float(metrics["spearman_rho"]))

    def empirical_p(obs: float, vals: list[float]) -> float:
        return round((1 + sum(v >= obs for v in vals)) / (len(vals) + 1), 6)

    obs_overlap = float(observed["transition_corroboration"])
    obs_weighted = float(observed["weighted_transition_corroboration"])
    obs_rho = observed["spearman_rho"]
    return {
        "observed": observed,
        "permutations": n_perm,
        "null": {
            "transition_corroboration_mean": round(float(np.mean(overlap_vals)), 6),
            "transition_corroboration_95ci": percentile_ci(overlap_vals),
            "weighted_transition_corroboration_mean": round(float(np.mean(weighted_vals)), 6),
            "weighted_transition_corroboration_95ci": percentile_ci(weighted_vals),
            "spearman_rho_mean": round(float(np.mean(rho_vals)), 6) if rho_vals else None,
            "spearman_rho_95ci": percentile_ci(rho_vals) if rho_vals else None,
        },
        "empirical_p": {
            "transition_corroboration": empirical_p(obs_overlap, overlap_vals),
            "weighted_transition_corroboration": empirical_p(obs_weighted, weighted_vals),
            "spearman_rho": empirical_p(float(obs_rho), rho_vals) if obs_rho is not None and rho_vals else None,
        },
    }


def mutation_effects(n_boot: int, seed: int) -> dict[str, Any]:
    mutation = load_json(ROOT / "mutation_analysis_v14.json")
    if not mutation:
        return {"status": "missing", "note": "mutation_analysis_v14.json not found"}
    base = mutation.get("base", {})
    eq7 = mutation.get("obfuscation_embedding_Eq7", {})
    old = mutation.get("obfuscation_random_OLD", {})
    rows = []
    for key, value in {
        "mutation.eq7_vs_base.realism_delta": eq7.get("mean_realism", 0) - base.get("mean_realism", 0),
        "mutation.eq7_vs_base.detection_delta": eq7.get("mean_detection_rate", 0) - base.get("mean_detection_rate", 0),
        "mutation.eq7_vs_random.cosine_delta": eq7.get("mean_substitution_cosine", 0) - old.get("mean_substitution_cosine", 0),
    }.items():
        rows.append(
            {
                "key": key,
                "status": "aggregate_only",
                "effect_size": round(float(value), 6),
                "ci": None,
                "p_raw": None,
                "note": "Only aggregate mutation metrics are available; scenario-level bootstrap CIs require rerunning run_mutation_analysis.py with per-scenario output.",
            }
        )
    return {"status": "aggregate_only", "tests": rows, "n_boot": n_boot, "seed": seed}


def external_validation_stats(n_perm: int, n_boot: int, seed: int) -> dict[str, Any]:
    index = load_index()
    active = active_ids(index)
    scenarios = load_jsonl(CORPUS_PATH)
    real_pairs, group_techs = group_pair_counts_from_index(index, active)
    gen_pairs = generated_transition_pairs(scenarios, active)
    pair_items = list(gen_pairs.items())

    observed = compare_pairs(gen_pairs, real_pairs)
    boot_overlap = bootstrap_ci(
        pair_items,
        lambda items: sum(1 for pair, _count in items if real_pairs.get(pair, 0) > 0) / max(1, len(items)),
        n_boot=n_boot,
        seed=seed,
    )
    boot_weighted = bootstrap_ci(
        pair_items,
        lambda items: sum(count for pair, count in items if real_pairs.get(pair, 0) > 0)
        / max(1, sum(count for _pair, count in items)),
        n_boot=n_boot,
        seed=seed + 1,
    )
    null = permutation_null(scenarios, active, real_pairs, n_perm=n_perm, seed=seed + 2)
    rho = observed.get("spearman_rho")
    rho_ci = fisher_z_ci(float(rho), int(observed["n_generated_pairs"])) if rho is not None else None

    tests = [
        {
            "key": "extval.transition_corroboration",
            "status": "recomputed",
            "effect_size": observed["transition_corroboration"],
            "ci": boot_overlap,
            "p_raw": null["empirical_p"]["transition_corroboration"],
            "null_model": "shuffle technique labels over generated transition pairs",
            "n": observed["n_generated_pairs"],
        },
        {
            "key": "extval.weighted_transition_corroboration",
            "status": "recomputed",
            "effect_size": observed["weighted_transition_corroboration"],
            "ci": boot_weighted,
            "p_raw": null["empirical_p"]["weighted_transition_corroboration"],
            "null_model": "shuffle technique labels over generated transition pairs",
            "n": sum(gen_pairs.values()),
        },
        {
            "key": "extval.spearman_rho",
            "status": "recomputed",
            "effect_size": observed["spearman_rho"],
            "ci": rho_ci,
            "p_raw": observed["spearman_p"],
            "r2": round(float(rho) ** 2, 6) if rho is not None else None,
            "null_empirical_p": null["empirical_p"]["spearman_rho"],
            "n": observed["n_generated_pairs"],
            "interpretation": "small directional association; report with rho^2 and null-model context",
        },
    ]
    return {
        "status": "recomputed",
        "active_techniques": len(active),
        "groups": len(group_techs),
        "observed": observed,
        "bootstrap": {"n_boot": n_boot, "seed": seed},
        "permutation_null": null,
        "tests": tests,
    }


def documented_registry_tests() -> list[dict[str, Any]]:
    data = load_json(REGISTRY_PATH)
    registry = {k: v for k, v in data.items() if not k.startswith("_")}
    rows = []
    graph = registry.get("graphcomplexity.pearson_r", {})
    if graph.get("status") == "missing":
        rows.append(
            {
                "key": "graphcomplexity.pearson_r",
                "status": "missing",
                "effect_size": None,
                "ci": None,
                "p_raw": None,
                "note": graph.get("note", "No source data available"),
            }
        )
    for key in ["det.env.cloud", "det.env.enterprise", "det.env.healthcare", "det.env.ics"]:
        entry = registry.get(key)
        if entry:
            rows.append(
                {
                    "key": key,
                    "status": entry.get("status"),
                    "effect_size": entry.get("value"),
                    "ci": entry.get("ci"),
                    "p_raw": None,
                    "note": entry.get("note"),
                }
            )
    return rows


def build_stats(n_perm: int, n_boot: int, seed: int) -> dict[str, Any]:
    ext = external_validation_stats(n_perm=n_perm, n_boot=n_boot, seed=seed)
    mutation = mutation_effects(n_boot=n_boot, seed=seed)
    tests = ext["tests"] + mutation.get("tests", []) + documented_registry_tests()
    p_values = {row["key"]: row.get("p_raw") for row in tests}
    adjusted = holm_bonferroni(p_values)
    for row in tests:
        row["p_holm"] = adjusted.get(row["key"])

    precision = {
        "n_1000_min_detectable_correlation_80pct_power": minimum_detectable_correlation(1000),
        "note": "For n=1000, correlations around 0.09-0.10 are detectable but still explain less than 1% of variance.",
    }
    return {
        "meta": {
            "script": "analysis/stats.py",
            "seed": seed,
            "n_permutations": n_perm,
            "n_bootstrap": n_boot,
        },
        "external_validation": ext,
        "mutation": mutation,
        "tests": tests,
        "precision": precision,
    }


def write_audit(stats_table: dict[str, Any]) -> None:
    ext = stats_table["external_validation"]
    obs = ext["observed"]
    null = ext["permutation_null"]["null"]
    p = ext["permutation_null"]["empirical_p"]
    lines = [
        "# Phase 2 Statistical Rigor Audit",
        "",
        "## External Validation",
        "",
        f"- Observed transition corroboration: {obs['transition_corroboration']:.3f}",
        f"- Null transition corroboration mean: {null['transition_corroboration_mean']:.3f} "
        f"with 95% band {null['transition_corroboration_95ci']}",
        f"- Empirical permutation p for transition corroboration: {p['transition_corroboration']}",
        f"- Observed Spearman rho: {obs['spearman_rho']:.3f}; rho^2 = {float(obs['spearman_rho']) ** 2:.3f}",
        "",
        "Interpretation: the external-validation signal should be framed as small and directional.",
        "The transition-corroboration rate is the more interpretable headline; rho is supporting evidence.",
        "",
        "## Multiple Testing",
        "",
        "All available p-values in `results/stats_table.json` include Holm-Bonferroni adjusted values.",
        "Rows without raw p-values are marked as aggregate-only, documented-only, or missing.",
        "",
        "## Remaining Gaps",
        "",
        "- `journal_experiments.py` and `all_results.json` are absent, so Table XI cannot yet be fully regenerated.",
        "- Graph-complexity correlation is still missing and must be recomputed when the journal experiment source is restored.",
        "- Mutation CIs need per-scenario outputs; current mutation JSON contains only aggregates.",
        "",
    ]
    AUDIT_PATH.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--permutations", type=int, default=1000)
    parser.add_argument("--bootstrap", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    stats_table = build_stats(n_perm=args.permutations, n_boot=args.bootstrap, seed=args.seed)
    RESULTS_PATH.write_text(json.dumps(stats_table, indent=2, sort_keys=True), encoding="utf-8")
    write_audit(stats_table)
    print(f"Wrote {RESULTS_PATH}")
    print(f"Wrote {AUDIT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
