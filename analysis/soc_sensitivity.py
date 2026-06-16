"""Phase 3 SOC simulation sensitivity and artifact audit.

The existing repository simulator is a per-stage Bernoulli harness. This script
does not pretend those outputs are empirical measurements; it stress-tests the
qualitative orderings under parameter sweeps and an ATT&CK metadata-derived
detectability proxy.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from itertools import product
from pathlib import Path
from statistics import mean
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CORPUS_PATH = ROOT / "full_dataset_v14clean.jsonl"
INDEX_PATH = ROOT / "mitre" / "enterprise-attack-14.1-active-techniques.json"
OUT_PATH = ROOT / "results" / "soc_invariance.json"
AUDIT_PATH = ROOT / "results" / "soc_sensitivity_audit.md"

ATTACK_TYPES = ["APT", "Ransomware", "Insider Threat", "Phishing"]
ENVIRONMENTS = ["Cloud Infrastructure", "Enterprise Network", "Healthcare", "ICS"]
DIFFICULTIES = ["Easy", "Medium", "Hard"]

STAGE_WEIGHTS = {
    "Initial Access": 0.90,
    "Execution": 0.85,
    "Persistence": 0.80,
    "Privilege Escalation": 0.75,
    "Defense Evasion": 0.70,
    "Credential Access": 0.70,
    "Discovery": 0.65,
    "Lateral Movement": 0.60,
    "Collection": 0.55,
    "Exfiltration": 0.50,
    "Data Exfiltration": 0.50,
    "Impact": 0.40,
    "Reconnaissance": 0.35,
    "Resource Development": 0.30,
}

DIFFICULTY_MULT = {"Easy": 1.15, "Medium": 1.0, "Hard": 0.82}
ENV_MULT = {
    "Cloud Infrastructure": 1.00,
    "Enterprise Network": 0.97,
    "Healthcare": 0.97,
    "ICS": 1.02,
}


def load_json(path: Path) -> dict[str, Any]:
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


def sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def clamp(value: float, lo: float = 0.02, hi: float = 0.98) -> float:
    return max(lo, min(hi, value))


def scenario_tids(stage: dict[str, Any]) -> list[str]:
    return [str(t.get("technique_id", "")).strip() for t in stage.get("techniques", []) if t.get("technique_id")]


def technique_detectability(index: dict[str, Any]) -> dict[str, float]:
    """Proxy detectability from ATT&CK data-source metadata.

    This is not empirical telemetry. It is a non-flat prior derived from how
    many ATT&CK data sources/components are associated with each technique in
    the pinned v14.1 bundle. More documented data sources imply more potential
    detection opportunities.
    """

    out = {}
    counts = [meta.get("data_source_count", 0) for meta in index.get("active", {}).values()]
    max_count = max(counts) if counts else 1
    for tid, meta in index.get("active", {}).items():
        ds_signal = meta.get("data_source_count", 0) / max_count
        subtech_signal = 0.08 if "." in tid else 0.0
        out[tid] = clamp(0.12 + 0.73 * ds_signal + subtech_signal, 0.05, 0.90)
    return out


def stage_prior(stage: dict[str, Any], detectability: dict[str, float], mode: str) -> float:
    name = stage.get("stage_name", "")
    if mode == "flat":
        return 1.0
    if mode == "stage":
        return STAGE_WEIGHTS.get(name, 0.50)
    if mode == "inverted_stage":
        return 1.0 - STAGE_WEIGHTS.get(name, 0.50) + 0.15
    if mode == "technique_prior":
        vals = [detectability.get(tid, 0.35) for tid in scenario_tids(stage)]
        tech = mean(vals) if vals else 0.35
        stage = STAGE_WEIGHTS.get(name, 0.50)
        return clamp(0.65 * tech + 0.35 * stage, 0.05, 0.95)
    raise ValueError(f"unknown detectability mode: {mode}")


def scenario_probabilities(
    scenario: dict[str, Any],
    *,
    d0: float,
    alpha: float,
    beta: float,
    mode: str,
    detectability: dict[str, float],
) -> dict[str, Any]:
    stages = scenario.get("attack_stages", []) or []
    env_mult = ENV_MULT.get(scenario.get("environment_type", ""), 1.0)
    diff_mult = DIFFICULTY_MULT.get(scenario.get("difficulty", "Medium"), 1.0)
    stage_probs = []
    survival = 1.0
    expected_mttd_num = 0.0
    detection_prob = 0.0
    maturity = d0

    for i, stage in enumerate(stages):
        prior = stage_prior(stage, detectability, mode)
        # alpha controls per-stage maturation; beta controls how strongly the
        # detectability prior contributes to the Bernoulli probability.
        maturity_i = clamp(maturity + alpha * i, 0.02, 0.98)
        p = clamp(maturity_i * ((1 - beta) + beta * prior) * env_mult * diff_mult)
        stage_probs.append(p)
        event_prob = survival * p
        detection_prob += event_prob
        expected_mttd_num += event_prob * (12 + 18 * i)
        survival *= 1 - p

    expected_mttd = expected_mttd_num / detection_prob if detection_prob > 0 else None
    return {
        "detection_probability": detection_prob,
        "miss_probability": survival,
        "expected_mttd": expected_mttd,
        "stage_count": len(stages),
        "mean_stage_probability": mean(stage_probs) if stage_probs else 0.0,
    }


def summarize_run(
    scenarios: list[dict[str, Any]],
    *,
    d0: float,
    alpha: float,
    beta: float,
    mode: str,
    detectability: dict[str, float],
) -> dict[str, Any]:
    rows = []
    for scenario in scenarios:
        metrics = scenario_probabilities(
            scenario,
            d0=d0,
            alpha=alpha,
            beta=beta,
            mode=mode,
            detectability=detectability,
        )
        rows.append({**metrics, "scenario": scenario})

    def group_summary(field: str) -> dict[str, dict[str, float | int | None]]:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            grouped[str(row["scenario"].get(field, "Unknown"))].append(row)
        out = {}
        for key, vals in grouped.items():
            mttd_vals = [v["expected_mttd"] for v in vals if v["expected_mttd"] is not None]
            out[key] = {
                "n": len(vals),
                "detection_rate": round(float(mean(v["detection_probability"] for v in vals)), 6),
                "expected_mttd": round(float(mean(mttd_vals)), 6) if mttd_vals else None,
                "mean_stage_count": round(float(mean(v["stage_count"] for v in vals)), 6),
            }
        return dict(sorted(out.items()))

    by_stage_count: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        by_stage_count[str(row["stage_count"])].append(float(row["detection_probability"]))

    return {
        "params": {"D0": d0, "alpha": alpha, "beta": beta, "detectability_mode": mode},
        "overall": {
            "n": len(rows),
            "detection_rate": round(float(mean(row["detection_probability"] for row in rows)), 6),
            "expected_mttd": round(float(mean(row["expected_mttd"] for row in rows if row["expected_mttd"] is not None)), 6),
        },
        "by_environment": group_summary("environment_type"),
        "by_attack_type": group_summary("attack_type"),
        "by_difficulty": group_summary("difficulty"),
        "by_stage_count": {
            k: {"n": len(v), "detection_rate": round(float(mean(v)), 6)}
            for k, v in sorted(by_stage_count.items(), key=lambda item: int(item[0]))
        },
    }


def ranking(summary: dict[str, Any], group: str, metric: str = "detection_rate") -> list[str]:
    rows = summary[group]
    return [k for k, _v in sorted(rows.items(), key=lambda item: (-float(item[1][metric]), item[0]))]


def pairwise_order(summary: dict[str, Any], group: str, metric: str = "detection_rate") -> set[tuple[str, str]]:
    rows = summary[group]
    order = set()
    for a, va in rows.items():
        for b, vb in rows.items():
            if a == b:
                continue
            if float(va[metric]) > float(vb[metric]):
                order.add((a, b))
    return order


def invariance(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    dimensions = {
        "environment_detection": ("by_environment", "detection_rate"),
        "attack_type_detection": ("by_attack_type", "detection_rate"),
        "difficulty_detection": ("by_difficulty", "detection_rate"),
        "stage_count_detection": ("by_stage_count", "detection_rate"),
    }
    out = {}
    for name, (group, metric) in dimensions.items():
        rankings = [ranking(s, group, metric) for s in summaries]
        top = Counter(r[0] for r in rankings if r)
        bottom = Counter(r[-1] for r in rankings if r)
        base_pairs = pairwise_order(summaries[0], group, metric)
        invariant_pairs = set(base_pairs)
        for summary in summaries[1:]:
            invariant_pairs &= pairwise_order(summary, group, metric)
        out[name] = {
            "top_counts": dict(sorted(top.items())),
            "bottom_counts": dict(sorted(bottom.items())),
            "unique_rankings": len({tuple(r) for r in rankings}),
            "invariant_pairwise_orderings": sorted([list(p) for p in invariant_pairs]),
            "status": "model_invariant" if len({tuple(r) for r in rankings}) == 1 else "parameter_sensitive",
        }

    # Analytic tautology check: independent per-stage detection rises with
    # stage count under positive p, so monotonic stage ordering is expected.
    monotonic_count = 0
    for summary in summaries:
        rows = summary["by_stage_count"]
        vals = [rows[k]["detection_rate"] for k in sorted(rows, key=int)]
        if all(b >= a for a, b in zip(vals, vals[1:])):
            monotonic_count += 1
    out["stage_count_tautology"] = {
        "monotonic_runs": monotonic_count,
        "total_runs": len(summaries),
        "status": "model_artifact",
        "aggregate_monotonic_status": "all_runs_monotonic" if monotonic_count == len(summaries) else "composition_sensitive",
        "analytic_note": "For a fixed scenario under independent per-stage detection with p_i > 0, P(detect at least once)=1-prod_i(1-p_i), so adding stages cannot lower detection probability unless per-stage probabilities are changed. Aggregate stage-count bins can still be composition-sensitive.",
    }
    return out


def classify_findings(inv: dict[str, Any]) -> dict[str, Any]:
    env = inv["environment_detection"]
    attack = inv["attack_type_detection"]
    return {
        "environment_ordering": {
            "tag": "model_invariant" if env["status"] == "model_invariant" else "parameter_sensitive",
            "recommended_language": "Report only invariant pairwise orderings; avoid claiming a universal environment ranking unless the full ranking is invariant.",
        },
        "attack_type_ordering": {
            "tag": "model_invariant" if attack["status"] == "model_invariant" else "parameter_sensitive",
            "recommended_language": "Treat attack-type detection rankings as simulation-harness behavior unless preserved under all detectability assumptions.",
        },
        "longer_chains_easier_to_detect": {
            "tag": "model_artifact",
            "recommended_language": "State this is expected analytically from the independent per-stage Bernoulli model; the contribution is magnitude/sensitivity, not discovery of the trend.",
        },
        "mttd_improvement_or_convergence": {
            "tag": "model_artifact",
            "recommended_language": "Frame Eq. 10 style convergence as harness stability/illustrative adaptation, not empirical analyst maturation.",
        },
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    scenarios = load_jsonl(CORPUS_PATH)
    index = load_json(INDEX_PATH)
    detectability = technique_detectability(index)
    d0_values = [float(x) for x in args.d0]
    alpha_values = [float(x) for x in args.alpha]
    beta_values = [float(x) for x in args.beta]
    modes = args.modes

    summaries = []
    for d0, alpha, beta, mode in product(d0_values, alpha_values, beta_values, modes):
        summaries.append(
            summarize_run(
                scenarios,
                d0=d0,
                alpha=alpha,
                beta=beta,
                mode=mode,
                detectability=detectability,
            )
        )

    inv = invariance(summaries)
    result = {
        "meta": {
            "script": "analysis/soc_sensitivity.py",
            "corpus": "full_dataset_v14clean.jsonl",
            "scenario_count": len(scenarios),
            "parameter_grid": {
                "D0": d0_values,
                "alpha": alpha_values,
                "beta": beta_values,
                "detectability_modes": modes,
            },
            "runs": len(summaries),
            "deterministic": True,
        },
        "baseline_run": summaries[0],
        "alternative_technique_prior_run": next(
            (s for s in summaries if s["params"]["detectability_mode"] == "technique_prior"),
            None,
        ),
        "invariance": inv,
        "finding_classification": classify_findings(inv),
        "runs": summaries,
    }
    return result


def write_audit(result: dict[str, Any]) -> None:
    inv = result["invariance"]
    cls = result["finding_classification"]
    lines = [
        "# Phase 3 SOC Simulation Artifact Audit",
        "",
        "## Scope",
        "",
        "This analysis treats detection, MTTD, and convergence as simulation outputs, not empirical measurements.",
        "It sweeps the Bernoulli harness parameters and compares flat/stage detectability against a non-flat ATT&CK metadata proxy.",
        "",
        "## Invariance Summary",
        "",
    ]
    for key, value in inv.items():
        lines.append(f"- `{key}`: `{value['status']}`")
    lines.extend(["", "## Finding Tags", ""])
    for key, value in cls.items():
        lines.append(f"- `{key}`: `{value['tag']}` -- {value['recommended_language']}")
    lines.extend(
        [
            "",
            "## Required Paper Reframe",
            "",
            "- Avoid words like measured/observed for simulated detection or MTTD until Phase 4 replay exists.",
            "- Present longer-chain detection as an analytic consequence of independent per-stage detection.",
            "- Report parameter-sensitive orderings as sensitivity results, not empirical findings.",
            "- Treat feedback-loop convergence as harness stability, not proof of analyst maturation.",
            "",
        ]
    )
    AUDIT_PATH.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phase 3 SOC simulation sensitivity analysis")
    parser.add_argument("--d0", nargs="+", default=["0.5", "0.6", "0.7", "0.8", "0.9"])
    parser.add_argument("--alpha", nargs="+", default=["0.05", "0.1", "0.2"])
    parser.add_argument("--beta", nargs="+", default=["0.4", "0.6", "0.8"])
    parser.add_argument("--modes", nargs="+", default=["flat", "stage", "inverted_stage", "technique_prior"])
    return parser.parse_args()


def main() -> int:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    result = run(parse_args())
    OUT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    write_audit(result)
    print(f"Wrote {OUT_PATH}")
    print(f"Wrote {AUDIT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
