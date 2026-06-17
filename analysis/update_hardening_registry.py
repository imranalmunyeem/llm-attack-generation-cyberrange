"""Merge reviewer-hardening outputs into results/registry.json."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "results" / "registry.json"


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def add(reg: dict[str, Any], key: str, value: Any, source: str, script: str, n: int | None = None) -> None:
    entry = {
        "value": value,
        "source": source,
        "script": script,
        "status": "cached_reproducible",
    }
    if n is not None:
        entry["n"] = n
    reg[key] = entry


def main() -> int:
    reg = load(REGISTRY)
    reg.setdefault("_meta", {})["hardening_registry_update"] = "analysis/update_hardening_registry.py"

    diversity = load(ROOT / "results" / "corpus_diversity.json")
    if diversity:
        glob = diversity["global"]
        add(reg, "diversity.effective_unique_count", glob["effective_unique_count"], "results/corpus_diversity.json", "analysis/corpus_diversity.py", glob["n"])
        add(reg, "diversity.near_duplicate_rate", glob["near_duplicate_rate"], "results/corpus_diversity.json", "analysis/corpus_diversity.py", glob["pairs_evaluated"])
        add(reg, "diversity.mean_jaccard", glob["mean_jaccard"], "results/corpus_diversity.json", "analysis/corpus_diversity.py", glob["pairs_evaluated"])
        add(reg, "diversity.p95_jaccard", glob["p95_jaccard"], "results/corpus_diversity.json", "analysis/corpus_diversity.py", glob["pairs_evaluated"])
        add(reg, "diversity.max_jaccard", glob["max_jaccard"], "results/corpus_diversity.json", "analysis/corpus_diversity.py", glob["pairs_evaluated"])
        for row in diversity.get("per_cell", []):
            safe_cell = row["cell"].lower().replace(" / ", ".").replace(" ", "_").replace("-", "_")
            add(reg, f"diversity.cell.{safe_cell}.max_jaccard", row["max_jaccard"], "results/corpus_diversity.json", "analysis/corpus_diversity.py", row["pairs_evaluated"])

    robustness = load(ROOT / "results" / "attack_version_robustness.json")
    if robustness:
        versions = robustness.get("versions", [])
        if versions:
            first = versions[0]
            add(reg, "attack_version.technique_mentions", first.get("corpus", {}).get("technique_occurrence_count"), "results/attack_version_robustness.json", "analysis/attack_version_robustness.py")
            requery = max(
                int(version.get("scenario_validity", {}).get("scenario_count_requiring_requery", 0))
                for version in versions
            )
            add(reg, "attack_version.requery_scenarios", requery, "results/attack_version_robustness.json", "analysis/attack_version_robustness.py")

    scaleup = load(ROOT / "results" / "scaleup_validation.json")
    if scaleup:
        summary = scaleup.get("scenario_summary", {})
        n = summary.get("scenario_count") or scaleup.get("n_accepted")
        for source_key, registry_key in (
            ("by_attack_type", "attack_type"),
            ("by_environment", "environment"),
            ("by_difficulty", "difficulty"),
        ):
            counts = summary.get(source_key, {})
            if not isinstance(counts, dict):
                continue
            for label, value in counts.items():
                safe_label = str(label).lower().replace(" ", "_").replace("-", "_")
                add(
                    reg,
                    f"scaleup.{registry_key}.{safe_label}",
                    value,
                    "results/scaleup_validation.json",
                    "analysis/scaleup_validation.py",
                    n,
                )

    baseline = load(ROOT / "results" / "non_llm_baseline.json")
    if baseline:
        base = baseline["template_baseline"]
        for field in ("n", "source_n", "unique_active_ids", "unique_base_techniques", "mean_rs", "median_rs", "mean_detail_proxy"):
            add(reg, f"non_llm.{field}", base[field], "results/non_llm_baseline.json", "analysis/non_llm_baseline.py", base.get("n"))
        llm = baseline.get("llm_reference", {})
        for field in ("n", "source_n", "unique_active_ids", "unique_base_techniques", "mean_rs", "mean_detail_proxy"):
            if field in llm:
                add(reg, f"non_llm.llm_{field}", llm[field], "results/non_llm_baseline.json", "analysis/non_llm_baseline.py", llm.get("n"))

    external = load(ROOT / "results" / "external_realism_validation.json")
    if external:
        test = external.get("statistical_test", {})
        add(reg, "external_realism.reports", external.get("n_real"), "results/external_realism_validation.json", "analysis/external_realism_validation.py")
        add(reg, "external_realism.controls", external.get("n_controls"), "results/external_realism_validation.json", "analysis/external_realism_validation.py")
        for key, reg_key in (
            ("auc", "external_realism.auc"),
            ("cliff_delta", "external_realism.cliff_delta"),
            ("mann_whitney_p_greater", "external_realism.p_value"),
        ):
            if key in test:
                add(reg, reg_key, test[key], "results/external_realism_validation.json", "analysis/external_realism_validation.py")
        ci = test.get("auc_bootstrap_95ci", [])
        if len(ci) == 2:
            add(reg, "external_realism.auc_ci_low", ci[0], "results/external_realism_validation.json", "analysis/external_realism_validation.py")
            add(reg, "external_realism.auc_ci_high", ci[1], "results/external_realism_validation.json", "analysis/external_realism_validation.py")
        if "real" in external:
            add(reg, "external_realism.real_mean", external["real"].get("mean"), "results/external_realism_validation.json", "analysis/external_realism_validation.py")
        if "matched_random_control" in external:
            add(reg, "external_realism.random_mean", external["matched_random_control"].get("mean"), "results/external_realism_validation.json", "analysis/external_realism_validation.py")
        if "paired_delta" in external:
            add(reg, "external_realism.delta_mean", external["paired_delta"].get("mean"), "results/external_realism_validation.json", "analysis/external_realism_validation.py")

    rs = load(ROOT / "results" / "rs_weight_sensitivity.json")
    if rs:
        add(reg, "rs_sensitivity.best_spearman", rs["best"]["spearman_rho"], "results/rs_weight_sensitivity.json", "analysis/rs_weight_sensitivity.py", rs["n"])
        for idx, value in enumerate(rs["best"]["weights"]):
            add(reg, f"rs_sensitivity.best_weight_{idx}", value, "results/rs_weight_sensitivity.json", "analysis/rs_weight_sensitivity.py", rs["n"])
        ci = rs["best"].get("bootstrap_95ci", [])
        if len(ci) == 2:
            add(reg, "rs_sensitivity.best_ci_low", ci[0], "results/rs_weight_sensitivity.json", "analysis/rs_weight_sensitivity.py", rs["n"])
            add(reg, "rs_sensitivity.best_ci_high", ci[1], "results/rs_weight_sensitivity.json", "analysis/rs_weight_sensitivity.py", rs["n"])

    sigma = load(ROOT / "results" / "sigma_replay_intervals.json")
    if sigma:
        ci = sigma.get("technique_coverage_95ci", [])
        if len(ci) == 2:
            add(reg, "sigma.replay.technique_coverage_ci_low", ci[0], "results/sigma_replay_intervals.json", "analysis/sigma_replay_intervals.py", sigma["technique_count"])
            add(reg, "sigma.replay.technique_coverage_ci_high", ci[1], "results/sigma_replay_intervals.json", "analysis/sigma_replay_intervals.py", sigma["technique_count"])
        for row in sigma.get("per_technique", []):
            prefix = "sigma.replay." + row["technique"].replace(".", "_")
            add(reg, f"{prefix}.labelled_events", row["labelled_events"], "results/sigma_replay_intervals.json", "analysis/sigma_replay_intervals.py")
            add(reg, f"{prefix}.matched_events", row["matched_events"], "results/sigma_replay_intervals.json", "analysis/sigma_replay_intervals.py")
            add(reg, f"{prefix}.event_match_rate", row["event_match_rate"], "results/sigma_replay_intervals.json", "analysis/sigma_replay_intervals.py")

    leakage = load(ROOT / "results" / "external_leakage_audit.json")
    if leakage:
        add(reg, "external_leakage.residual_rate", leakage["residual_leakage_rate"], "results/external_leakage_audit.json", "analysis/leakage_audit.py", leakage["total_pairs"])
        add(reg, "external_leakage.source_only_pairs_excluded", leakage["source_only_pairs_excluded"], "results/external_leakage_audit.json", "analysis/leakage_audit.py", leakage["total_pairs"])
        add(reg, "external_leakage.source_group_exclusion_applied", int(bool(leakage["source_group_exclusion_applied"])), "results/external_leakage_audit.json", "analysis/leakage_audit.py")

    contamination = load(ROOT / "results" / "contamination_audit.json")
    if contamination:
        for field in ("n_scenarios", "exact_set_matches", "subset_matches", "high_jaccard_matches", "max_jaccard"):
            add(reg, f"contamination.{field}", contamination[field], "results/contamination_audit.json", "analysis/contamination_audit.py", contamination.get("n_scenarios"))

    curve = load(ROOT / "results" / "multimodel_coverage_curve.json")
    if curve:
        for model, payload in curve.get("models", {}).items():
            safe_model = model.replace("-", "_").replace(".", "_")
            if payload.get("series"):
                last = payload["series"][-1]
                add(reg, f"multimodel_curve.{safe_model}.n", last["n"], "results/multimodel_coverage_curve.json", "analysis/multimodel_coverage_curve.py")
                add(reg, f"multimodel_curve.{safe_model}.base_techniques_at_n", last["unique_base_techniques"], "results/multimodel_coverage_curve.json", "analysis/multimodel_coverage_curve.py", last["n"])

    REGISTRY.write_text(json.dumps(reg, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"updated {REGISTRY}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
