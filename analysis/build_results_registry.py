"""Build paper/ieee_access_overleaf/generated_macros.tex from results/registry.json."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "results" / "registry.json"
OUT = ROOT / "paper" / "ieee_access_overleaf" / "generated_macros.tex"

MACROS = {
    "robustness.min_scenario_all_ids_active_rate": ("AttackVersionMinScenarioActive", "pct1"),
    "robustness.min_unique_id_active_rate": ("AttackVersionMinUniqueActive", "pct1"),
    "robustness.attack_versions_completed": ("AttackVersionsCompleted", "int"),
    "attack_version.technique_mentions": ("AttackVersionTechniqueMentions", "intcomma"),
    "attack_version.requery_scenarios": ("AttackVersionRequeryScenarios", "int"),
    "corpus.base_technique_coverage": ("BaseCoverage", "pct1"),
    "baseline.adversim.base_coverage": ("BaselineAdverSimBaseCoverage", "pct1"),
    "baseline.adversim.transition_corroboration": ("BaselineAdverSimTransition", "pct1"),
    "baseline.atomic.base_coverage": ("BaselineAtomicBaseCoverage", "pct1"),
    "baseline.atomic.unique_active_v14": ("BaselineAtomicUniqueActive", "int"),
    "baseline.caldera.base_coverage": ("BaselineCalderaBaseCoverage", "pct1"),
    "baseline.caldera.transition_corroboration": ("BaselineCalderaTransition", "pct1"),
    "baseline.caldera.unique_active_v14": ("BaselineCalderaUniqueActive", "int"),
    "cost.per_scenario_usd": ("CostPerScenario", "float6"),
    "extval.transition_corroboration": ("ExtCorrob", "pct1"),
    "extval.transition_corroboration_weighted": ("ExtCorrobWeighted", "pct1"),
    "external_realism.auc": ("ExternalAUC", "float3"),
    "external_realism.auc_ci_low": ("ExternalAUCCILo", "float3"),
    "external_realism.auc_ci_high": ("ExternalAUCCIHi", "float3"),
    "external_realism.cliff_delta": ("ExternalCliffDelta", "float3"),
    "external_realism.controls": ("ExternalControls", "int"),
    "external_realism.delta_mean": ("ExternalDeltaMean", "float3"),
    "external_realism.p_value": ("ExternalPValue", "sci"),
    "external_realism.random_mean": ("ExternalRandomMean", "float3"),
    "external_realism.real_mean": ("ExternalRealMean", "float3"),
    "external_realism.reports": ("ExternalReports", "int"),
    "gen.first_attempt_active_ci_high": ("FirstAttemptCIhi", "pct1"),
    "gen.first_attempt_active_ci_low": ("FirstAttemptCIlo", "pct1"),
    "gen.first_attempt_active_rate": ("FirstAttemptRate", "pct1"),
    "human.alpha_attck_alignment": ("HumanAlphaAttck", "float3"),
    "human.alpha_overall_realism": ("HumanAlphaOverall", "float3"),
    "human.alpha_stage_sequence": ("HumanAlphaSequence", "float3"),
    "human.annotator_count": ("HumanAnnotators", "int"),
    "human.rs_spearman_ci_high": ("HumanRsCIhi", "float3"),
    "human.rs_spearman_ci_low": ("HumanRsCIlo", "float3"),
    "human.rs_spearman_rho": ("HumanRsRho", "float3"),
    "human.scenario_count": ("HumanScenarioCount", "int"),
    "multimodel.gpt4o.first_attempt_active_rate": ("MultiGptFourOMiniFirstAttempt", "pct1"),
    "multimodel.gpt41.first_attempt_active_rate": ("MultiGptFourOneMiniFirstAttempt", "pct1"),
    "multimodel.replication_n_per_model": ("MultiModelN", "int"),
    "multimodel.union_unique_active_v14": ("MultiModelUnionActive", "int"),
    "multimodel.models_completed": ("MultiModelsCompleted", "int"),
    "preregistered.blinded_row_count": ("PreregisteredRows", "int"),
    "preregistered.supported_hypotheses": ("PreregisteredSupportedHypotheses", "int"),
    "realism.cv_mean": ("RealismCV", "float3"),
    "realism.cv_sd": ("RealismCVsd", "float3"),
    "realism.full_corpus_mean": ("RealismFull", "float4"),
    "corpus.scenario_count": ("ScenarioCount", "int"),
    "sigma.replay.technique_coverage": ("SigmaReplayCoverage", "pct1"),
    "sigma.replay.event_count": ("SigmaReplayEvents", "int"),
    "sigma.replay.rule_count": ("SigmaReplayRules", "int"),
    "sigma.replay.true_positive_alerts": ("SigmaReplayTruePositiveAlerts", "int"),
    "sigma.rules_generated": ("SigmaRulesGenerated", "int"),
    "extval.spearman_rho": ("SpearmanRho", "float4"),
    "corpus.unique_active_v14": ("UniqueActiveV", "int"),
    "corpus.unique_base_techniques": ("UniqueBaseTechniques", "int"),
}


def value(registry: dict[str, Any], key: str) -> Any:
    entry = registry.get(key, {})
    return entry.get("value") if isinstance(entry, dict) else None


def fmt(raw: Any, style: str) -> str:
    if raw is None:
        return "--"
    if style == "int":
        return str(int(raw))
    if style == "intcomma":
        return f"{int(raw):,}"
    if style == "float3":
        return f"{float(raw):.3f}"
    if style == "float4":
        return f"{float(raw):.4f}"
    if style == "float6":
        return f"{float(raw):.6f}"
    if style == "pct1":
        return f"{float(raw) * 100:.1f}\\%"
    if style == "sci":
        val = float(raw)
        if val == 0:
            return "0"
        exponent = math.floor(math.log10(abs(val)))
        mantissa = val / (10**exponent)
        return f"{mantissa:.2f}\\times10^{{{exponent}}}"
    return str(raw)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    lines = [
        "% generated_macros.tex",
        "% DO NOT EDIT BY HAND -- produced by analysis/build_results_registry.py",
        "",
    ]
    for key, (macro, style) in MACROS.items():
        lines.append(f"\\newcommand{{\\{macro}}}{{{fmt(value(registry, key), style)}}}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
