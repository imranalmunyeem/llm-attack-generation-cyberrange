"""Build a single machine-readable registry for AdverSim headline numbers.

The registry is intentionally evidence-first. Values regenerated from local
data/scripts are marked `reproducible`; values that currently exist only in
README tables are marked `documented_not_regenerated`; absent values are marked
`missing` and are not emitted as LaTeX macros.
"""

from __future__ import annotations

import json
import math
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
REGISTRY_PATH = ROOT / "results" / "registry.json"
MACROS_PATH = ROOT / "paper" / "generated_macros.tex"
AUDIT_PATH = ROOT / "results" / "number_audit.md"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, str):
                obj = json.loads(obj)
            rows.append(obj)
    return rows


class TechniqueValidator(Protocol):
    active: dict[str, Any]

    def is_valid(self, tid: str) -> bool:
        ...


class CompactTechniqueIndex:
    def __init__(self, path: Path) -> None:
        data = load_json(path)
        self.path = path
        self.source_sha256 = data.get("source_sha256")
        self.active = data.get("active", {})

    def is_valid(self, tid: str) -> bool:
        return tid in self.active


def load_technique_validator(path: Path) -> TechniqueValidator:
    if path.name.endswith("-active-techniques.json"):
        return CompactTechniqueIndex(path)
    from mitre_attack_validator import MitreAttackValidator

    return MitreAttackValidator(path)


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def wilson_ci(successes: int, n: int) -> list[float] | None:
    if n <= 0:
        return None
    z = 1.96
    p = successes / n
    denom = 1 + z**2 / n
    centre = p + z**2 / (2 * n)
    spread = z * math.sqrt((p * (1 - p) + z**2 / (4 * n)) / n)
    return [round((centre - spread) / denom, 4), round((centre + spread) / denom, 4)]


def add(
    registry: dict[str, dict[str, Any]],
    key: str,
    value: Any,
    *,
    status: str,
    source: str,
    script: str | None = None,
    n: int | None = None,
    ci: list[float] | None = None,
    sd: float | None = None,
    note: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    entry: dict[str, Any] = {
        "value": value,
        "status": status,
        "source": source,
        "script": script,
    }
    if n is not None:
        entry["n"] = n
    if ci is not None:
        entry["ci"] = ci
    if sd is not None:
        entry["sd"] = sd
    if note:
        entry["note"] = note
    if extra:
        entry.update(extra)
    registry[key] = entry


def active_base_denominator(stix_path: Path) -> int:
    validator = load_technique_validator(stix_path)
    return len([tid for tid in validator.active if "." not in tid])


def clean_corpus_coverage(corpus_path: Path, stix_path: Path) -> tuple[int, int, int, int]:
    validator = load_technique_validator(stix_path)
    rows = load_jsonl(corpus_path)
    active_ids = set()
    base_ids = set()
    for scenario in rows:
        for stage in scenario.get("attack_stages", []) or []:
            for technique in stage.get("techniques", []) or []:
                tid = str(technique.get("technique_id", "")).strip()
                if tid and validator.is_valid(tid):
                    active_ids.add(tid)
                    base_ids.add(tid.split(".")[0])
        for tid in scenario.get("mitre_attack_mapping", []) or []:
            tid = str(tid).strip()
            if tid and validator.is_valid(tid):
                active_ids.add(tid)
                base_ids.add(tid.split(".")[0])
    return len(rows), len(active_ids), len(base_ids), active_base_denominator(stix_path)


def parse_readme_tables(readme: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {"det_env": {}, "det_attack": {}}

    env_re = re.compile(
        r"^\|\s*(Cloud Infrastructure|Enterprise Network|Healthcare|ICS)\s*\|\s*(\d+)\s*"
        r"\|\s*([0-9.]+)\s*\[([0-9.]+),\s*([0-9.]+)\]\s*\|\s*([0-9.]+)\s*\|\s*([0-9.]+)\s*\|",
        re.MULTILINE,
    )
    for match in env_re.finditer(readme):
        env, n, dr, lo, hi, containment, mttd = match.groups()
        parsed["det_env"][env] = {
            "n": int(n),
            "detection_rate": float(dr),
            "ci": [float(lo), float(hi)],
            "containment_rate": float(containment),
            "mttd_min": float(mttd),
        }

    attack_re = re.compile(
        r"^\|\s*(APT|Ransomware|Insider Threat|Phishing)\s*\|\s*([0-9.]+)\s*"
        r"\[([0-9.]+),\s*([0-9.]+)\]\s*\|\s*([0-9.]+)\s*\|\s*([0-9.]+)\s*\|",
        re.MULTILINE,
    )
    for match in attack_re.finditer(readme):
        attack, dr, lo, hi, mttd, realism = match.groups()
        parsed["det_attack"][attack] = {
            "detection_rate": float(dr),
            "ci": [float(lo), float(hi)],
            "mttd_min": float(mttd),
            "realism": float(realism),
        }

    cv_match = re.search(r"\|\s*\*\*Mean[^|]*\|\s*\*\*([0-9.]+)\s*[^|]*\|\s*\*\*([0-9.]+)\s*[^|]*\|", readme)
    if cv_match:
        parsed["realism_cv_graph_mean"] = float(cv_match.group(1))
        parsed["realism_cv_mean"] = float(cv_match.group(2))
    sd_match = re.search(r"\*\*R\S*\s*=\s*0\.945\s*[^0-9]+([0-9.]+)\*\*", readme)
    if sd_match:
        parsed["realism_cv_sd"] = float(sd_match.group(1))

    sigma_match = re.search(r"Sigma detection rules generated\s*\|\s*\*\*(\d+)\s+rules", readme)
    if sigma_match:
        parsed["sigma_rules"] = int(sigma_match.group(1))

    return parsed


def format_plain(value: Any, decimals: int | None = None) -> str:
    if isinstance(value, float):
        if decimals is None:
            return f"{value:g}"
        return f"{value:.{decimals}f}"
    return str(value)


def format_percent(value: float, decimals: int = 1) -> str:
    return f"{value * 100:.{decimals}f}\\%"


MACRO_MAP: dict[str, tuple[str, str, int | None]] = {
    "baseline.adversim.base_coverage": ("BaselineAdverSimBaseCoverage", "percent", 1),
    "baseline.adversim.transition_corroboration": ("BaselineAdverSimTransition", "percent", 1),
    "baseline.atomic.base_coverage": ("BaselineAtomicBaseCoverage", "percent", 1),
    "baseline.atomic.unique_active_v14": ("BaselineAtomicUniqueActive", "plain", None),
    "baseline.caldera.base_coverage": ("BaselineCalderaBaseCoverage", "percent", 1),
    "baseline.caldera.transition_corroboration": ("BaselineCalderaTransition", "percent", 1),
    "baseline.caldera.unique_active_v14": ("BaselineCalderaUniqueActive", "plain", None),
    "corpus.unique_active_v14": ("UniqueActiveV", "plain", None),
    "corpus.scenario_count": ("ScenarioCount", "plain", None),
    "corpus.unique_base_techniques": ("UniqueBaseTechniques", "plain", None),
    "corpus.base_technique_coverage": ("BaseCoverage", "percent", 1),
    "gen.first_attempt_active_rate": ("FirstAttemptRate", "percent", 1),
    "gen.first_attempt_active_ci_low": ("FirstAttemptCIlo", "percent", 1),
    "gen.first_attempt_active_ci_high": ("FirstAttemptCIhi", "percent", 1),
    "human.alpha_attck_alignment": ("HumanAlphaAttck", "plain", 3),
    "human.alpha_overall_realism": ("HumanAlphaOverall", "plain", 3),
    "human.alpha_stage_sequence": ("HumanAlphaSequence", "plain", 3),
    "human.annotator_count": ("HumanAnnotators", "plain", None),
    "human.rs_spearman_ci_high": ("HumanRsCIhi", "plain", 3),
    "human.rs_spearman_ci_low": ("HumanRsCIlo", "plain", 3),
    "human.rs_spearman_rho": ("HumanRsRho", "plain", 3),
    "human.scenario_count": ("HumanScenarioCount", "plain", None),
    "realism.full_corpus_mean": ("RealismFull", "plain", 4),
    "realism.cv_mean": ("RealismCV", "plain", 3),
    "realism.cv_sd": ("RealismCVsd", "plain", 3),
    "robustness.attack_versions_completed": ("AttackVersionsCompleted", "plain", None),
    "robustness.min_scenario_all_ids_active_rate": ("AttackVersionMinScenarioActive", "percent", 1),
    "robustness.min_unique_id_active_rate": ("AttackVersionMinUniqueActive", "percent", 1),
    "external_realism.n_reports": ("ExternalReports", "plain", None),
    "external_realism.real_mean": ("ExternalRealMean", "plain", 3),
    "external_realism.random_mean": ("ExternalRandomMean", "plain", 3),
    "external_realism.cliff_delta": ("ExternalCliffDelta", "plain", 3),
    "extval.transition_corroboration": ("ExtCorrob", "percent", 1),
    "extval.transition_corroboration_weighted": ("ExtCorrobWeighted", "percent", 1),
    "extval.spearman_rho": ("SpearmanRho", "plain", 4),
    "multimodel.gpt4o.first_attempt_active_rate": ("MultiGptFourOMiniFirstAttempt", "percent", 1),
    "multimodel.gpt41.first_attempt_active_rate": ("MultiGptFourOneMiniFirstAttempt", "percent", 1),
    "multimodel.models_completed": ("MultiModelsCompleted", "plain", None),
    "multimodel.replication_n_per_model": ("MultiModelN", "plain", None),
    "multimodel.union_unique_active_v14": ("MultiModelUnionActive", "plain", None),
    "preregistered.blinded_row_count": ("PreregisteredRows", "plain", None),
    "preregistered.supported_hypotheses": ("PreregisteredSupportedHypotheses", "plain", None),
    "cost.per_scenario_usd": ("CostPerScenario", "plain", 6),
    "det.env.cloud": ("DetEnvCloud", "plain", 3),
    "det.env.enterprise": ("DetEnvEnterprise", "plain", 3),
    "det.env.healthcare": ("DetEnvHealthcare", "plain", 3),
    "det.env.ics": ("DetEnvICS", "plain", 3),
    "sigma.rules_generated": ("SigmaRulesGenerated", "plain", None),
    "sigma.replay.event_count": ("SigmaReplayEvents", "plain", None),
    "sigma.replay.rule_count": ("SigmaReplayRules", "plain", None),
    "sigma.replay.technique_coverage": ("SigmaReplayCoverage", "percent", 1),
    "sigma.replay.true_positive_alerts": ("SigmaReplayTruePositiveAlerts", "plain", None),
}


def macro_value(entry: dict[str, Any], mode: str, decimals: int | None) -> str:
    value = entry["value"]
    if mode == "percent":
        return format_percent(float(value), decimals or 1)
    return format_plain(value, decimals)


def write_macros(registry: dict[str, dict[str, Any]]) -> None:
    lines = [
        "% generated_macros.tex",
        "% DO NOT EDIT BY HAND -- produced by analysis/build_results_registry.py",
        "",
    ]
    for key, (macro, mode, decimals) in sorted(MACRO_MAP.items(), key=lambda x: x[1][0]):
        entry = registry.get(key)
        if not entry or entry.get("status") == "missing":
            lines.append(f"% \\{macro} omitted: registry key {key} is missing")
            continue
        lines.append(f"\\newcommand{{\\{macro}}}{{{macro_value(entry, mode, decimals)}}}")
    lines.append("")
    MACROS_PATH.parent.mkdir(parents=True, exist_ok=True)
    MACROS_PATH.write_text("\n".join(lines), encoding="utf-8")


def write_registry(registry: dict[str, dict[str, Any]]) -> None:
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "_meta": {
            "builder": "analysis/build_results_registry.py",
            "policy": "Values are included only with an explicit local source and status.",
        },
        **dict(sorted(registry.items())),
    }
    REGISTRY_PATH.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_number_audit(registry: dict[str, dict[str, Any]], readme_values: dict[str, Any]) -> None:
    lines = [
        "# Phase 1 Number Audit",
        "",
        "## Registry Status",
        "",
    ]
    counts = Counter(entry.get("status", "unknown") for entry in registry.values())
    for status, count in sorted(counts.items()):
        lines.append(f"- `{status}`: {count}")
    lines.extend(["", "## Fixed / Canonicalized Values", ""])

    rows = [
        ("Unique active ATT&CK IDs", "README says 121 active / handover flags 78,000+ manuscript artifact", "145", "validation_report_v14.json + full_dataset_v14clean.jsonl"),
        ("Base technique coverage", "README says 60.2% (121/201)", "48.8% (98/201)", "computed against active v14 base techniques"),
        ("First-attempt active-v14 rate", "README hallucination report says 100% for n=240", "92.9% for the original 1,000-scenario corpus before remediation", "validation_report_v14.json"),
        ("External validation", "README says 53.6% / rho 0.122", "55.8% unweighted, 57.0% weighted, rho 0.1248", "data/journal_results/attck_groups_validation.json"),
        ("Cost per scenario", "README prose/table also contains $0.34 per 1,000 and $0.000342", "$0.000322", "data/journal_results/hallucination_report.json"),
    ]
    lines.append("| Item | Before / conflicting source | Registry value | Evidence |")
    lines.append("|---|---|---|---|")
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")

    lines.extend(["", "## Still Missing Or Not Regenerated", ""])
    for key, entry in sorted(registry.items()):
        if entry.get("status") in {"missing", "documented_not_regenerated"}:
            lines.append(f"- `{key}`: {entry.get('status')} -- {entry.get('note') or entry.get('source')}")

    lines.extend(
        [
            "",
            "## Manuscript Wiring Status",
            "",
            "`paper/manuscript_draft.tex` is a macro-wired manuscript scaffold.",
            "Headline registry values should be cited through `paper/generated_macros.tex`.",
            "Run `analysis/audit_consistency.py --strict-paper` to check manuscript",
            "entry points for hard-coded registry literals.",
            "",
        ]
    )
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    AUDIT_PATH.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    registry: dict[str, dict[str, Any]] = {}
    previous_registry = load_json(REGISTRY_PATH)
    validation = load_json(ROOT / "validation_report_v14.json")
    mutation = load_json(ROOT / "mutation_analysis_v14.json")
    hallucination = load_json(ROOT / "data" / "journal_results" / "hallucination_report.json")
    extval = load_json(ROOT / "data" / "journal_results" / "attck_groups_validation.json")
    sigma_measured = load_json(ROOT / "results" / "sigma_measured.json")
    scaleup_validation = load_json(ROOT / "results" / "scaleup_validation.json")
    multimodel = load_json(ROOT / "results" / "multimodel.json")
    real_baselines = load_json(ROOT / "results" / "real_baselines.json")
    attack_robustness = load_json(ROOT / "results" / "attack_version_robustness.json")
    external_realism = load_json(ROOT / "results" / "external_realism_validation.json")
    preregistered = load_json(ROOT / "results" / "preregistered_blind_eval.json")
    human_validation = load_json(ROOT / "results" / "human_validation.json")
    readme = (ROOT / "README.md").read_text(encoding="utf-8", errors="ignore")
    readme_values = parse_readme_tables(readme)

    stix_path = ROOT / "mitre" / "enterprise-attack-14.1-active-techniques.json"
    if not stix_path.exists():
        stix_path = ROOT / "data" / "journal_results" / "enterprise-attack-14.1.json"
    if not stix_path.exists():
        stix_path = ROOT / "data" / "journal_results" / "enterprise-attack.json"
    clean_corpus = ROOT / "full_dataset_v14clean.jsonl"

    if clean_corpus.exists() and stix_path.exists():
        n_rows, unique_active, unique_base, denom = clean_corpus_coverage(clean_corpus, stix_path)
        add(registry, "corpus.scenario_count", n_rows, status="reproducible", source=rel(clean_corpus), script="analysis/build_results_registry.py", n=n_rows)
        add(registry, "corpus.unique_active_v14", unique_active, status="reproducible", source=rel(clean_corpus), script="mitre_attack_validator.py", n=n_rows)
        add(registry, "corpus.unique_base_techniques", unique_base, status="reproducible", source=rel(clean_corpus), script="mitre_attack_validator.py", n=n_rows)
        add(registry, "corpus.active_base_denominator", denom, status="reproducible", source=rel(stix_path), script="mitre_attack_validator.py")
        add(registry, "corpus.base_technique_coverage", unique_base / denom, status="reproducible", source=rel(clean_corpus), script="analysis/build_results_registry.py", n=denom)

    if scaleup_validation:
        summary = scaleup_validation.get("scenario_summary", {})
        scenario_count = summary.get("scenario_count") or scaleup_validation.get("n_accepted")
        unique_active = summary.get("unique_active_v14_ids")
        unique_base = summary.get("unique_base_techniques")
        coverage = summary.get("base_technique_coverage")
        denom = round(unique_base / coverage) if unique_base is not None and coverage else None
        source = "results/scaleup_validation.json"
        add(registry, "corpus.scenario_count", scenario_count, status="cached_reproducible", source=source, script="scaleup/parallel_scaleup.py", n=scenario_count)
        add(registry, "corpus.unique_active_v14", unique_active, status="cached_reproducible", source=source, script="scaleup/parallel_scaleup.py", n=scenario_count)
        add(registry, "corpus.unique_base_techniques", unique_base, status="cached_reproducible", source=source, script="scaleup/parallel_scaleup.py", n=scenario_count)
        if denom is not None:
            add(registry, "corpus.active_base_denominator", denom, status="cached_reproducible", source=source, script="scaleup/parallel_scaleup.py")
        add(registry, "corpus.base_technique_coverage", coverage, status="cached_reproducible", source=source, script="scaleup/parallel_scaleup.py", n=denom)
        add(registry, "gen.first_attempt_active_rate", scaleup_validation.get("first_attempt_active_rate"), status="cached_reproducible", source=source, script="scaleup/parallel_scaleup.py", n=scaleup_validation.get("n_requested"), ci=scaleup_validation.get("first_attempt_active_rate_wilson_95ci"))
        ci = scaleup_validation.get("first_attempt_active_rate_wilson_95ci") or []
        if len(ci) == 2:
            add(registry, "gen.first_attempt_active_ci_low", ci[0], status="cached_reproducible", source=source, script="scaleup/parallel_scaleup.py", n=scaleup_validation.get("n_requested"))
            add(registry, "gen.first_attempt_active_ci_high", ci[1], status="cached_reproducible", source=source, script="scaleup/parallel_scaleup.py", n=scaleup_validation.get("n_requested"))
        add(registry, "cost.per_scenario_usd", scaleup_validation.get("cost_per_accepted_scenario_usd"), status="cached_reproducible", source=source, script="scaleup/parallel_scaleup.py", n=scaleup_validation.get("n_accepted"))

    before = validation.get("before", {})
    if before and not scaleup_validation:
        n = 1000
        successes = round(float(before.get("first_attempt_active_pass_pct", 0)) / 100 * n)
        ci = wilson_ci(successes, n)
        add(registry, "gen.first_attempt_active_rate", successes / n, status="cached_reproducible", source="validation_report_v14.json:before", script="mitre_attack_validator.py", n=n, ci=ci)
        if ci:
            add(registry, "gen.first_attempt_active_ci_low", ci[0], status="cached_reproducible", source="validation_report_v14.json:before", script="mitre_attack_validator.py", n=n)
            add(registry, "gen.first_attempt_active_ci_high", ci[1], status="cached_reproducible", source="validation_report_v14.json:before", script="mitre_attack_validator.py", n=n)

    if hallucination and not scaleup_validation:
        add(registry, "cost.per_scenario_usd", hallucination.get("cost_per_scenario_usd"), status="cached_reproducible", source="data/journal_results/hallucination_report.json", script="instrumented_generator.py", n=hallucination.get("n_attempted"))
        add(registry, "gen.instrumented_pass_rate", hallucination.get("first_attempt_pass_rate"), status="cached_reproducible", source="data/journal_results/hallucination_report.json", script="instrumented_generator.py", n=hallucination.get("n_attempted"), ci=hallucination.get("wilson_95ci"))

    if mutation:
        base = mutation.get("base", {})
        obf = mutation.get("obfuscation_embedding_Eq7", {})
        if "mean_realism" in base:
            add(registry, "realism.full_corpus_mean", base["mean_realism"], status="cached_reproducible", source="mutation_analysis_v14.json", script="run_mutation_analysis.py", n=mutation.get("scenarios"))
        if obf:
            add(registry, "mutation.obfuscation_mean_jaccard", obf.get("mean_jaccard"), status="cached_reproducible", source="mutation_analysis_v14.json", script="run_mutation_analysis.py", n=mutation.get("scenarios"))
            add(registry, "mutation.obfuscation_mean_cosine", obf.get("mean_substitution_cosine"), status="cached_reproducible", source="mutation_analysis_v14.json", script="run_mutation_analysis.py", n=mutation.get("substitutions"))

    if readme_values.get("realism_cv_mean") is not None:
        add(registry, "realism.cv_mean", readme_values["realism_cv_mean"], status="documented_not_regenerated", source="README.md Realism Metric table", script=None, n=1000, note="journal_experiments.py is absent in this checkout")
    if readme_values.get("realism_cv_sd") is not None:
        add(registry, "realism.cv_sd", readme_values["realism_cv_sd"], status="documented_not_regenerated", source="README.md Key Results", script=None, n=1000, note="journal_experiments.py is absent in this checkout")

    if extval:
        add(registry, "extval.transition_corroboration", extval.get("overlap_fraction"), status="cached_reproducible", source="data/journal_results/attck_groups_validation.json", script="attck_groups_validation.py", n=extval.get("n_generated_pairs"))
        add(registry, "extval.transition_corroboration_weighted", extval.get("weighted_overlap"), status="cached_reproducible", source="data/journal_results/attck_groups_validation.json", script="attck_groups_validation.py", n=extval.get("n_generated_pairs"))
        add(registry, "extval.spearman_rho", extval.get("spearman_rho"), status="cached_reproducible", source="data/journal_results/attck_groups_validation.json", script="attck_groups_validation.py", n=extval.get("n_groups"), extra={"p": extval.get("spearman_p")})
    else:
        for key in [
            "extval.transition_corroboration",
            "extval.transition_corroboration_weighted",
            "extval.spearman_rho",
        ]:
            if key in previous_registry:
                registry[key] = previous_registry[key]

    env_map = {
        "Cloud Infrastructure": "det.env.cloud",
        "Enterprise Network": "det.env.enterprise",
        "Healthcare": "det.env.healthcare",
        "ICS": "det.env.ics",
    }
    for env, key in env_map.items():
        if env in readme_values.get("det_env", {}):
            row = readme_values["det_env"][env]
            add(registry, key, row["detection_rate"], status="documented_not_regenerated", source="README.md Detection Performance by Environment", script=None, n=row["n"], ci=row["ci"], note="journal_experiments.py is absent in this checkout")

    if readme_values.get("sigma_rules") is not None:
        add(registry, "sigma.rules_generated", readme_values["sigma_rules"], status="documented_not_regenerated", source="README.md Key Results", script="sigma_rule_generator.py", note="README value; smoke validates generator structure but not this exact full-corpus count")

    if sigma_measured:
        inputs = sigma_measured.get("inputs", {})
        measured = sigma_measured.get("measured", {})
        add(registry, "sigma.replay.event_count", inputs.get("event_count"), status="cached_reproducible", source="results/sigma_measured.json", script="detection/sigma_replay.py")
        add(registry, "sigma.replay.rule_count", inputs.get("rule_count"), status="cached_reproducible", source="results/sigma_measured.json", script="detection/sigma_replay.py")
        add(registry, "sigma.replay.technique_coverage", measured.get("technique_coverage"), status="cached_reproducible", source="results/sigma_measured.json", script="detection/sigma_replay.py", n=measured.get("techniques_present"))
        add(registry, "sigma.replay.true_positive_alerts", measured.get("event_true_positive_alerts"), status="cached_reproducible", source="results/sigma_measured.json", script="detection/sigma_replay.py")

    if multimodel:
        rows = multimodel.get("model_rows", [])
        add(registry, "multimodel.models_completed", len(multimodel.get("models_completed", [])), status="cached_reproducible", source="results/multimodel.json", script="analysis/multimodel.py")
        add(registry, "multimodel.replication_n_per_model", multimodel.get("replication_n_per_model"), status="cached_reproducible", source="results/multimodel.json", script="analysis/multimodel.py")
        add(registry, "multimodel.union_unique_active_v14", multimodel.get("union_unique_active_v14_ids"), status="cached_reproducible", source="results/multimodel.json", script="analysis/multimodel.py")
        for row in rows:
            model_key = str(row.get("model", "")).replace(".", "_").replace("-", "_")
            if model_key == "gpt_4o_mini":
                add(registry, "multimodel.gpt4o.first_attempt_active_rate", row.get("first_attempt_active_rate"), status="cached_reproducible", source="results/multimodel.json", script="analysis/multimodel.py", n=row.get("n_requested"))
            if model_key == "gpt_4_1_mini":
                add(registry, "multimodel.gpt41.first_attempt_active_rate", row.get("first_attempt_active_rate"), status="cached_reproducible", source="results/multimodel.json", script="analysis/multimodel.py", n=row.get("n_requested"))

    if real_baselines:
        for row in real_baselines.get("rows", []):
            name = row.get("name")
            prefix = None
            if name == "AdverSim":
                prefix = "baseline.adversim"
            elif name == "CALDERA Stockpile adversary profiles":
                prefix = "baseline.caldera"
            elif name == "Atomic Red Team technique set":
                prefix = "baseline.atomic"
            if not prefix:
                continue
            ext = row.get("external_transition_validation") or {}
            add(registry, f"{prefix}.unique_active_v14", row.get("unique_active_v14_ids"), status="cached_reproducible", source="results/real_baselines.json", script="baselines/real_baselines.py", n=row.get("unit_count"))
            add(registry, f"{prefix}.base_coverage", row.get("base_technique_coverage"), status="cached_reproducible", source="results/real_baselines.json", script="baselines/real_baselines.py", n=row.get("unit_count"))
            if ext.get("transition_corroboration") is not None:
                add(registry, f"{prefix}.transition_corroboration", ext.get("transition_corroboration"), status="cached_reproducible", source="results/real_baselines.json", script="baselines/real_baselines.py", n=ext.get("unique_transition_pairs"))

    if attack_robustness:
        versions = [row for row in attack_robustness.get("versions", []) if row.get("status") == "completed"]
        if versions:
            add(registry, "robustness.attack_versions_completed", len(versions), status="cached_reproducible", source="results/attack_version_robustness.json", script="analysis/attack_version_robustness.py")
            add(registry, "robustness.min_unique_id_active_rate", min(row.get("unique_id_active_rate", 0) for row in versions), status="cached_reproducible", source="results/attack_version_robustness.json", script="analysis/attack_version_robustness.py")
            add(registry, "robustness.min_scenario_all_ids_active_rate", min(row.get("scenario_all_ids_active_rate", 0) for row in versions), status="cached_reproducible", source="results/attack_version_robustness.json", script="analysis/attack_version_robustness.py")

    if external_realism:
        add(registry, "external_realism.n_reports", external_realism.get("n_reports"), status="cached_reproducible", source="results/external_realism_validation.json", script="analysis/external_realism_validation.py")
        add(registry, "external_realism.real_mean", external_realism.get("real_mean"), status="cached_reproducible", source="results/external_realism_validation.json", script="analysis/external_realism_validation.py", n=external_realism.get("n_reports"))
        add(registry, "external_realism.random_mean", external_realism.get("random_mean"), status="cached_reproducible", source="results/external_realism_validation.json", script="analysis/external_realism_validation.py", n=external_realism.get("n_reports"))
        test = external_realism.get("statistical_test", {})
        add(registry, "external_realism.cliff_delta", test.get("cliff_delta"), status="cached_reproducible", source="results/external_realism_validation.json", script="analysis/external_realism_validation.py")

    if preregistered:
        add(registry, "preregistered.blinded_row_count", preregistered.get("blinded_row_count"), status="cached_reproducible", source="results/preregistered_blind_eval.json", script="analysis/preregistered_blind_eval.py")
        supported = sum(1 for row in preregistered.get("hypotheses", []) if row.get("supported") is True)
        add(registry, "preregistered.supported_hypotheses", supported, status="cached_reproducible", source="results/preregistered_blind_eval.json", script="analysis/preregistered_blind_eval.py")

    if human_validation:
        alpha = human_validation.get("krippendorff_alpha_ordinal", {})
        rs = human_validation.get("rs_vs_human_overall", {})
        ci = rs.get("bootstrap_95ci") or [None, None]
        add(registry, "human.scenario_count", human_validation.get("scenario_count"), status="cached_reproducible", source="results/human_validation.json", script="annotation/harness.py")
        add(registry, "human.annotator_count", human_validation.get("annotator_count"), status="cached_reproducible", source="results/human_validation.json", script="annotation/harness.py")
        add(registry, "human.alpha_attck_alignment", alpha.get("attck_alignment"), status="cached_reproducible", source="results/human_validation.json", script="annotation/harness.py")
        add(registry, "human.alpha_stage_sequence", alpha.get("stage_sequence"), status="cached_reproducible", source="results/human_validation.json", script="annotation/harness.py")
        add(registry, "human.alpha_overall_realism", alpha.get("overall_realism"), status="cached_reproducible", source="results/human_validation.json", script="annotation/harness.py")
        add(registry, "human.rs_spearman_rho", rs.get("spearman_rho"), status="cached_reproducible", source="results/human_validation.json", script="annotation/harness.py")
        add(registry, "human.rs_spearman_ci_low", ci[0], status="cached_reproducible", source="results/human_validation.json", script="annotation/harness.py")
        add(registry, "human.rs_spearman_ci_high", ci[1], status="cached_reproducible", source="results/human_validation.json", script="annotation/harness.py")

    add(registry, "graphcomplexity.pearson_r", None, status="missing", source="not found", script=None, note="No journal_experiments.py/all_results.json source exists in this checkout")
    add(registry, "graphcomplexity.pearson_r2", None, status="missing", source="not found", script=None, note="No journal_experiments.py/all_results.json source exists in this checkout")

    write_registry(registry)
    write_macros(registry)
    write_number_audit(registry, readme_values)
    print(f"Wrote {REGISTRY_PATH}")
    print(f"Wrote {MACROS_PATH}")
    print(f"Wrote {AUDIT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
