"""External real-vs-random discrimination test for R(S).

The main experiment uses documented MITRE ATT&CK group procedure chains as a
third-party real corpus, then creates equal-size matched controls by
random-substituting techniques while preserving each chain length and tactic
profile. It reports Mann-Whitney U, AUC, and a bootstrap AUC confidence
interval. No LLM API calls are made.

Legacy TRAM helper functions are retained because the preregistered blinded
evaluation harness imports them.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import re
import urllib.parse
import urllib.request
from collections import Counter
from itertools import combinations
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from scipy import stats


ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = ROOT / "mitre" / "enterprise-attack-14.1-active-techniques.json"
RESULTS_PATH = ROOT / "results" / "external_realism_validation.json"
AUDIT_PATH = ROOT / "results" / "external_realism_validation_audit.md"

TRAM_REPO = "center-for-threat-informed-defense/tram"
TRAM_REF = "main"
TRAM_TREE_URL = f"https://api.github.com/repos/{TRAM_REPO}/git/trees/{TRAM_REF}?recursive=1"
TRAM_RAW = f"https://raw.githubusercontent.com/{TRAM_REPO}/{TRAM_REF}/"
TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)

TACTIC_ORDER = {
    "reconnaissance": 0,
    "resource-development": 1,
    "initial-access": 2,
    "execution": 3,
    "persistence": 4,
    "privilege-escalation": 5,
    "defense-evasion": 6,
    "credential-access": 7,
    "discovery": 8,
    "lateral-movement": 9,
    "collection": 10,
    "command-and-control": 11,
    "exfiltration": 12,
    "impact": 13,
}


def get_json(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def get_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode("utf-8", "replace")


def load_index() -> dict[str, Any]:
    return json.loads(INDEX_PATH.read_text(encoding="utf-8"))


def extract_tid(text: Any) -> str | None:
    match = TECHNIQUE_RE.search(str(text or "").upper())
    return match.group(0).upper() if match else None


def active_ids(index: dict[str, Any]) -> set[str]:
    return set(index.get("active", {}))


def technique_tactics(index: dict[str, Any], tid: str) -> list[str]:
    meta = index.get("active", {}).get(tid, {})
    tactics = meta.get("tactics") or []
    return [str(t).strip() for t in tactics if str(t).strip()]


def primary_tactic(index: dict[str, Any], tid: str) -> str:
    tactics = technique_tactics(index, tid)
    if not tactics:
        return "unknown"
    return min(tactics, key=lambda tactic: TACTIC_ORDER.get(tactic, 99))


def ordered_tids(index: dict[str, Any], tids: Iterable[str]) -> list[str]:
    unique = sorted(set(tids))
    return sorted(unique, key=lambda tid: (TACTIC_ORDER.get(primary_tactic(index, tid), 99), tid))


def all_pairs(tids: list[str]) -> set[tuple[str, str]]:
    return {tuple(sorted((a, b))) for a, b in combinations(sorted(set(tids)), 2) if a != b}


def adjacent_pairs(tids: list[str]) -> list[tuple[str, str]]:
    return [tuple(sorted((a, b))) for a, b in zip(tids, tids[1:]) if a != b]


def group_pairs(index: dict[str, Any], active: set[str], exclude_group: str | None = None) -> set[tuple[str, str]]:
    pairs = set()
    for group, tids in index.get("group_techniques", {}).items():
        if exclude_group and group == exclude_group:
            continue
        clean = sorted({tid for tid in tids if tid in active})
        pairs.update(all_pairs(clean))
    return pairs


def active_by_tactic(index: dict[str, Any], active: set[str]) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {}
    for tid in sorted(active):
        tactic = primary_tactic(index, tid)
        buckets.setdefault(tactic, []).append(tid)
    return buckets


def tram_paths(limit: int) -> list[str]:
    tree = get_json(TRAM_TREE_URL).get("tree", [])
    paths = [
        item["path"]
        for item in tree
        if item["path"].startswith("data/training/tram2_data/mjson_files/")
        and item["path"].endswith(".mjson")
    ]
    dfir = [p for p in paths if "dfir report" in p.lower() or "the dfir report" in p.lower()]
    rest = [p for p in paths if p not in dfir]
    return (dfir + rest)[:limit]


def parse_tram_report(path: str, active: set[str]) -> dict[str, Any] | None:
    url = TRAM_RAW + urllib.parse.quote(path)
    obj = json.loads(get_text(url))
    signal = obj.get("signal") or ""
    title = path.rsplit("/", 1)[-1].replace(".mjson", "")
    tids = []
    for aset in obj.get("asets", []) or []:
        tid = extract_tid(aset.get("type") if isinstance(aset, dict) else None)
        if tid and tid in active:
            tids.append(tid)
    unique_tids = list(dict.fromkeys(tids))
    if len(unique_tids) < 3:
        return None
    return {
        "source": "ctid_tram",
        "source_path": path,
        "title": title,
        "signal_excerpt": signal[:500],
        "techniques": unique_tids,
    }


def make_scenario(report: dict[str, Any], random_tids: list[str] | None = None) -> dict[str, Any]:
    tids = random_tids or report["techniques"]
    stages = []
    for i, tid in enumerate(tids):
        stages.append(
            {
                "stage_name": f"Reported Technique {i + 1}",
                "description": f"Third-party annotation maps this step to {tid}.",
                "techniques": [{"technique_id": tid, "technique_name": tid}],
            }
        )
    return {
        "scenario_id": report.get("title") or report.get("group") or "third-party-scenario",
        "environment_type": "Enterprise Network",
        "difficulty": "Medium",
        "attack_type": "Third-party CTI report",
        "narrative": report.get("signal_excerpt", ""),
        "attack_stages": stages,
        "mitre_attack_mapping": tids,
        "attack_graph": {
            "nodes": [stage["stage_name"] for stage in stages],
            "edges": [[stages[i]["stage_name"], stages[i + 1]["stage_name"]] for i in range(len(stages) - 1)],
        },
    }


def scenario_tids(scenario: dict[str, Any]) -> list[str]:
    tids = [
        extract_tid(tech.get("technique_id"))
        for stage in scenario.get("attack_stages", []) or []
        for tech in stage.get("techniques", []) or []
    ]
    return [tid for tid in tids if tid]


def realism_score(
    scenario: dict[str, Any],
    active: set[str],
    reference_pairs: set[tuple[str, str]],
    *,
    pair_mode: str = "adjacent",
) -> float:
    """Compute the R(S)-style proxy used in prior phases.

    The default adjacent-pair mode preserves compatibility with the
    preregistered blinded harness. The external discrimination experiment uses
    all-pairs mode because ATT&CK group procedure sets are unordered.
    """

    tids = scenario_tids(scenario)
    active_ratio = sum(1 for tid in tids if tid in active) / max(1, len(tids))

    stages = scenario.get("attack_stages", []) or []
    graph = scenario.get("attack_graph", {}) or {}
    edges = graph.get("edges", []) or []
    edge_ratio = len(edges) / max(1, len(stages) - 1)
    structure = min(1.0, (len(stages) / 4) * 0.6 + edge_ratio * 0.4)

    if pair_mode == "all_pairs":
        pairs = list(all_pairs(tids))
    else:
        pairs = adjacent_pairs(tids)
    coherence = sum(1 for pair in pairs if pair in reference_pairs) / max(1, len(pairs))
    return round(0.4 * active_ratio + 0.35 * structure + 0.25 * coherence, 6)


def group_reports(index: dict[str, Any], active: set[str], *, n: int, seed: int, min_techniques: int) -> list[dict[str, Any]]:
    eligible = []
    for group, raw_tids in index.get("group_techniques", {}).items():
        tids = ordered_tids(index, [tid for tid in raw_tids if tid in active])
        if len(tids) < min_techniques:
            continue
        eligible.append(
            {
                "source": "mitre_attack_group_techniques",
                "group": group,
                "title": group,
                "techniques": tids,
                "technique_count": len(tids),
                "tactic_profile": Counter(primary_tactic(index, tid) for tid in tids),
            }
        )

    if len(eligible) < n:
        raise ValueError(f"only {len(eligible)} ATT&CK groups have at least {min_techniques} techniques")

    rng = random.Random(seed)
    # Prefer broad documented chains, but sample deterministically among the
    # eligible set rather than hand-picking groups.
    eligible.sort(key=lambda row: (-row["technique_count"], row["group"]))
    top_pool = eligible[: max(n, min(len(eligible), int(n * 1.4)))]
    selected = rng.sample(top_pool, n)
    return sorted(selected, key=lambda row: row["group"])


def matched_random_tids(
    report: dict[str, Any],
    index: dict[str, Any],
    active: set[str],
    buckets: dict[str, list[str]],
    rng: random.Random,
) -> list[str]:
    original = set(report["techniques"])
    used: set[str] = set()
    replacements: list[str] = []
    active_list = sorted(active)

    for original_tid in report["techniques"]:
        tactic = primary_tactic(index, original_tid)
        candidates = [tid for tid in buckets.get(tactic, []) if tid not in original and tid not in used]
        if not candidates:
            candidates = [tid for tid in buckets.get(tactic, []) if tid not in used]
        if not candidates:
            candidates = [tid for tid in active_list if tid not in original and tid not in used]
        if not candidates:
            candidates = [tid for tid in active_list if tid not in used]
        choice = rng.choice(candidates)
        used.add(choice)
        replacements.append(choice)

    return ordered_tids(index, replacements)


def auc_score(real_scores: list[float], control_scores: list[float]) -> float:
    wins = ties = 0
    total = len(real_scores) * len(control_scores)
    if total == 0:
        return float("nan")
    for real in real_scores:
        for control in control_scores:
            if real > control:
                wins += 1
            elif real == control:
                ties += 1
    return (wins + 0.5 * ties) / total


def bootstrap_auc_ci(
    pairs: list[tuple[float, float]],
    *,
    n_boot: int,
    seed: int,
    alpha: float = 0.05,
) -> list[float]:
    rng = random.Random(seed)
    vals = []
    n = len(pairs)
    for _ in range(n_boot):
        sample = [pairs[rng.randrange(n)] for _ in range(n)]
        vals.append(auc_score([row[0] for row in sample], [row[1] for row in sample]))
    lo, hi = np.percentile(vals, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return [round(float(lo), 6), round(float(hi), 6)]


def cliff_delta(x: list[float], y: list[float]) -> float:
    gt = lt = 0
    for a in x:
        for b in y:
            if a > b:
                gt += 1
            elif a < b:
                lt += 1
    return (gt - lt) / max(1, len(x) * len(y))


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "n": len(values),
        "mean": round(float(np.mean(values)), 6) if values else 0.0,
        "median": round(float(np.median(values)), 6) if values else 0.0,
        "sd": round(float(np.std(values, ddof=1)), 6) if len(values) > 1 else 0.0,
        "min": round(min(values), 6) if values else 0.0,
        "max": round(max(values), 6) if values else 0.0,
    }


def run_group_discrimination(
    *,
    n: int,
    min_techniques: int,
    seed: int,
    bootstrap: int,
) -> dict[str, Any]:
    index = load_index()
    active = active_ids(index)
    buckets = active_by_tactic(index, active)
    rng = random.Random(seed)
    reports = group_reports(index, active, n=n, seed=seed, min_techniques=min_techniques)

    real_scores: list[float] = []
    control_scores: list[float] = []
    paired_rows = []

    for report in reports:
        reference_pairs = group_pairs(index, active, exclude_group=report["group"])
        real_scenario = make_scenario(report)
        control_tids = matched_random_tids(report, index, active, buckets, rng)
        control_scenario = make_scenario(
            {
                "title": f"{report['group']} matched random control",
                "techniques": control_tids,
                "signal_excerpt": "",
            }
        )

        real = realism_score(real_scenario, active, reference_pairs, pair_mode="all_pairs")
        control = realism_score(control_scenario, active, reference_pairs, pair_mode="all_pairs")
        real_scores.append(real)
        control_scores.append(control)
        paired_rows.append(
            {
                "group": report["group"],
                "technique_count": report["technique_count"],
                "real_score": real,
                "matched_control_score": control,
                "delta": round(real - control, 6),
                "real_techniques": report["techniques"],
                "matched_control_techniques": control_tids,
            }
        )

    u_stat, p_value = stats.mannwhitneyu(real_scores, control_scores, alternative="greater")
    auc = auc_score(real_scores, control_scores)
    auc_ci = bootstrap_auc_ci(list(zip(real_scores, control_scores)), n_boot=bootstrap, seed=seed + 17)
    paired_deltas = [r - c for r, c in zip(real_scores, control_scores)]
    wilcoxon = stats.wilcoxon(paired_deltas, alternative="greater", zero_method="zsplit")

    return {
        "source": "MITRE ATT&CK Enterprise documented group technique mappings",
        "n_real": len(real_scores),
        "n_controls": len(control_scores),
        "control_design": (
            "Matched random-substitution control preserving each ATT&CK group's "
            "chain length and primary tactic profile; source group's original "
            "techniques are excluded where possible."
        ),
        "scoring": {
            "metric": "R(S) = 0.4 active-ID validity + 0.35 graph/stage structure + 0.25 leave-one-group-out ATT&CK co-occurrence coherence",
            "pair_mode": "all technique pairs because ATT&CK group procedure sets are unordered",
            "reference_pairs": "All documented group co-occurrence pairs excluding the scored group",
        },
        "real": summarize(real_scores),
        "matched_random_control": summarize(control_scores),
        "paired_delta": summarize(paired_deltas),
        "statistical_test": {
            "mann_whitney_u": round(float(u_stat), 6),
            "mann_whitney_p_greater": float(p_value) if not math.isnan(float(p_value)) else None,
            "auc": round(float(auc), 6),
            "auc_bootstrap_95ci": auc_ci,
            "auc_bootstrap_replicates": bootstrap,
            "cliff_delta": round(cliff_delta(real_scores, control_scores), 6),
            "paired_wilcoxon_statistic": round(float(wilcoxon.statistic), 6),
            "paired_wilcoxon_p_greater": float(wilcoxon.pvalue),
        },
        "sampled_sources": paired_rows,
        "notes": [
            "This is a discriminative-validity test for R(S), not a human realism study.",
            "The real set is third-party ATT&CK group procedure data not authored by this project.",
            "Controls are matched by scenario length and primary tactic profile to avoid a real-vs-toy comparison.",
        ],
    }


def write_audit(results: dict[str, Any], path: Path) -> None:
    test = results["statistical_test"]
    lines = [
        "# External Real-vs-Random R(S) Discrimination Audit",
        "",
        f"Source: {results['source']}",
        f"Real scenarios: {results['n_real']}",
        f"Matched controls: {results['n_controls']}",
        "",
        "| Group | n | Mean R(S) | Median R(S) | SD |",
        "|---|---:|---:|---:|---:|",
        "| ATT&CK documented group chains | {n} | {mean:.3f} | {median:.3f} | {sd:.3f} |".format(**results["real"]),
        "| Matched random controls | {n} | {mean:.3f} | {median:.3f} | {sd:.3f} |".format(
            **results["matched_random_control"]
        ),
        "",
        "## Separation Test",
        "",
        f"- Mann-Whitney U: `{test['mann_whitney_u']}`",
        f"- One-sided p-value: `{test['mann_whitney_p_greater']:.3g}`",
        f"- AUC: `{test['auc']:.3f}`",
        f"- Bootstrap 95% CI for AUC: `{test['auc_bootstrap_95ci']}`",
        f"- Cliff's delta: `{test['cliff_delta']:.3f}`",
        f"- Paired Wilcoxon p-value: `{test['paired_wilcoxon_p_greater']:.3g}`",
        "",
        "## Design",
        "",
        results["control_design"],
        "",
        results["scoring"]["metric"],
        "",
        "## Interpretation",
        "",
        "This supports external discriminative validity if R(S) is higher for",
        "third-party ATT&CK-documented chains than for matched randomized controls.",
        "It should be framed as evidence that the metric is useful for screening",
        "realism, not as a replacement for blinded human judgment.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=100, help="Number of real ATT&CK group chains to sample.")
    parser.add_argument("--min-techniques", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20260617)
    parser.add_argument("--bootstrap", type=int, default=5000)
    parser.add_argument("--out", type=Path, default=RESULTS_PATH)
    parser.add_argument("--audit", type=Path, default=AUDIT_PATH)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    results = {
        "schema_version": 2,
        "seed": args.seed,
        "bootstrap_replicates": args.bootstrap,
        **run_group_discrimination(
            n=args.n,
            min_techniques=args.min_techniques,
            seed=args.seed,
            bootstrap=args.bootstrap,
        ),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.audit.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    write_audit(results, args.audit)
    test = results["statistical_test"]
    print(f"real n={results['n_real']} mean={results['real']['mean']:.3f}")
    print(f"control n={results['n_controls']} mean={results['matched_random_control']['mean']:.3f}")
    print(f"AUC={test['auc']:.3f} 95% CI={test['auc_bootstrap_95ci']} p={test['mann_whitney_p_greater']:.3g}")
    print(f"wrote {args.out}")
    print(f"wrote {args.audit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
