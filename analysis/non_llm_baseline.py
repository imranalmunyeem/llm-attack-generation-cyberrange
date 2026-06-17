"""Template + ATT&CK-constrained random baseline for scenario generation."""

from __future__ import annotations

import argparse
import json
import random
from itertools import combinations
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "mitre" / "enterprise-attack-14.1-active-techniques.json"
RESULTS = ROOT / "results" / "non_llm_baseline.json"
TABLE = ROOT / "paper" / "ieee_access_overleaf" / "table_non_llm_baseline.tex"
DEFAULT_CORPUS = ROOT / "data" / "generated" / "scaleup" / "adversim_scaleup_full.jsonl"


TACTICS = [
    "reconnaissance",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def load_index() -> dict[str, Any]:
    return json.loads(INDEX.read_text(encoding="utf-8"))


def primary_tactic(meta: dict[str, Any]) -> str:
    tactics = meta.get("tactics") or []
    return tactics[0] if tactics else "unknown"


def group_pairs(index: dict[str, Any], active: set[str]) -> set[tuple[str, str]]:
    pairs = set()
    for tids in index.get("group_techniques", {}).values():
        clean = sorted({tid for tid in tids if tid in active})
        for a, b in combinations(clean, 2):
            pairs.add(tuple(sorted((a, b))))
    return pairs


def score(tids: list[str], active: set[str], pairs: set[tuple[str, str]]) -> float:
    v = sum(1 for tid in tids if tid in active) / max(1, len(tids))
    g = 1.0
    adj = [tuple(sorted((a, b))) for a, b in zip(tids, tids[1:]) if a != b]
    c = sum(1 for pair in adj if pair in pairs) / max(1, len(adj))
    return round(0.4 * v + 0.35 * g + 0.25 * c, 6)


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
            rows.append(json.loads(obj) if isinstance(obj, str) else obj)
    return rows


def technique_ids(row: dict[str, Any]) -> list[str]:
    return [
        tech["technique_id"]
        for stage in row.get("attack_stages", []) or []
        for tech in stage.get("techniques", []) or []
        if isinstance(tech, dict) and tech.get("technique_id")
    ]


def detail_proxy(row: dict[str, Any]) -> float:
    """R(S)-independent scenario-detail proxy used only for baseline contrast."""

    chunks = [str(row.get("narrative", ""))]
    for stage in row.get("attack_stages", []) or []:
        chunks.append(str(stage.get("stage_name", "")))
        chunks.append(str(stage.get("description", "")))
    tokens = [tok.lower() for tok in " ".join(chunks).replace("/", " ").replace("-", " ").split() if tok.strip()]
    if not tokens:
        return 0.0
    unique_ratio = len(set(tokens)) / len(tokens)
    stage_count = len(row.get("attack_stages", []) or [])
    length_score = min(1.0, len(tokens) / 140.0)
    stage_score = min(1.0, stage_count / 4.0)
    return round(0.45 * unique_ratio + 0.35 * length_score + 0.20 * stage_score, 6)


def generate(n: int, seed: int, index: dict[str, Any]) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    active = set(index["active"])
    by_tactic: dict[str, list[str]] = {}
    for tid, meta in index["active"].items():
        by_tactic.setdefault(primary_tactic(meta), []).append(tid)
    rows = []
    for i in range(n):
        tactic_path = sorted(rng.sample(TACTICS, k=4), key=TACTICS.index)
        tids = [rng.choice(by_tactic.get(tactic, sorted(active))) for tactic in tactic_path]
        stages = [
            {
                "stage_name": tactic.replace("-", " ").title(),
                "description": f"Template baseline stage mapped to {tid}.",
                "techniques": [{"technique_id": tid, "technique_name": index["active"][tid].get("name", tid)}],
            }
            for tactic, tid in zip(tactic_path, tids)
        ]
        rows.append(
            {
                "scenario_id": f"template-baseline-{i+1:04d}",
                "attack_type": "Template Baseline",
                "environment_type": "Enterprise Network",
                "difficulty": "Medium",
                "narrative": "Template-generated ATT&CK-constrained scenario baseline.",
                "attack_stages": stages,
                "attack_graph": {"edges": [[stages[j]["stage_name"], stages[j + 1]["stage_name"]] for j in range(len(stages) - 1)]},
            }
        )
    return rows


def summarize(rows: list[dict[str, Any]], index: dict[str, Any]) -> dict[str, Any]:
    active = set(index["active"])
    pairs = group_pairs(index, active)
    all_tids = [tid for row in rows for tid in technique_ids(row)]
    scores = [
        float(row.get("realism_score", score(technique_ids(row), active, pairs)))
        for row in rows
    ]
    detail_scores = [detail_proxy(row) for row in rows]
    base = {tid.split(".")[0] for tid in all_tids}
    return {
        "n": len(rows),
        "unique_active_ids": len(set(all_tids)),
        "unique_base_techniques": len(base),
        "mean_rs": round(sum(scores) / max(1, len(scores)), 6),
        "median_rs": sorted(scores)[len(scores) // 2] if scores else None,
        "mean_detail_proxy": round(sum(detail_scores) / max(1, len(detail_scores)), 6),
    }


def write_table(result: dict[str, Any]) -> None:
    llm = result.get("llm_reference", {})
    base = result["template_baseline"]
    lines = [
        "% Auto-generated by analysis/non_llm_baseline.py",
        "\\begin{table*}[t]",
        "\\centering",
        "\\caption{LLM pipeline versus ATT\\&CK-constrained non-LLM template baseline. Matched-evaluation $n$ is used for comparison; full/source $n$ annotates unequal corpus sizes. Detail proxy is a 0--1 lexical-and-stage-detail score computed without $R(S)$ components, where higher values indicate richer narrative/stage description.}",
        "\\label{tab:non-llm-baseline}",
        "\\small",
        "\\setlength{\\tabcolsep}{2pt}",
        "\\begin{tabular}{lrrrrrr}",
        "\\toprule",
        "Generator & n full & n match & IDs & Base tech. & $R(S)$ & Detail \\\\",
        "\\midrule",
        f"AdverSim LLM & {llm.get('source_n','--')} & {llm.get('n','--')} & {llm.get('unique_active_ids','--')} & {llm.get('unique_base_techniques','--')} & {llm.get('mean_rs','--')} & {llm.get('mean_detail_proxy','--')} \\\\",
        f"Template baseline & {base['source_n']} & {base['n']} & {base['unique_active_ids']} & {base['unique_base_techniques']} & {base['mean_rs']} & {base['mean_detail_proxy']} \\\\",
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table*}",
        "",
    ]
    TABLE.parent.mkdir(parents=True, exist_ok=True)
    TABLE.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=5150)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    args = parser.parse_args()
    index = load_index()
    rows = generate(args.n, args.seed, index)
    baseline = summarize(rows, index)
    baseline["source_n"] = args.n
    llm_rows = load_jsonl(args.corpus)
    llm_eval_rows = llm_rows[: args.n] if llm_rows else []
    llm_sample = summarize(llm_eval_rows, index) if llm_eval_rows else {}
    if llm_sample:
        llm_sample["source_n"] = len(llm_rows)
    registry = json.loads((ROOT / "results" / "registry.json").read_text(encoding="utf-8")) if (ROOT / "results" / "registry.json").exists() else {}
    llm_reference = {
        **llm_sample,
        "source_n": llm_sample.get("source_n") or registry.get("corpus.scenario_count", {}).get("value"),
        "n": llm_sample.get("n") or min(args.n, int(registry.get("corpus.scenario_count", {}).get("value") or args.n)),
        "unique_active_ids": llm_sample.get("unique_active_ids") or registry.get("corpus.unique_active_v14", {}).get("value"),
        "unique_base_techniques": llm_sample.get("unique_base_techniques") or registry.get("corpus.unique_base_techniques", {}).get("value"),
        "mean_rs": llm_sample.get("mean_rs") or registry.get("realism.full_corpus_mean", {}).get("value"),
    }
    result = {"schema_version": 1, "template_baseline": baseline, "llm_reference": llm_reference}
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(result, indent=2), encoding="utf-8")
    write_table(result)
    print(f"wrote {RESULTS}")
    print(f"wrote {TABLE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
