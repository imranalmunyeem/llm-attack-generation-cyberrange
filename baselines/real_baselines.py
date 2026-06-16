"""Compute real-system ATT&CK baselines for Phase 6.

The script compares AdverSim with public, non-author-constructed corpora:

- CALDERA Stockpile adversary profiles and abilities
- Atomic Red Team atomic test definitions

Only metadata YAML is fetched. No payloads, commands, agents, or tests are
executed. Raw fetched metadata is not committed; the tracked output is the
aggregate metrics table.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import urllib.request
from collections import Counter
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any

import yaml
from scipy import stats


ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = ROOT / "mitre" / "enterprise-attack-14.1-active-techniques.json"
ADVERSIM_PATH = ROOT / "full_dataset_v14clean.jsonl"
RESULTS_PATH = ROOT / "results" / "real_baselines.json"
AUDIT_PATH = ROOT / "results" / "real_baselines_audit.md"

TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


@dataclass(frozen=True)
class SequenceCorpus:
    name: str
    source: str
    source_ref: str
    sequences: list[list[str]]
    unit_count: int
    notes: list[str]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


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


def github_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def raw_text(owner_repo: str, ref: str, path: str) -> str:
    url = f"https://raw.githubusercontent.com/{owner_repo}/{ref}/{path}"
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode("utf-8", "replace")


def resolve_ref(owner_repo: str, ref: str) -> str:
    data = github_json(f"https://api.github.com/repos/{owner_repo}/commits/{ref}")
    return data["sha"]


def repo_tree(owner_repo: str, ref: str) -> list[dict[str, Any]]:
    data = github_json(f"https://api.github.com/repos/{owner_repo}/git/trees/{ref}?recursive=1")
    return data.get("tree", [])


def safe_yaml_load(text: str) -> Any:
    return yaml.safe_load(text) if text.strip() else None


def extract_tid(value: Any) -> str | None:
    if value is None:
        return None
    match = TECHNIQUE_RE.search(str(value).upper())
    return match.group(0) if match else None


def load_index(path: Path) -> dict[str, Any]:
    data = read_json(path)
    if not data.get("active"):
        raise ValueError(f"compact ATT&CK index missing active techniques: {path}")
    return data


def active_sets(index: dict[str, Any]) -> tuple[set[str], set[str], int]:
    active = set(index["active"])
    active_bases = {tid for tid in active if "." not in tid}
    return active, active_bases, len(active_bases)


def group_pair_counts(index: dict[str, Any], active: set[str]) -> Counter[tuple[str, str]]:
    pairs: Counter[tuple[str, str]] = Counter()
    for tids in index.get("group_techniques", {}).values():
        clean = sorted({tid for tid in tids if tid in active})
        for pair in combinations(clean, 2):
            pairs[pair] += 1
    return pairs


def adversim_sequences(path: Path, active: set[str]) -> SequenceCorpus:
    scenarios = load_jsonl(path)
    sequences = []
    for scenario in scenarios:
        seq = []
        for stage in scenario.get("attack_stages", []) or []:
            stage_tids = []
            for technique in stage.get("techniques", []) or []:
                tid = extract_tid(technique.get("technique_id"))
                if tid and tid in active:
                    stage_tids.append(tid)
            # Keep stage order but avoid duplicate IDs within one stage.
            seq.extend(list(dict.fromkeys(stage_tids)))
        if seq:
            sequences.append(seq)
    return SequenceCorpus(
        name="AdverSim",
        source=str(path.relative_to(ROOT)),
        source_ref="local committed corpus",
        sequences=sequences,
        unit_count=len(scenarios),
        notes=["Generated corpus; included as the system row for baseline comparison."],
    )


def caldera_stockpile_corpus(ref: str, active: set[str]) -> SequenceCorpus:
    owner_repo = "mitre/stockpile"
    sha = resolve_ref(owner_repo, ref)
    tree = repo_tree(owner_repo, sha)
    ability_paths = [
        item["path"]
        for item in tree
        if item["path"].startswith("data/abilities/") and item["path"].endswith((".yml", ".yaml"))
    ]
    adversary_paths = [
        item["path"]
        for item in tree
        if item["path"].startswith("data/adversaries/") and item["path"].endswith((".yml", ".yaml"))
    ]

    ability_to_tid: dict[str, str] = {}
    for path in ability_paths:
        parsed = safe_yaml_load(raw_text(owner_repo, sha, path))
        rows = parsed if isinstance(parsed, list) else [parsed]
        for row in rows:
            if not isinstance(row, dict):
                continue
            ability_id = str(row.get("id") or "").strip()
            tid = extract_tid((row.get("technique") or {}).get("attack_id"))
            if ability_id and tid and tid in active:
                ability_to_tid[ability_id] = tid

    sequences = []
    profile_count = 0
    for path in adversary_paths:
        parsed = safe_yaml_load(raw_text(owner_repo, sha, path))
        rows = parsed if isinstance(parsed, list) else [parsed]
        for row in rows:
            if not isinstance(row, dict):
                continue
            ordering = row.get("atomic_ordering") or []
            if not ordering:
                continue
            profile_count += 1
            seq = []
            for ability_id in ordering:
                tid = ability_to_tid.get(str(ability_id).strip())
                if tid:
                    seq.append(tid)
            if seq:
                sequences.append(seq)

    return SequenceCorpus(
        name="CALDERA Stockpile adversary profiles",
        source=owner_repo,
        source_ref=sha,
        sequences=sequences,
        unit_count=profile_count,
        notes=[
            "Parsed Stockpile ability metadata and adversary atomic_ordering fields only.",
            "No CALDERA server, agent, ability command, or payload was executed.",
        ],
    )


def atomic_red_team_corpus(ref: str, active: set[str]) -> SequenceCorpus:
    owner_repo = "redcanaryco/atomic-red-team"
    sha = resolve_ref(owner_repo, ref)
    tree = repo_tree(owner_repo, sha)
    paths = [
        item["path"]
        for item in tree
        if item["path"].startswith("atomics/")
        and item["path"].endswith(".yaml")
        and re.search(r"atomics/T\d{4}(?:\.\d{3})?/T\d{4}(?:\.\d{3})?\.yaml$", item["path"])
    ]

    sequences = []
    tests = 0
    for path in paths:
        parsed = safe_yaml_load(raw_text(owner_repo, sha, path))
        if not isinstance(parsed, dict):
            continue
        tid = extract_tid(parsed.get("attack_technique"))
        if not tid or tid not in active:
            continue
        tests += len(parsed.get("atomic_tests") or [])
        sequences.append([tid])

    return SequenceCorpus(
        name="Atomic Red Team technique set",
        source=owner_repo,
        source_ref=sha,
        sequences=sequences,
        unit_count=tests,
        notes=[
            "Parsed atomic test YAML metadata only.",
            "Atomic tests are single-technique units, so transition metrics are not applicable.",
        ],
    )


def sequence_pairs(sequences: list[list[str]]) -> Counter[tuple[str, str]]:
    pairs: Counter[tuple[str, str]] = Counter()
    for seq in sequences:
        for left, right in zip(seq, seq[1:]):
            if left != right:
                pairs[tuple(sorted((left, right)))] += 1
    return pairs


def compare_pairs(
    observed: Counter[tuple[str, str]],
    reference: Counter[tuple[str, str]],
) -> dict[str, Any]:
    if not observed:
        return {
            "unique_transition_pairs": 0,
            "weighted_transition_count": 0,
            "transition_corroboration": None,
            "weighted_transition_corroboration": None,
            "spearman_rho": None,
            "spearman_p": None,
        }
    observed_pairs = set(observed)
    overlapping = observed_pairs & set(reference)
    weighted_total = sum(observed.values())
    weighted_overlap = sum(count for pair, count in observed.items() if pair in reference)
    rho = pval = None
    if len(observed_pairs) >= 2:
        obs_vec = []
        ref_vec = []
        for pair in sorted(observed_pairs):
            obs_vec.append(observed[pair])
            ref_vec.append(reference.get(pair, 0))
        rho, pval = stats.spearmanr(obs_vec, ref_vec)
        if isinstance(rho, float) and math.isnan(rho):
            rho = None
            pval = None
    return {
        "unique_transition_pairs": len(observed_pairs),
        "weighted_transition_count": weighted_total,
        "transition_corroboration": round(len(overlapping) / len(observed_pairs), 6),
        "weighted_transition_corroboration": round(weighted_overlap / weighted_total, 6)
        if weighted_total
        else None,
        "spearman_rho": round(float(rho), 6) if rho is not None else None,
        "spearman_p": round(float(pval), 8) if pval is not None else None,
    }


def corpus_metrics(
    corpus: SequenceCorpus,
    active: set[str],
    active_base_count: int,
    reference_pairs: Counter[tuple[str, str]],
) -> dict[str, Any]:
    ids = [tid for seq in corpus.sequences for tid in seq if tid in active]
    unique_ids = sorted(set(ids))
    base_ids = sorted({tid.split(".")[0] for tid in unique_ids})
    lengths = [len(seq) for seq in corpus.sequences]
    pairs = sequence_pairs(corpus.sequences)
    transition = compare_pairs(pairs, reference_pairs)
    return {
        "name": corpus.name,
        "source": corpus.source,
        "source_ref": corpus.source_ref,
        "unit_count": corpus.unit_count,
        "sequence_count": len(corpus.sequences),
        "technique_mentions": len(ids),
        "unique_active_v14_ids": len(unique_ids),
        "unique_active_v14_ids_list": unique_ids,
        "unique_base_techniques": len(base_ids),
        "base_technique_coverage": round(len(base_ids) / active_base_count, 6),
        "avg_sequence_length": round(sum(lengths) / len(lengths), 3) if lengths else 0,
        "max_sequence_length": max(lengths) if lengths else 0,
        "graph": {
            "avg_nodes": round(sum(lengths) / len(lengths), 3) if lengths else 0,
            "avg_edges": round(sum(max(0, length - 1) for length in lengths) / len(lengths), 3)
            if lengths
            else 0,
        },
        "external_transition_validation": transition,
        "notes": corpus.notes,
    }


def write_audit(results: dict[str, Any], path: Path) -> None:
    lines = [
        "# Phase 6 Real Baseline Audit",
        "",
        "This phase replaces purely author-constructed baselines with public",
        "metadata baselines computed with the same active ATT&CK v14.1 denominator.",
        "",
        "No baseline command, payload, agent, or atomic test is executed. The scripts",
        "download and parse metadata YAML only.",
        "",
        "## Table XIV Candidate",
        "",
        "| Corpus | Units | Unique active IDs | Base techniques | Base coverage | Transition corroboration | Avg edges |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in results["rows"]:
        ext = row["external_transition_validation"]
        tc = ext.get("transition_corroboration")
        tc_text = "n/a" if tc is None else f"{tc:.1%}"
        lines.append(
            "| {name} | {units} | {uids} | {base} | {coverage:.1%} | {tc} | {edges:.2f} |".format(
                name=row["name"],
                units=row["unit_count"],
                uids=row["unique_active_v14_ids"],
                base=row["unique_base_techniques"],
                coverage=row["base_technique_coverage"],
                tc=tc_text,
                edges=row["graph"]["avg_edges"],
            )
        )
    lines.extend(
        [
            "",
            "## Fairness Notes",
            "",
            "- All rows are filtered to active Enterprise ATT&CK v14.1 technique IDs.",
            "- Base coverage uses the same active base-technique denominator.",
            "- CALDERA Stockpile adversary profiles are ordered sequences, so transition",
            "  corroboration is comparable to AdverSim's stage-to-stage pair metric.",
            "- Atomic Red Team is a technique-set corpus, not an adversary-sequence",
            "  corpus; transition corroboration is therefore reported as not applicable.",
            "",
            "## Paper Framing",
            "",
            "Use this to soften the old Random/Template baseline claims. The key result",
            "is not that AdverSim beats every public corpus on every metric, but that",
            "Table XIV now includes real, public systems under identical ATT&CK coverage",
            "accounting.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stockpile-ref", default="master")
    parser.add_argument("--atomic-ref", default="master")
    parser.add_argument("--index", type=Path, default=INDEX_PATH)
    parser.add_argument("--adversim", type=Path, default=ADVERSIM_PATH)
    parser.add_argument("--out", type=Path, default=RESULTS_PATH)
    parser.add_argument("--audit", type=Path, default=AUDIT_PATH)
    parser.add_argument("--skip-network", action="store_true", help="Only compute local AdverSim row")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    index = load_index(args.index)
    active, _active_bases, active_base_count = active_sets(index)
    reference_pairs = group_pair_counts(index, active)

    corpora = [adversim_sequences(args.adversim, active)]
    if not args.skip_network:
        corpora.append(caldera_stockpile_corpus(args.stockpile_ref, active))
        corpora.append(atomic_red_team_corpus(args.atomic_ref, active))

    rows = [corpus_metrics(corpus, active, active_base_count, reference_pairs) for corpus in corpora]
    results = {
        "schema_version": 1,
        "active_base_technique_denominator": active_base_count,
        "group_reference_pair_count": len(reference_pairs),
        "method": (
            "Filter each corpus to active ATT&CK Enterprise v14.1 IDs; compute unique active IDs, "
            "base-technique coverage, simple sequence graph metrics, and transition corroboration "
            "against ATT&CK group co-occurrence pairs where ordered sequences exist."
        ),
        "rows": rows,
    }
    write_json(args.out, results)
    write_audit(results, args.audit)

    print(f"wrote {args.out}")
    print(f"wrote {args.audit}")
    for row in rows:
        print(
            f"{row['name']}: {row['unique_active_v14_ids']} active IDs, "
            f"{row['unique_base_techniques']} base techniques, "
            f"coverage={row['base_technique_coverage']:.1%}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
