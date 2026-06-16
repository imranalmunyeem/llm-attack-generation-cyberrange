"""External R(S) validation on public CTI/report-mapped corpora.

Uses CTID TRAM report annotation metadata as a third-party corpus, then compares
R(S)-style realism scores for report-derived technique sequences against
matched random technique sequences.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import re
import urllib.parse
import urllib.request
from itertools import combinations
from pathlib import Path
from typing import Any

from scipy import stats


ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = ROOT / "mitre" / "enterprise-attack-14.1-active-techniques.json"
RESULTS_PATH = ROOT / "results" / "external_realism_validation.json"
AUDIT_PATH = ROOT / "results" / "external_realism_validation_audit.md"

TRAM_REPO = "center-for-threat-informed-defense/tram"
TRAM_REF = "main"
TRAM_TREE_URL = f"https://api.github.com/repos/{TRAM_REPO}/git/trees/{TRAM_REF}?recursive=1"
TRAM_RAW = f"https://raw.githubusercontent.com/{TRAM_REPO}/{TRAM_REF}/"
TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


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
    return match.group(0) if match else None


def group_pairs(index: dict[str, Any], active: set[str]) -> set[tuple[str, str]]:
    pairs = set()
    for tids in index.get("group_techniques", {}).values():
        clean = sorted({tid for tid in tids if tid in active})
        for a, b in combinations(clean, 2):
            pairs.add((a, b))
    return pairs


def tram_paths(limit: int) -> list[str]:
    tree = get_json(TRAM_TREE_URL).get("tree", [])
    paths = [
        item["path"]
        for item in tree
        if item["path"].startswith("data/training/tram2_data/mjson_files/")
        and item["path"].endswith(".mjson")
    ]
    # Prefer DFIR Report examples, then fill with other CTI reports.
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
                "description": f"Third-party report annotation maps this step to {tid}.",
                "techniques": [{"technique_id": tid, "technique_name": tid}],
            }
        )
    return {
        "scenario_id": report["title"],
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


def realism_score(scenario: dict[str, Any], active: set[str], reference_pairs: set[tuple[str, str]]) -> float:
    tids = [
        extract_tid(tech.get("technique_id"))
        for stage in scenario.get("attack_stages", []) or []
        for tech in stage.get("techniques", []) or []
    ]
    tids = [tid for tid in tids if tid]
    active_ratio = sum(1 for tid in tids if tid in active) / max(1, len(tids))
    stages = scenario.get("attack_stages", []) or []
    graph = scenario.get("attack_graph", {}) or {}
    edges = graph.get("edges", []) or []
    structure = min(1.0, (len(stages) / 4) * 0.6 + (len(edges) / max(1, len(stages) - 1)) * 0.4)
    pairs = [tuple(sorted((a, b))) for a, b in zip(tids, tids[1:]) if a != b]
    coherence = sum(1 for pair in pairs if pair in reference_pairs) / max(1, len(pairs))
    return round(0.4 * active_ratio + 0.35 * structure + 0.25 * coherence, 6)


def cliff_delta(x: list[float], y: list[float]) -> float:
    gt = lt = 0
    for a in x:
        for b in y:
            if a > b:
                gt += 1
            elif a < b:
                lt += 1
    return (gt - lt) / max(1, len(x) * len(y))


def write_audit(results: dict[str, Any], path: Path) -> None:
    test = results["statistical_test"]
    lines = [
        "# External R(S) Validation Audit",
        "",
        "This evaluates an R(S)-style score on public CTI/report annotations from",
        "CTID TRAM and compares those report-derived technique sequences with",
        "matched random active-ATT&CK sequences.",
        "",
        f"Reports used: {results['n_reports']}",
        f"Real mean score: {results['real_mean']:.3f}",
        f"Random mean score: {results['random_mean']:.3f}",
        f"Mann-Whitney p-value: {test['mann_whitney_p']:.3g}",
        f"Cliff's delta: {test['cliff_delta']:.3f}",
        "",
        "## Interpretation",
        "",
        "This is an external discriminative-validity check, not a human realism study.",
        "It asks whether the metric assigns higher scores to public report-derived",
        "ATT&CK sequences than to length-matched random active-technique sequences.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=40)
    parser.add_argument("--seed", type=int, default=20260616)
    parser.add_argument("--out", type=Path, default=RESULTS_PATH)
    parser.add_argument("--audit", type=Path, default=AUDIT_PATH)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    index = load_index()
    active = set(index["active"])
    active_list = sorted(active)
    reference_pairs = group_pairs(index, active)
    rng = random.Random(args.seed)

    reports = []
    for path in tram_paths(args.limit * 3):
        report = parse_tram_report(path, active)
        if report:
            reports.append(report)
        if len(reports) >= args.limit:
            break

    real_scores = []
    random_scores = []
    sources = []
    for report in reports:
        scenario = make_scenario(report)
        real = realism_score(scenario, active, reference_pairs)
        random_tids = rng.sample(active_list, k=min(len(report["techniques"]), len(active_list)))
        random_scenario = make_scenario(report, random_tids=random_tids)
        random_score = realism_score(random_scenario, active, reference_pairs)
        real_scores.append(real)
        random_scores.append(random_score)
        sources.append({"title": report["title"], "technique_count": len(report["techniques"]), "realism_score": real})

    u_stat, p_value = stats.mannwhitneyu(real_scores, random_scores, alternative="greater")
    results = {
        "schema_version": 1,
        "source": TRAM_REPO,
        "source_ref": TRAM_REF,
        "n_reports": len(reports),
        "metric": "0.4 active-ID validity + 0.35 graph/stage structure + 0.25 ATT&CK group transition coherence",
        "real_mean": round(sum(real_scores) / max(1, len(real_scores)), 6),
        "random_mean": round(sum(random_scores) / max(1, len(random_scores)), 6),
        "real_scores": real_scores,
        "random_scores": random_scores,
        "statistical_test": {
            "mann_whitney_u": round(float(u_stat), 6),
            "mann_whitney_p": float(p_value) if not math.isnan(p_value) else None,
            "cliff_delta": round(cliff_delta(real_scores, random_scores), 6),
        },
        "sources": sources[:20],
        "notes": [
            "Raw report text is fetched at runtime and not committed.",
            "This is a discriminative-validity check using public CTI/report annotations, not independent human annotation.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.audit.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    write_audit(results, args.audit)
    print(f"wrote {args.out}")
    print(f"wrote {args.audit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
