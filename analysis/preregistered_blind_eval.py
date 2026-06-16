"""Pre-registered blinded evaluation harness.

The script writes a preregistration artifact containing hypotheses, frozen
metrics, deterministic blind IDs, and the evaluation result. It does not expose
scenario source labels until after scores are computed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analysis.external_realism_validation import (
    group_pairs,
    load_index,
    make_scenario,
    parse_tram_report,
    realism_score,
    tram_paths,
)
from analysis.soc_sensitivity import scenario_probabilities, technique_detectability


RESULTS_PATH = ROOT / "results" / "preregistered_blind_eval.json"
AUDIT_PATH = ROOT / "results" / "preregistered_blind_eval.md"
CORPUS_PATH = ROOT / "full_dataset_v14clean.jsonl"


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


def blind_id(seed: str, label: str, idx: int) -> str:
    return hashlib.sha256(f"{seed}:{label}:{idx}".encode()).hexdigest()[:16]


def detection_proxy(scenario: dict[str, Any], detectability: dict[str, float]) -> float:
    row = scenario_probabilities(
        scenario,
        detectability=detectability,
        d0=0.7,
        alpha=0.1,
        beta=0.6,
        mode="technique_prior",
    )
    return round(float(row["detection_probability"]), 6)


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "n": len(values),
        "mean": round(sum(values) / max(1, len(values)), 6),
        "min": round(min(values), 6) if values else 0,
        "max": round(max(values), 6) if values else 0,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=40)
    parser.add_argument("--seed", type=int, default=60616)
    parser.add_argument("--out", type=Path, default=RESULTS_PATH)
    parser.add_argument("--audit", type=Path, default=AUDIT_PATH)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    seed = str(args.seed)
    rng = random.Random(args.seed)
    index = load_index()
    active = set(index["active"])
    active_list = sorted(active)
    reference_pairs = group_pairs(index, active)
    detectability = technique_detectability(index)

    adversim = load_jsonl(CORPUS_PATH)[: args.n]
    tram_reports = []
    for path in tram_paths(args.n * 3):
        report = parse_tram_report(path, active)
        if report:
            tram_reports.append(make_scenario(report))
        if len(tram_reports) >= args.n:
            break

    random_controls = []
    for i, scenario in enumerate(tram_reports):
        length = max(3, len(scenario.get("attack_stages", [])))
        tids = rng.sample(active_list, k=min(length, len(active_list)))
        random_controls.append(make_scenario({"title": f"random-control-{i}", "techniques": tids, "signal_excerpt": ""}))

    blinded_rows = []
    labels = []
    for label, rows in [("adversim", adversim), ("third_party_report", tram_reports), ("random_control", random_controls)]:
        for idx, scenario in enumerate(rows):
            blinded_rows.append(
                {
                    "blind_id": blind_id(seed, label, idx),
                    "realism": realism_score(scenario, active, reference_pairs),
                    "detection_proxy": detection_proxy(scenario, detectability),
                }
            )
            labels.append((blinded_rows[-1]["blind_id"], label))
    rng.shuffle(blinded_rows)

    frozen_scores = {row["blind_id"]: row for row in blinded_rows}
    revealed: dict[str, dict[str, list[float]]] = {}
    for bid, label in labels:
        revealed.setdefault(label, {"realism": [], "detection_proxy": []})
        revealed[label]["realism"].append(frozen_scores[bid]["realism"])
        revealed[label]["detection_proxy"].append(frozen_scores[bid]["detection_proxy"])

    group_summary = {
        label: {metric: summarize(vals) for metric, vals in metrics.items()}
        for label, metrics in revealed.items()
    }
    hypotheses = [
        {
            "id": "H1",
            "statement": "Third-party report-derived scenarios score higher on R(S) than matched random controls.",
            "decision_rule": "supported if mean R(S)_third_party_report > mean R(S)_random_control by at least 0.05",
            "result": group_summary["third_party_report"]["realism"]["mean"]
            - group_summary["random_control"]["realism"]["mean"],
        },
        {
            "id": "H2",
            "statement": "AdverSim scenarios remain comparable to third-party report scenarios on R(S).",
            "decision_rule": "supported if absolute mean difference is <= 0.10",
            "result": abs(group_summary["adversim"]["realism"]["mean"] - group_summary["third_party_report"]["realism"]["mean"]),
        },
        {
            "id": "H3",
            "statement": "Technique-prior detection proxy is evaluated blinded and reported separately from realism.",
            "decision_rule": "descriptive only; no empirical detection claim",
            "result": {
                "adversim": group_summary["adversim"]["detection_proxy"]["mean"],
                "third_party_report": group_summary["third_party_report"]["detection_proxy"]["mean"],
                "random_control": group_summary["random_control"]["detection_proxy"]["mean"],
            },
        },
    ]
    for h in hypotheses:
        if h["id"] == "H1":
            h["supported"] = h["result"] >= 0.05
        elif h["id"] == "H2":
            h["supported"] = h["result"] <= 0.10
        else:
            h["supported"] = None

    results = {
        "schema_version": 1,
        "preregistered_before_manual_review": True,
        "seed": args.seed,
        "blind_id_method": "sha256(seed:group:index) truncated to 16 hex chars",
        "frozen_metrics": [
            "R(S)-style realism = 0.4 active-ID validity + 0.35 structure + 0.25 group transition coherence",
            "Technique-prior detection proxy from ATT&CK data-source counts; descriptive only",
        ],
        "hypotheses": hypotheses,
        "group_summary_after_reveal": group_summary,
        "blinded_row_count": len(blinded_rows),
        "notes": [
            "Group labels are not needed to compute per-row scores.",
            "This harness supports preregistered/blinded evaluation; it is not a substitute for independent human annotation.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.audit.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")

    lines = [
        "# Preregistered Blinded Evaluation",
        "",
        "This artifact freezes hypotheses, metrics, sampling seed, and blind-ID",
        "construction before manual interpretation of the results.",
        "",
        "## Hypotheses",
        "",
    ]
    for h in hypotheses:
        lines.append(f"- {h['id']}: {h['statement']} Decision: {h['supported']}.")
    lines.extend(["", "## Group Summary", "", json.dumps(group_summary, indent=2)])
    args.audit.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {args.out}")
    print(f"wrote {args.audit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
