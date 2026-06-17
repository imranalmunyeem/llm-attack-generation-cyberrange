"""Build coverage-vs-sample-size curves for cached multi-model corpora."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "data" / "generated" / "multimodel"
RESULTS = ROOT / "results" / "multimodel_coverage_curve.json"
FIGURE = ROOT / "paper" / "ieee_access_overleaf" / "figures" / "multimodel_coverage_curve.pdf"


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


def technique_ids(row: dict[str, Any]) -> set[str]:
    return {
        str(tech.get("technique_id", "")).upper()
        for stage in row.get("attack_stages", []) or []
        for tech in stage.get("techniques", []) or []
        if isinstance(tech, dict) and tech.get("technique_id")
    }


def series(rows: list[dict[str, Any]], steps: list[int]) -> list[dict[str, int]]:
    out = []
    for step in steps:
        seen: set[str] = set()
        for row in rows[:step]:
            seen.update(technique_ids(row))
        out.append(
            {
                "n": min(step, len(rows)),
                "unique_active_ids": len(seen),
                "unique_base_techniques": len({tid.split(".")[0] for tid in seen}),
            }
        )
    return out


def main() -> int:
    model_files = sorted(path for path in BASE.glob("*/*_scenarios.jsonl"))
    if not model_files:
        raise FileNotFoundError(f"no cached multi-model corpora found under {BASE}")
    steps = [25, 50, 75, 100, 125, 150, 200, 300]
    result = {"schema_version": 1, "models": {}}
    FIGURE.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(3.5, 2.45))
    for path in model_files:
        model = path.parent.name.replace("_", "-")
        rows = load_jsonl(path)
        model_series = series(rows, [step for step in steps if step <= len(rows)])
        result["models"][model] = {
            "source": str(path.relative_to(ROOT)),
            "n": len(rows),
            "series": model_series,
        }
        ax.plot(
            [item["n"] for item in model_series],
            [item["unique_base_techniques"] for item in model_series],
            marker="o",
            linewidth=1.5,
            label=model,
        )
    ax.set_xlabel("Scenarios sampled")
    ax.set_ylabel("Unique base techniques")
    ax.grid(alpha=0.25)
    ax.legend(fontsize=7, frameon=False)
    fig.tight_layout()
    fig.savefig(FIGURE)
    fig.savefig(FIGURE.with_suffix(".png"), dpi=300)
    plt.close(fig)
    RESULTS.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {RESULTS}")
    print(f"wrote {FIGURE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
