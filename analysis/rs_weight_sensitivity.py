"""Grid-sweep R(S) weights against human ratings and emit a heatmap."""

from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
from scipy import stats


ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "results" / "human_ratings_summary.csv"
RESULTS = ROOT / "results" / "rs_weight_sensitivity.json"
FIGURE = ROOT / "paper" / "ieee_access_overleaf" / "figures" / "rs_weight_sensitivity_heatmap.pdf"


def load_rows(path: Path) -> list[dict[str, float]]:
    rows = []
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if not row.get("mean_overall_realism"):
                continue
            rows.append(
                {
                    "v": float(row["active_validity"]),
                    "g": float(row["structure"]),
                    "c": float(row["transition_coherence"]),
                    "human": float(row["mean_overall_realism"]) / 5.0,
                }
            )
    return rows


def spearman_for(rows: list[dict[str, float]], weights: tuple[float, float, float]) -> float:
    x = [weights[0] * r["v"] + weights[1] * r["g"] + weights[2] * r["c"] for r in rows]
    y = [r["human"] for r in rows]
    rho, _ = stats.spearmanr(x, y)
    return float(rho) if not np.isnan(rho) else 0.0


def bootstrap_ci(rows: list[dict[str, float]], weights: tuple[float, float, float], seed: int, n_boot: int) -> list[float]:
    rng = random.Random(seed)
    vals = []
    n = len(rows)
    for _ in range(n_boot):
        sample = [rows[rng.randrange(n)] for _ in range(n)]
        vals.append(spearman_for(sample, weights))
    lo, hi = np.percentile(vals, [2.5, 97.5])
    return [round(float(lo), 6), round(float(hi), 6)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--step", type=float, default=0.05)
    parser.add_argument("--seed", type=int, default=7007)
    parser.add_argument("--bootstrap", type=int, default=2000)
    args = parser.parse_args()
    rows = load_rows(CSV)
    values = [round(i * args.step, 10) for i in range(int(1 / args.step) + 1)]
    records = []
    best = None
    grid = np.full((len(values), len(values)), np.nan)
    for i, v_w in enumerate(values):
        for j, g_w in enumerate(values):
            c_w = round(1 - v_w - g_w, 10)
            if c_w < -1e-9:
                continue
            weights = (v_w, g_w, max(0.0, c_w))
            rho = spearman_for(rows, weights)
            record = {"weights": list(weights), "spearman_rho": round(rho, 6)}
            records.append(record)
            grid[j, i] = rho
            if best is None or rho > best["spearman_rho"]:
                best = record
    best_weights = tuple(best["weights"])
    best["bootstrap_95ci"] = bootstrap_ci(rows, best_weights, args.seed, args.bootstrap)
    original = {"weights": [0.4, 0.35, 0.25], "spearman_rho": round(spearman_for(rows, (0.4, 0.35, 0.25)), 6)}
    original["bootstrap_95ci"] = bootstrap_ci(rows, (0.4, 0.35, 0.25), args.seed + 1, args.bootstrap)

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps({"schema_version": 1, "n": len(rows), "step": args.step, "best": best, "original": original, "grid": records}, indent=2), encoding="utf-8")

    FIGURE.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(3.5, 3.0))
    im = ax.imshow(grid, origin="lower", extent=[0, 1, 0, 1], vmin=-0.35, vmax=0.15, cmap="viridis", aspect="auto")
    ax.set_xlabel("Active-validity weight V")
    ax.set_ylabel("Structure weight G")
    ax.set_title("R(S)-human Spearman rho")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(FIGURE)
    fig.savefig(FIGURE.with_suffix(".png"), dpi=300)
    plt.close(fig)
    print(f"wrote {RESULTS}")
    print(f"wrote {FIGURE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
