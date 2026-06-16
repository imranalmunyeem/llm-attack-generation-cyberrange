"""Regenerate checked-in Phase 8 paper figures from tracked aggregate outputs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "paper_assets" / "figures"
MANIFEST = ROOT / "results" / "figure_manifest.json"

STYLE = {
    "blue": "#2f5d8c",
    "green": "#4f8a6d",
    "gold": "#b8872b",
    "red": "#a3483f",
    "gray": "#6f7782",
    "light": "#eef2f5",
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def save(fig: plt.Figure, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=180, bbox_inches="tight", metadata={"Software": "AdverSim Phase 8"})
    plt.close(fig)


def setup_axes(ax: plt.Axes, *, title: str, ylabel: str | None = None) -> None:
    ax.set_title(title, fontsize=11, pad=10)
    if ylabel:
        ax.set_ylabel(ylabel)
    ax.grid(axis="y", color="#d8dee6", linewidth=0.7)
    ax.set_axisbelow(True)
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)


def human_validation_figure(out_dir: Path) -> Path:
    result = load_json(ROOT / "results" / "human_validation.json")
    rows = load_csv(ROOT / "results" / "human_ratings_summary.csv")
    dimensions = [
        ("ATT&CK alignment", "mean_attck_alignment"),
        ("Stage sequence", "mean_stage_sequence"),
        ("Overall realism", "mean_overall_realism"),
    ]
    means = []
    for _label, column in dimensions:
        values = [float(row[column]) for row in rows if row.get(column)]
        means.append(sum(values) / len(values))

    alpha = result["krippendorff_alpha_ordinal"]
    rho = result["rs_vs_human_overall"]["spearman_rho"]
    ci = result["rs_vs_human_overall"]["bootstrap_95ci"]

    fig, axes = plt.subplots(1, 2, figsize=(9, 3.8))
    ax = axes[0]
    ax.bar([d[0] for d in dimensions], means, color=[STYLE["blue"], STYLE["green"], STYLE["gold"]])
    ax.set_ylim(0, 5)
    setup_axes(ax, title="Mean Human Ratings", ylabel="Mean rating (1-5)")
    ax.tick_params(axis="x", labelrotation=20)
    for i, value in enumerate(means):
        ax.text(i, value + 0.08, f"{value:.2f}", ha="center", fontsize=9)

    ax = axes[1]
    labels = ["ATT&CK", "Sequence", "Overall", "R(S) rho"]
    values = [alpha["attck_alignment"], alpha["stage_sequence"], alpha["overall_realism"], rho]
    colors = [STYLE["blue"], STYLE["green"], STYLE["gold"], STYLE["red"]]
    ax.bar(labels, values, color=colors)
    if ci:
        idx = 3
        lower = rho - ci[0]
        upper = ci[1] - rho
        ax.errorbar([idx], [rho], yerr=[[lower], [upper]], fmt="none", ecolor="#222222", capsize=4)
    ax.axhline(0, color="#222222", linewidth=0.8)
    ax.set_ylim(-0.35, 1.0)
    setup_axes(ax, title="Agreement and R(S) Alignment", ylabel="Alpha / Spearman rho")
    for i, value in enumerate(values):
        ax.text(i, value + (0.04 if value >= 0 else -0.08), f"{value:.2f}", ha="center", fontsize=9)

    fig.suptitle("Phase 7 Human Realism Validation", fontsize=12, y=1.03)
    path = out_dir / "phase7_human_validation.png"
    save(fig, path)
    return path


def baseline_coverage_figure(out_dir: Path) -> Path:
    data = load_json(ROOT / "results" / "real_baselines.json")
    rows = data["rows"]
    names = [row["name"].replace(" technique set", "\ntechnique set").replace(" adversary profiles", "\nadversary profiles") for row in rows]
    coverage = [row["base_technique_coverage"] * 100 for row in rows]
    transitions = [
        (row.get("external_transition_validation") or {}).get("transition_corroboration")
        for row in rows
    ]
    transitions = [value * 100 if value is not None else None for value in transitions]

    fig, ax = plt.subplots(figsize=(8.5, 4))
    x = range(len(rows))
    ax.bar([i - 0.18 for i in x], coverage, width=0.36, label="Base technique coverage", color=STYLE["blue"])
    transition_values = [0 if value is None else value for value in transitions]
    ax.bar([i + 0.18 for i in x], transition_values, width=0.36, label="Transition corroboration", color=STYLE["green"])
    for i, value in enumerate(transitions):
        if value is None:
            ax.text(i + 0.18, 1, "n/a", ha="center", fontsize=9, color=STYLE["gray"])
    ax.set_xticks(list(x), names)
    ax.set_ylim(0, 100)
    setup_axes(ax, title="Real Baselines vs AdverSim", ylabel="Percent")
    ax.legend(frameon=False, loc="upper left")
    path = out_dir / "real_baselines_coverage.png"
    save(fig, path)
    return path


def multimodel_figure(out_dir: Path) -> Path:
    data = load_json(ROOT / "results" / "multimodel.json")
    rows = data["model_rows"]
    models = [row["model"] for row in rows]
    first_attempt = [row["first_attempt_active_rate"] * 100 for row in rows]
    coverage = [row["base_technique_coverage"] * 100 for row in rows]

    fig, ax = plt.subplots(figsize=(7, 3.8))
    x = range(len(rows))
    ax.bar([i - 0.18 for i in x], first_attempt, width=0.36, color=STYLE["blue"], label="First-attempt active rate")
    ax.bar([i + 0.18 for i in x], coverage, width=0.36, color=STYLE["gold"], label="Base technique coverage")
    ax.set_xticks(list(x), models)
    ax.set_ylim(0, 105)
    setup_axes(ax, title="Multi-LLM Generalization", ylabel="Percent")
    ax.legend(frameon=False, loc="upper left")
    path = out_dir / "multimodel_generalization.png"
    save(fig, path)
    return path


def sigma_replay_figure(out_dir: Path) -> Path:
    data = load_json(ROOT / "results" / "sigma_measured.json")
    per_technique = data["per_technique"]
    labels = list(per_technique)
    labelled = [per_technique[key]["labelled_events"] for key in labels]
    matched = [per_technique[key]["matched_events"] for key in labels]

    fig, ax = plt.subplots(figsize=(8.5, 4))
    x = range(len(labels))
    ax.bar([i - 0.18 for i in x], labelled, width=0.36, color=STYLE["gray"], label="Labelled events")
    ax.bar([i + 0.18 for i in x], matched, width=0.36, color=STYLE["green"], label="Matched events")
    ax.set_yscale("symlog", linthresh=1)
    ax.set_xticks(list(x), labels, rotation=25, ha="right")
    setup_axes(ax, title="Empirical Sigma Replay", ylabel="Event count (symlog)")
    ax.legend(frameon=False, loc="upper left")
    path = out_dir / "sigma_replay_coverage.png"
    save(fig, path)
    return path


def soc_sensitivity_figure(out_dir: Path) -> Path:
    data = load_json(ROOT / "results" / "soc_invariance.json")
    runs = data["runs"]
    modes: dict[str, list[float]] = {}
    for run in runs:
        mode = run["params"]["detectability_mode"]
        modes.setdefault(mode, []).append(run["overall"]["detection_rate"] * 100)
    labels = sorted(modes)
    values = [modes[label] for label in labels]

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.boxplot(values, tick_labels=labels, patch_artist=True, medianprops={"color": "#222222"})
    for patch, color in zip(ax.patches, [STYLE["blue"], STYLE["green"], STYLE["gold"], STYLE["red"]]):
        patch.set_facecolor(color)
        patch.set_alpha(0.75)
    ax.set_ylim(60, 101)
    setup_axes(ax, title="SOC Simulation Sensitivity", ylabel="Detection rate (%)")
    ax.tick_params(axis="x", labelrotation=15)
    path = out_dir / "soc_sensitivity_ranges.png"
    save(fig, path)
    return path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(paths: list[Path]) -> None:
    entries = []
    for path in sorted(paths):
        entries.append(
            {
                "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                "sha256": sha256(path),
                "bytes": path.stat().st_size,
            }
        )
    MANIFEST.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "script": "analysis/regenerate_figures.py",
                "figures": entries,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    paths = [
        human_validation_figure(args.out_dir),
        baseline_coverage_figure(args.out_dir),
        multimodel_figure(args.out_dir),
        sigma_replay_figure(args.out_dir),
        soc_sensitivity_figure(args.out_dir),
    ]
    write_manifest(paths)
    for path in paths:
        print(f"wrote {path.relative_to(ROOT)}")
    print(f"wrote {MANIFEST.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
