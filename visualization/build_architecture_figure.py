"""Build the registry-driven Figure 1 architecture diagram."""

from __future__ import annotations

import argparse
import json
import textwrap
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "results" / "registry.json"
DEFAULT_OUT = ROOT / "paper" / "ieee_access_overleaf" / "figures" / "architecture.pdf"


def load_value(registry: dict[str, Any], key: str, default: Any = "?") -> Any:
    entry = registry.get(key, {})
    return entry.get("value", default) if isinstance(entry, dict) else default


def fmt_percent(value: Any) -> str:
    try:
        return f"{float(value) * 100:.1f}%"
    except Exception:
        return str(value)


def box(ax, x: float, y: float, w: float, h: float, title: str, body: str, color: str) -> None:
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0.02,rounding_size=0.015",
        linewidth=1.1,
        edgecolor="#2b2b2b",
        facecolor=color,
    )
    ax.add_patch(patch)
    wrapped = "\n".join(
        "\n".join(textwrap.wrap(line, width=18, break_long_words=False)) for line in body.splitlines()
    )
    ax.text(x + w / 2, y + h - 0.045, title, ha="center", va="top", fontsize=9.2, weight="bold")
    ax.text(x + w / 2, y + h - 0.115, wrapped, ha="center", va="top", fontsize=7.2, linespacing=1.22)


def arrow(ax, x1: float, y1: float, x2: float, y2: float) -> None:
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=14, lw=1.2, color="#333333"))


def build(registry_path: Path, out_path: Path) -> None:
    registry = json.loads(registry_path.read_text(encoding="utf-8")) if registry_path.exists() else {}
    scenarios = load_value(registry, "corpus.scenario_count")
    active = load_value(registry, "corpus.unique_active_v14")
    base = load_value(registry, "corpus.unique_base_techniques")
    first = fmt_percent(load_value(registry, "gen.first_attempt_active_rate"))
    sigma_rules = load_value(registry, "sigma.replay.rule_count")
    sigma_events = load_value(registry, "sigma.replay.event_count")
    human_n = load_value(registry, "human.scenario_count")
    human_r = load_value(registry, "human.annotator_count")

    fig, ax = plt.subplots(figsize=(10.5, 5.8))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    boxes = [
        (0.04, 0.61, "Input Plan", "48 balanced cells\nattack x environment\nx difficulty", "#e8f1fb"),
        (0.25, 0.61, "LLM Proposal", "metadata-only JSON\nno payload execution\nno live targets", "#f7efe2"),
        (0.46, 0.61, "Validator", f"schema + ATT&CK v14.1\nfirst active {first}\nbounded re-query", "#e8f6ee"),
        (0.67, 0.61, "Accepted Corpus", f"{scenarios} scenarios\n{active} active IDs\n{base} base techniques", "#f2edf9"),
        (0.25, 0.17, "Evaluation Stack", "R(S) scoring\nmutation + SOC sensitivity\nreal metadata baselines", "#eef3f3"),
        (0.46, 0.17, "Replay Grounding", f"{sigma_rules} Sigma rules\n{sigma_events} labelled events\ntechnique coverage", "#fff1f1"),
        (0.67, 0.17, "Human Validation", f"{human_n} blinded scenarios\n{human_r} non-author reviewers\nordinal agreement", "#edf7ff"),
    ]
    for x, y, title, body, color in boxes:
        box(ax, x, y, 0.17, 0.25, title, body, color)
    for x1, x2 in [(0.21, 0.25), (0.42, 0.46), (0.63, 0.67)]:
        arrow(ax, x1, 0.74, x2, 0.74)
    arrow(ax, 0.755, 0.63, 0.335, 0.40)
    arrow(ax, 0.755, 0.63, 0.545, 0.40)
    arrow(ax, 0.755, 0.63, 0.755, 0.40)

    ax.text(
        0.5,
        0.045,
        "Delivered scope: validated metadata generation, replay, baselines, cross-version audits, and human evaluation. "
        "No continuous-learning/adaptive feedback component is claimed.",
        ha="center",
        va="center",
        fontsize=8,
        color="#333333",
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, bbox_inches="tight")
    fig.savefig(out_path.with_suffix(".png"), dpi=300, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    build(args.registry, args.out)
    print(f"wrote {args.out}")
    print(f"wrote {args.out.with_suffix('.png')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
