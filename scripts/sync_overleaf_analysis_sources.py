"""Copy table/macro generator scripts into the private Overleaf bundle."""

from __future__ import annotations

import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PAPER = ROOT / "paper" / "ieee_access_overleaf"
DEST = PAPER / "analysis"

SOURCES = [
    ROOT / "analysis" / "build_results_registry.py",
    ROOT / "analysis" / "contamination_audit.py",
    ROOT / "analysis" / "corpus_diversity.py",
    ROOT / "analysis" / "multimodel_coverage_curve.py",
    ROOT / "analysis" / "multimodel_table.py",
    ROOT / "analysis" / "non_llm_baseline.py",
    ROOT / "analysis" / "rs_weight_sensitivity.py",
    ROOT / "analysis" / "sigma_replay_intervals.py",
    ROOT / "analysis" / "statistical_hardening.py",
    ROOT / "analysis" / "update_hardening_registry.py",
    ROOT / "visualization" / "build_architecture_figure.py",
    ROOT / "visualization" / "export_ieee_figures.py",
]


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    for source in SOURCES:
        if not source.exists():
            raise FileNotFoundError(source)
        target = DEST / source.name
        shutil.copy2(source, target)
        print(f"copied {source.relative_to(ROOT)} -> {target.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
