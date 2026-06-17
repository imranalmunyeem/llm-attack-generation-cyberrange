"""Regenerate paper artifacts and fail if generated outputs drift.

This check is intentionally local-package oriented. It compares the generated
macros, generated tables, registry, and PNG figure companions before and after
running the offline artifact generators. PDF files are not byte-compared
because Matplotlib/PDF metadata can vary; the PNG companions catch visual drift
for source-backed figures such as the architecture diagram.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PAPER = ROOT / "paper" / "ieee_access_overleaf"


@dataclass(frozen=True)
class CommandSpec:
    args: list[str]
    required: tuple[Path, ...] = ()


COMMANDS = [
    CommandSpec(["analysis/multimodel_table.py"], (ROOT / "results" / "multimodel.json",)),
    CommandSpec(["analysis/multimodel_coverage_curve.py"], (ROOT / "data" / "generated" / "multimodel",)),
    CommandSpec(["analysis/corpus_diversity.py"], (ROOT / "data" / "generated" / "scaleup" / "adversim_scaleup_full.jsonl",)),
    CommandSpec(["analysis/non_llm_baseline.py"], (ROOT / "mitre" / "enterprise-attack-14.1-active-techniques.json",)),
    CommandSpec(["analysis/sigma_replay_intervals.py"], (ROOT / "results" / "sigma_measured.json",)),
    CommandSpec(["analysis/contamination_audit.py"], (ROOT / "data" / "generated" / "scaleup" / "adversim_scaleup_full.jsonl",)),
    CommandSpec(["analysis/rs_weight_sensitivity.py", "--bootstrap", "500"], (ROOT / "results" / "human_ratings_summary.csv",)),
    CommandSpec(["analysis/statistical_hardening.py"], (ROOT / "results" / "human_validation.json",)),
    CommandSpec(["analysis/update_hardening_registry.py"], (ROOT / "results",)),
    CommandSpec(["analysis/build_results_registry.py"], (ROOT / "results" / "registry.json",)),
    CommandSpec(["visualization/build_architecture_figure.py"], (ROOT / "results" / "registry.json",)),
    CommandSpec(["visualization/export_ieee_figures.py"], (PAPER / "figures",)),
    CommandSpec(["scripts/sync_overleaf_analysis_sources.py"], (PAPER,)),
]


def artifact_paths() -> list[Path]:
    paths = [
        ROOT / "results" / "registry.json",
        PAPER / "generated_macros.tex",
        PAPER / "statistical_macros.tex",
    ]
    paths.extend(sorted(PAPER.glob("table_*.tex")))
    paths.extend(sorted((PAPER / "figures").glob("*.png")))
    paths.extend(sorted((PAPER / "analysis").glob("*.py")))
    return [path for path in paths if path.exists()]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot() -> dict[str, str]:
    return {str(path.relative_to(ROOT)): sha256(path) for path in artifact_paths()}


def run(spec: CommandSpec, *, strict: bool) -> None:
    missing = [path for path in spec.required if not path.exists()]
    if missing:
        message = ", ".join(str(path.relative_to(ROOT)) for path in missing)
        if strict:
            raise FileNotFoundError(f"missing inputs for {' '.join(spec.args)}: {message}")
        print(f"regeneration-drift: skip {' '.join(spec.args)}; missing {message}")
        return
    cmd = [sys.executable, *spec.args]
    print("+ " + " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="Fail instead of skipping generators with missing local inputs.")
    args = parser.parse_args()
    if not PAPER.exists():
        print(f"regeneration-drift: skipped missing paper directory {PAPER}")
        return 0

    before = snapshot()
    for spec in COMMANDS:
        run(spec, strict=args.strict)
    after = snapshot()

    changed = sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))
    if changed:
        print("regeneration-drift: FAIL")
        for path in changed:
            state = "added" if path not in before else "removed" if path not in after else "changed"
            print(f"{path}: {state}")
        return 1
    print(f"regeneration-drift: ok ({len(after)} artifacts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
