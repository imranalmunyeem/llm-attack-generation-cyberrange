"""CI-friendly reproducibility checks for the public AdverSim codebase."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

PY_COMPILE_TARGETS = [
    "analysis/attack_version_robustness.py",
    "analysis/build_results_registry.py",
    "analysis/contamination_audit.py",
    "analysis/external_realism_validation.py",
    "analysis/multimodel.py",
    "analysis/multimodel_coverage_curve.py",
    "analysis/multimodel_table.py",
    "analysis/corpus_diversity.py",
    "analysis/non_llm_baseline.py",
    "analysis/rs_weight_sensitivity.py",
    "analysis/sigma_replay_intervals.py",
    "analysis/statistical_hardening.py",
    "analysis/leakage_audit.py",
    "analysis/update_hardening_registry.py",
    "analysis/preregistered_blind_eval.py",
    "analysis/soc_sensitivity.py",
    "analysis/stats.py",
    "annotation/harness.py",
    "baselines/real_baselines.py",
    "detection/otrf_normalize.py",
    "detection/sigma_replay.py",
    "scaleup/corpus_scaleup.py",
    "scaleup/parallel_scaleup.py",
    "scripts/reproducibility_ci.py",
    "scripts/float_reference_lint.py",
    "scripts/number_consistency_lint.py",
    "scripts/regeneration_drift_check.py",
    "scripts/sync_overleaf_analysis_sources.py",
    "scripts/verify_overleaf_zip.py",
    "tests/smoke_pipeline.py",
    "visualization/build_architecture_figure.py",
    "visualization/export_ieee_figures.py",
]


def run(cmd: list[str]) -> None:
    print("+ " + " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def main() -> int:
    py = sys.executable
    run([py, "-m", "py_compile", *PY_COMPILE_TARGETS])
    run([py, "tests/smoke_pipeline.py"])
    if (ROOT / "paper" / "ieee_access_overleaf").exists() and (ROOT / "results" / "registry.json").exists():
        run([py, "scripts/number_consistency_lint.py"])
        run([py, "scripts/float_reference_lint.py"])
        run([py, "scripts/regeneration_drift_check.py"])
    print("reproducibility-ci ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
