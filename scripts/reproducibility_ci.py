"""CI-friendly reproducibility checks for the public AdverSim codebase."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

PY_COMPILE_TARGETS = [
    "analysis/attack_version_robustness.py",
    "analysis/external_realism_validation.py",
    "analysis/multimodel.py",
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
    "tests/smoke_pipeline.py",
]


def run(cmd: list[str]) -> None:
    print("+ " + " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def main() -> int:
    py = sys.executable
    run([py, "-m", "py_compile", *PY_COMPILE_TARGETS])
    run([py, "tests/smoke_pipeline.py"])
    print("reproducibility-ci ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
