"""CI-friendly reproducibility checks for tracked AdverSim artifacts."""

from __future__ import annotations

import json
import hashlib
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_ARTIFACTS = [
    ROOT / "results" / "registry.json",
    ROOT / "results" / "stats_table.json",
    ROOT / "results" / "soc_invariance.json",
    ROOT / "results" / "sigma_measured.json",
    ROOT / "results" / "multimodel.json",
    ROOT / "results" / "real_baselines.json",
    ROOT / "results" / "human_validation.json",
    ROOT / "results" / "human_ratings_summary.csv",
    ROOT / "paper" / "generated_macros.tex",
]


def run(cmd: list[str]) -> None:
    print("+ " + " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def require_artifacts() -> None:
    missing = [path for path in REQUIRED_ARTIFACTS if not path.exists()]
    if missing:
        formatted = "\n".join(str(path.relative_to(ROOT)) for path in missing)
        raise AssertionError(f"missing required reproducibility artifacts:\n{formatted}")


def validate_manifest() -> None:
    manifest = ROOT / "results" / "figure_manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    figures = data.get("figures", [])
    if len(figures) < 5:
        raise AssertionError("expected at least five regenerated figures")
    for entry in figures:
        path = ROOT / entry["path"]
        if not path.exists():
            raise AssertionError(f"manifest references missing figure: {entry['path']}")
        if path.stat().st_size != entry["bytes"]:
            raise AssertionError(f"manifest byte count mismatch: {entry['path']}")
        digest = sha256(path)
        if digest != entry["sha256"]:
            raise AssertionError(f"manifest sha256 mismatch: {entry['path']}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    py = sys.executable
    require_artifacts()
    run([py, "-m", "py_compile", "analysis/regenerate_figures.py", "scripts/reproducibility_ci.py"])
    run([py, "analysis/regenerate_figures.py"])
    validate_manifest()
    run([py, "tests/smoke_pipeline.py"])
    print("reproducibility-ci ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
