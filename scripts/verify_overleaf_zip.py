"""Verify that an Overleaf zip compiles from a clean extraction."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


REQUIRED_FILES = {"main.tex", "ieeeaccess.cls", "IEEEtran.cls", "IEEEtran.bst", "bullet.png", "references.bib"}


def run(cmd: list[str], cwd: Path) -> int:
    print("$ " + " ".join(cmd))
    completed = subprocess.run(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(completed.stdout)
    return completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip_path", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    missing_bins = [name for name in ("pdflatex", "bibtex") if shutil.which(name) is None]
    if missing_bins:
        print(f"verify-overleaf: missing LaTeX executables on PATH: {', '.join(missing_bins)}")
        return 2
    with tempfile.TemporaryDirectory(prefix="adversim-overleaf-") as tmp:
        work = Path(tmp)
        with zipfile.ZipFile(args.zip_path) as zf:
            zf.extractall(work)
        missing_files = sorted(name for name in REQUIRED_FILES if not (work / name).exists())
        if missing_files:
            print(f"verify-overleaf: missing files: {', '.join(missing_files)}")
            return 1
        sequence = [
            ["pdflatex", "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
            ["bibtex", "main"],
            ["pdflatex", "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
            ["pdflatex", "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
        ]
        for cmd in sequence:
            rc = run(cmd, work)
            if rc != 0:
                print(f"verify-overleaf: command failed: {' '.join(cmd)}")
                return rc
        print(f"verify-overleaf: ok {args.zip_path}")
        if args.keep:
            kept = args.zip_path.with_suffix(".verify_extract")
            if kept.exists():
                shutil.rmtree(kept)
            shutil.copytree(work, kept)
            print(f"kept extraction at {kept}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
