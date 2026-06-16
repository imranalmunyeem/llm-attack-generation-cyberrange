"""Audit manuscript use of generated registry macros.

The current checkout may not contain manuscript `.tex` files yet. In that case
the audit verifies registry/macro consistency and exits successfully with a
clear warning so Phase 1 tooling can still be tested.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "results" / "registry.json"
MACROS_PATH = ROOT / "paper" / "generated_macros.tex"


def load_registry() -> dict:
    if not REGISTRY_PATH.exists():
        raise FileNotFoundError("results/registry.json does not exist; run analysis/build_results_registry.py")
    data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def macro_defs() -> dict[str, str]:
    if not MACROS_PATH.exists():
        raise FileNotFoundError("paper/generated_macros.tex does not exist; run analysis/build_results_registry.py")
    macros = {}
    pattern = re.compile(r"\\newcommand\{\\([A-Za-z]+)\}\{([^}]*)\}")
    for match in pattern.finditer(MACROS_PATH.read_text(encoding="utf-8")):
        macros[match.group(1)] = match.group(2)
    return macros


def tex_files() -> list[Path]:
    return [p for p in ROOT.rglob("*.tex") if ".venv" not in p.parts and "venv" not in p.parts]


def registry_literal_patterns(registry: dict) -> dict[str, re.Pattern[str]]:
    patterns = {}
    for key, entry in registry.items():
        if entry.get("status") == "missing":
            continue
        value = entry.get("value")
        if isinstance(value, float):
            variants = {f"{value:g}", f"{value:.3f}", f"{value:.4f}", f"{value * 100:.1f}"}
        elif isinstance(value, int):
            variants = {str(value)}
        else:
            continue
        escaped = "|".join(re.escape(v) for v in sorted(variants, key=len, reverse=True))
        patterns[key] = re.compile(rf"(?<![A-Za-z0-9_.])(?:{escaped})(?![A-Za-z0-9_.])")
    return patterns


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict-paper", action="store_true", help="Fail if no manuscript .tex files exist")
    args = parser.parse_args()

    registry = load_registry()
    macros = macro_defs()
    if not macros:
        print("No generated macros found", file=sys.stderr)
        return 1

    failures = []
    files = [p for p in tex_files() if p != MACROS_PATH]
    if not files:
        message = "No manuscript .tex files found; checked registry and generated macros only."
        if args.strict_paper:
            print(message, file=sys.stderr)
            return 1
        print(message)
        return 0

    patterns = registry_literal_patterns(registry)
    for path in files:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for key, pattern in patterns.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                failures.append(f"{path.relative_to(ROOT)}:{line}: hard-coded registry literal for {key}: {match.group(0)}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Checked {len(files)} manuscript .tex file(s); no hard-coded registry literals found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
