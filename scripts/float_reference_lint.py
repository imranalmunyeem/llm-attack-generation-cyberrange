"""Fail if labelled manuscript floats are never referenced.

The check is scoped to figure/table environments in the Overleaf package. It
helps ensure that every visual and generated table is part of the argument
rather than an unmentioned artifact.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FLOAT_RE = re.compile(r"\\begin\{(?P<env>figure\*?|table\*?)\}(?P<body>.*?)\\end\{(?P=env)\}", re.S)
LABEL_RE = re.compile(r"\\label\{([^}]+)\}")
REF_RE = re.compile(r"\\(?:ref|autoref|pageref|cref|Cref)\{([^}]+)\}")


@dataclass(frozen=True)
class FloatLabel:
    path: Path
    line: int
    env: str
    label: str


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def manuscript_tex_files(root: Path) -> list[Path]:
    skip = {"ieeeaccess.cls", "IEEEtran.cls", "references.bib"}
    return sorted(path for path in root.glob("*.tex") if path.name not in skip)


def collect_labels(files: list[Path]) -> list[FloatLabel]:
    labels: list[FloatLabel] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        for match in FLOAT_RE.finditer(text):
            body = match.group("body")
            for label_match in LABEL_RE.finditer(body):
                labels.append(
                    FloatLabel(
                        path=path,
                        line=line_for_offset(text, match.start() + label_match.start()),
                        env=match.group("env"),
                        label=label_match.group(1),
                    )
                )
    return labels


def collect_refs(files: list[Path]) -> set[str]:
    refs: set[str] = set()
    for path in files:
        text = path.read_text(encoding="utf-8")
        for match in REF_RE.finditer(text):
            for item in match.group(1).split(","):
                refs.add(item.strip())
    return refs


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paper", type=Path, default=ROOT / "paper" / "ieee_access_overleaf")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not args.paper.exists():
        print(f"float-reference: skipped missing paper directory {args.paper}")
        return 0
    files = manuscript_tex_files(args.paper)
    labels = collect_labels(files)
    refs = collect_refs(files)
    missing = [item for item in labels if item.label not in refs]
    if missing:
        print("float-reference: FAIL")
        for item in missing:
            rel = item.path.relative_to(ROOT) if item.path.is_relative_to(ROOT) else item.path
            print(f"{rel}:{item.line}: {item.env} label {item.label} has no reference")
        return 1
    print(f"float-reference: ok ({len(labels)} labelled floats)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
